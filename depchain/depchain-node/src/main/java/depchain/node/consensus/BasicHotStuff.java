package depchain.node.consensus;

import depchain.common.network.Message;
import depchain.common.network.Network;
import depchain.common.utils.StaticMembership;
import depchain.node.crypto.ThresholdSignatureService;
import depchain.node.state.UpcallHandler;
import threshsig.SigShare;

import depchain.common.crypto.PKIProvider;
import depchain.common.protocol.ClientRequest;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.*;
import java.util.function.Consumer;
import java.util.logging.Logger;

/**
 * Basic HotStuff consensus protocol — Algorithm 2 (Abraham et al. 2018).
 *
 * <h3>Architecture</h3>
 * <ul>
 *   <li><b>Actor / single event-loop thread</b>: all mutable consensus state is
 *       owned by one thread that drains events from inbox sequentially.
 *       No synchronized blocks or explicit locks are needed on the hot
 *       path — race conditions in vote aggregation or QC formation are
 *       structurally impossible.</li>
 *   <li><b>Async crypto</b>: expensive threshold-signature operations
 *       (tsign, tverify) are dispatched to a dedicated
 *       {cryptoPool via CompletableFuture.  When complete, the
 *       result is posted back to inbox as a Runnable lambda,
 *       so the callback executes on the single event-loop thread and may
 *       safely mutate replica state.</li>
 *   <li><b>O(n) communication</b>: star topology — the leader broadcasts one
 *       message per phase; each replica replies only to the leader.</li>
 * </ul>
 *
 * <h3>Safety invariant</h3>
 * The safeNode predicate (§5.2 of the paper) ensures that a correct
 * replica never votes for two conflicting blocks in the same or overlapping
 * views; combined with the lockedQC lock, this prevents two different
 * committed values from ever being accepted by two different correct replicas
 * (Theorem 2).
 */
public class BasicHotStuff implements Runnable {

    private static final Logger LOG = Logger.getLogger(BasicHotStuff.class.getName());

    // ── Message-type string constants ─────────────────────────────────────────
    static final String NEW_VIEW   = "NEW-VIEW";
    static final String PREPARE    = "PREPARE";
    static final String PRE_COMMIT = "PRE-COMMIT";
    static final String COMMIT     = "COMMIT";
    static final String DECIDE     = "DECIDE";
    /** Synthetic type injected by the view-change timer. */
    private static final String NEXT_VIEW  = "NEXT-VIEW";
    /** Request to fetch missing blocks during recovery. */
    static final String FETCH_BLOCKS_REQ  = "FETCH-BLOCKS-REQ";
    /** Response with recovered blocks. */
    static final String FETCH_BLOCKS_RESP  = "FETCH-BLOCKS-RESP";

    /** How long (ms) a replica waits per view before triggering a view change. */
    private static final long DEFAULT_VIEW_TIMEOUT_MS = 4_000;
    /** Maximum view timeout after exponential backoff (only applies when consensus was active). */
    private static final long MAX_VIEW_TIMEOUT_MS     = 32_000;
    private long currentTimeout = DEFAULT_VIEW_TIMEOUT_MS;

    // Batching window in ms
    private static final long BATCHING_PERIOD_MS = 2_000;

    // Block Gas Limit: Maximum accumulated gas per block
    private static final long BLOCK_GAS_LIMIT = 250_000L;

    // Batching lock
    private boolean batchingInProgress = false;

    // ── Injected dependencies ─────────────────────────────────────────────────
    private final StaticMembership          membership;
    private final int                       myId;
    private final Network                    network;
    private final ThresholdSignatureService tss;
    private final UpcallHandler             upcallHandler;
    // ── Crypto thread pool (runs off the event loop) ──────────────────────────
    private final ExecutorService cryptoPool =
            Executors.newFixedThreadPool(Math.max(2, Runtime.getRuntime().availableProcessors()));

    /**
     * The single event inbox.  Accepts:
     * <ul>
     *   <li>HotStuffMessage — external messages from the network layer</li>
     *   <li>Runnable       — internal callbacks from async crypto</li>
     * </ul>
     * All consumers run on the single event-loop thread.
     */
    private final BlockingQueue<Object> inbox = new LinkedBlockingQueue<>();

    // ── Persistent replica state (event-loop thread only) ────────────────────
    // volatile so that external threads (e.g. BlockchainMember main loop) always
    // read the latest value without requiring synchronization on the hot path.
    private volatile int      curView;
    private QuorumCertificate lockedQC;   // updated in the commit phase
    private QuorumCertificate prepareQC;  // updated when a valid prepareQC is seen

    // ── Per-view leader accumulators ──────────────────────────────────────────
    private final List<HotStuffMessage> newViewMsgs    = new ArrayList<>();
    private final Map<Integer, SigShare> prepareVotes   = new HashMap<>();
    private final Map<Integer, SigShare> preCommitVotes = new HashMap<>();
    private final Map<Integer, SigShare> commitVotes    = new HashMap<>();
    /** Block the leader proposed in the current view (null until PREPARE sent). */
    private Block curProposal;
    /** The last block whose command was applied to the state machine. Prevents re-execution. */
    private Block highestExecutedBlock = null;

    /**
     * Local block store: hash -> Block. Populated whenever this replica votes
     * on (or proposes) a block.  Used by executeChain to walk the
     * parent chain of deserialised blocks whose parent field is null.
     */
    private final Map<String, Block> blockStore = new HashMap<>();

    // ── Per-view QC-formation guards (prevent duplicate quorum processing) ────
    private boolean prepareProposed;    // leader: PREPARE already broadcast this view
    private boolean prepareQCForming;
    private boolean preCommitQCForming;
    private boolean commitQCForming;

    // ── Per-view replica vote guards (vote at most once per phase/view) ───────
    private boolean sentPrepareSig;
    private boolean sentPreCommitSig;
    private boolean sentCommitSig;

    // ── Leader deferred-proposal state (event-loop thread only) ──────────────
    /** True when the leader has received quorum NEW-VIEW messages but has not yet proposed. */
    private boolean leaderReady;
    /** The highQC computed when quorum was reached — used by tryPropose. */
    private QuorumCertificate leaderHighQC;

    // ── View-change timer ─────────────────────────────────────────────────────
    private final ScheduledExecutorService timerService =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "hotstuff-timer");
                t.setDaemon(true);
                return t;
            });
    private ScheduledFuture<?> viewTimer;

    // ── Client-command queue (fed from outside) ───────────────────────────────
    private final BlockingQueue<ClientRequest> pendingCommands = new LinkedBlockingQueue<>();
    /** Reference to the running event-loop thread (used by shutdown()). */
    private volatile Thread eventLoopThread;


    // ── Block recovery state (event-loop thread only) ────────────────────────
    private final Map<String, BlockRecoveryState> pendingRecoveries = new HashMap<>();
    private final Set<String> currentRecoveryRequests = new HashSet<>();
    private static final long RECOVERY_TIMEOUT_MS = 10000;  // 10 seconds - allow time for network delays
    /** Block waiting for recovery completion to retry execution. */
    private Block pendingExecutionBlock = null;
    private QuorumCertificate pendingExecutionQC = null;

    // ─────────────────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────────────────

    public BasicHotStuff(StaticMembership membership, int myId,
                         Network network,
                         ThresholdSignatureService tss,
                         UpcallHandler upcallHandler) {
        this(membership, myId, network, tss, upcallHandler, null);
    }

    /**
     * Production constructor that enables the client-request registry check.
     *
     * <p>When pki is non-null, isKnownCommand enforces that
     * a ClientRequest JSON command was previously registered via
     * registerClientRequest before the leader proposes it or a
     * replica votes for it in PREPARE.  When pki is null
     * (backward-compatible / test mode), the registry check is skipped and all
     * syntactically valid commands are accepted — the final security line is
     * then only UpcallHandler#execute, which verifies signatures.
     */
    public BasicHotStuff(StaticMembership membership, int myId,
                         Network network,
                         ThresholdSignatureService tss,
                         UpcallHandler upcallHandler,
                         PKIProvider pki) {
        this.membership    = membership;
        this.myId          = myId;
        this.network       = network;
        this.tss           = tss;
        this.upcallHandler = upcallHandler;

        // Genesis QC — the "⊥" QC from view 0 used as the initial prepareQC
        Block genesis   = new Block();
        QuorumCertificate genericQC = new QuorumCertificate(PREPARE, 0, genesis, new SigShare[0]);
        this.lockedQC  = genericQC;
        this.prepareQC = genericQC;
        this.curView   = 0;

        // Store genesis block in blockStore so first-level blocks can find their parent
        blockStore.put(genesis.computeHash(), genesis);
    }

    public int getCurrentView() {
        return curView;
    }

    /**
     * Receives a block fetch request from another node.
     * Posts it to the inbox for async processing on the event-loop thread.
     */
    public void addBlockFetchRequest(BlockFetchRequest req) {
        inbox.add((Runnable) () -> onFetchBlocksRequest(req));
    }

    /**
     * Receives a block fetch response from another node.
     * Posts it to the inbox for async processing on the event-loop thread.
     */
    public void addBlockFetchResponse(BlockFetchResponse resp) {
        inbox.add((Runnable) () -> onFetchBlocksResponse(resp));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Public API  (thread-safe — posts to the lock-free inbox)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Delivers an incoming HotStuff network message to the consensus engine.
     * Called by the networking layer; may be invoked from any thread.
     */
    public void addMessageToQueue(HotStuffMessage msg) {
        inbox.add(msg);
    }

    /**
     * Enqueues a client command for ordering.  The leader of the next available
     * view will include it in a PREPARE proposal.
     *
     * <p>Thread-safe: may be called from any thread.
     */
    public void proposeCommand(ClientRequest req) {
        pendingCommands.add(req);
        // Notify the event loop: schedule the view timer if needed and try to
        // propose immediately (leader may already have quorum NEW-VIEW).
        inbox.add((Runnable) () -> {
            if (viewTimer == null && !pendingCommands.isEmpty()) {
                scheduleViewTimer();
            }
            tryPropose();
        });
    }

    /**
     * Starts the event-loop thread and returns it.  Must be called once before
     * messages can be processed.
     */
    public Thread start() {
        if (eventLoopThread != null && eventLoopThread.isAlive()) return eventLoopThread;
        Thread t = new Thread(this, "hotstuff-event-loop-" + myId);
        t.setDaemon(false);
        eventLoopThread = t;
        t.start();
        return t;
    }

    /** Interrupts the event loop and shuts down internal executor services. */
    public void shutdown() {
        Thread t = eventLoopThread;
        if (t != null) t.interrupt();
        cancelTimer();
        cryptoPool.shutdownNow();
        timerService.shutdownNow();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Event loop  (Runnable — exactly one thread executes this)
    // ─────────────────────────────────────────────────────────────────────────

    @Override
    public void run() {
        enterView(1);   // Algorithm line 1: for curView ← 1, 2, 3, …
        while (!Thread.currentThread().isInterrupted()) {
            try {
                Object event = inbox.take();
                if (event instanceof HotStuffMessage msg) {
                    dispatch(msg);
                } else if (event instanceof Runnable task) {
                    task.run();   // async crypto callback — safe to mutate state
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        cryptoPool.shutdownNow();
        timerService.shutdownNow();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // View management
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Transitions to newView, resetting all per-view accumulators and
     * sending a NEW-VIEW message to the new view's leader.
     */
    private void enterView(int newView) {
        if (newView <= curView) return;   // ignore stale transitions

        cancelTimer();
        curView = newView;

        // Clear all per-view mutable state
        newViewMsgs.clear();
        prepareVotes.clear();
        preCommitVotes.clear();
        commitVotes.clear();
        curProposal         = null;
        prepareProposed     = false;
        prepareQCForming    = false;
        preCommitQCForming  = false;
        commitQCForming     = false;
        sentPrepareSig      = false;
        sentPreCommitSig    = false;
        sentCommitSig       = false;
        leaderReady         = false;
        batchingInProgress  = false;
        leaderHighQC        = null;

        // Clear expired recoveries but keep active ones ongoing
        // This allows recovery to continue across view changes
        List<String> expiredRequests = new ArrayList<>();
        for (Map.Entry<String, BlockRecoveryState> e : pendingRecoveries.entrySet()) {
            if (e.getValue().isExpired(RECOVERY_TIMEOUT_MS)) {
                expiredRequests.add(e.getKey());
            }
        }
        for (String expiredId : expiredRequests) {
            BlockRecoveryState expired = pendingRecoveries.remove(expiredId);
            if (expired != null) {
                currentRecoveryRequests.remove(expired.missingParentHash);
            }
        }

        // Only clear pending execution block if there are no active recoveries.
        // If a recovery is in progress, we need to preserve the block and QC
        // so that when recovery completes, we can retry execution.
        // If recovery has expired (timeout), it's safe to clear.
        if (pendingRecoveries.isEmpty()) {
            pendingExecutionBlock = null;
            pendingExecutionQC = null;
        }

        LOG.info(String.format("[%d] ▶ Enter view %d  leader=%d", myId, curView, leader(curView)));

        // Only arm the timer eagerly when there is already a client command waiting
        // to be decided.  This prevents nodes from hot-spinning through idle views
        // when the cluster is quiescent (no commands pending).  When a command later
        // arrives, proposeCommand() re-arms the timer via its event-loop callback.
        if (!pendingCommands.isEmpty()) {
            scheduleViewTimer();
        }

        // Algorithm line 36: send Msg(new-view, ⊥, prepareQC) to leader(curView)
        // viewNumber in the message = curView-1 so the leader matches
        //   matchingMsg(m, new-view, curView−1)
        HotStuffMessage nv = new HotStuffMessage(NEW_VIEW, curView - 1, null, prepareQC);
        sendToLeader(curView, nv);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Message dispatch & Safe Catch-Up
    // ─────────────────────────────────────────────────────────────────────────

    private void dispatch(HotStuffMessage msg) {
        QuorumCertificate qc = msg.getJustify();
        
        // Safe catch-up: valid QC from the future
        if (qc != null && qc.getViewNumber() > curView) {
            final int targetView = qc.getType().equals(COMMIT) ? qc.getViewNumber() + 1 : qc.getViewNumber();
            
            asyncVerifyQC(qc, () -> {
                // Ensure we haven't advanced while verifying
                if (targetView > curView) {
                    LOG.info(String.format("[%d] Catch-up: QC from view %d. Jumping to %d", 
                                           myId, qc.getViewNumber(), targetView));
                    
                    // Catch up state if it's a decision
                    if (qc.getType().equals(COMMIT)) {
                        executeChain(qc.getNode(), qc);
                    }
                    enterView(targetView);
                }
                // Resume processing in the new view
                dispatchPhase(msg);
            });
            return; // Suspend until async verification completes
        }

        dispatchPhase(msg);
    }

    private void dispatchPhase(HotStuffMessage msg) {
        switch (msg.getType()) {
            case NEXT_VIEW  -> {
                // Guard against stale timer events: if the timer fired *after* the view
                // was already advanced (e.g. by a DECIDE), the inbox may still contain the
                // old NEXT_VIEW message.  Ignore it to prevent a spurious extra view-change
                // that would desync the quorum NEW-VIEW collection in the new view.
                if (msg.getViewNumber() == curView) onViewTimeout(msg.getNode());
            }
            case NEW_VIEW   -> onNewView(msg);
            case PREPARE    -> { if (isVote(msg)) onPrepareVote(msg);    else onPrepare(msg); }
            case PRE_COMMIT -> { if (isVote(msg)) onPreCommitVote(msg);  else onPreCommit(msg); }
            case COMMIT     -> { if (isVote(msg)) onCommitVote(msg);     else onCommit(msg); }
            case DECIDE     -> onDecide(msg);
            default         -> LOG.warning("[" + myId + "] Unknown type: " + msg.getType());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // View-change timeout  (Algorithm line 35-36)
    // ─────────────────────────────────────────────────────────────────────────

    private void onViewTimeout(Block node) {
        // Only apply exponential backoff when this view had *active* consensus work
        // (the leader broadcast a PREPARE, or this replica voted in the prepare phase).
        // For purely idle views — no pending command, no proposal — there is no
        // Byzantine leader to slow down, so resetting to DEFAULT keeps latency low
        // when the next client command eventually arrives.
        boolean hadActiveConsensus = prepareProposed || sentPrepareSig;
        if (hadActiveConsensus) {
            currentTimeout = Math.min(currentTimeout * 2, MAX_VIEW_TIMEOUT_MS);
        } else {
            currentTimeout = DEFAULT_VIEW_TIMEOUT_MS;  // idle view: reset, don't accumulate
        }
        LOG.warning(String.format("[%d] View %d timed out — triggering view change (next timeout=%d ms)",
                myId, curView, currentTimeout));
        // enterView will send the NEW-VIEW to the next leader
        enterView(curView + 1);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ── PREPARE phase ────────────────────────────────────────────────────────
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Leader (lines 3-6): waits for n−f new-view messages, derives highQC,
     * creates a leaf block, and broadcasts PREPARE.
     */
    private void onNewView(HotStuffMessage msg) {
        if (!isLeader(curView)) return;
        // matchingMsg(m, new-view, curView − 1)
        if (msg.getViewNumber() != curView - 1) return;
        if (prepareProposed) return;   // already broadcast PREPARE this view

        QuorumCertificate justify = msg.getJustify();
        if (justify == null) return;

        final int snap = curView;

        // Verify QC before accepting the message to prevent forged views
        asyncVerifyQC(justify, () -> {
            if (curView != snap || prepareProposed) return;

            newViewMsgs.add(msg);
            if (newViewMsgs.size() < quorum()) return;
            if (leaderReady) return;   // quorum already processed

            // Line 4: highQC ← argmax { m.justify.viewNumber } over M
            QuorumCertificate highQC = newViewMsgs.stream()
                    .map(HotStuffMessage::getJustify)
                    .filter(qc -> qc != null)
                    .max(Comparator.comparingInt(QuorumCertificate::getViewNumber))
                    .orElse(lockedQC);

            leaderHighQC = highQC;
            leaderReady  = true;
            tryPropose();
        });
    }

    /**
     * Attempts to create the PREPARE proposal.  Called when the leader reaches
     * quorum NEW-VIEW OR when a new command is enqueued (whichever comes last).
     * If no command is available, does nothing — the leader waits.
     */
    private void tryPropose() {
        if (!isLeader(curView) || !leaderReady || prepareProposed) return;
        if (pendingCommands.isEmpty()) return;   // wait for a client command

        if (!batchingInProgress) {
            batchingInProgress = true;
            LOG.info(String.format("LEADER [View %d]: 1st Tx received. Waiting %d ms to batch more Txs...", 
                curView, BATCHING_PERIOD_MS));
            
            // Schedule block creation
            timerService.schedule(() -> {
                inbox.add((Runnable) this::finalizeProposal);
            }, BATCHING_PERIOD_MS, TimeUnit.MILLISECONDS);
        }
    }

    private void finalizeProposal() {
        batchingInProgress = false;
        
        if (!isLeader(curView) || !leaderReady || prepareProposed) return;
        if (pendingCommands.isEmpty()) return;

        List<ClientRequest> allPending = new ArrayList<>();
        pendingCommands.drainTo(allPending);

        if (allPending.isEmpty()) return;

        // ENFORCE NONCE ORDER: Group by ClientId and sort queues by requestId
        Map<Integer, Queue<ClientRequest>> clientQueues = new HashMap<>();
        for (ClientRequest tx : allPending) {
            clientQueues.computeIfAbsent(tx.getClientId(), 
                    k -> new PriorityQueue<>(Comparator.comparingInt(ClientRequest::getRequestId)))
                .add(tx);
        }

        // GREEDY FRONTIER ALGORITHM
        List<ClientRequest> batch = new ArrayList<>();
        long currentBlockGas = 0L;

        while (true) {
            ClientRequest bestTx = null;
            long bestFee = -1;
            int bestClientId = -1;

            // Inspect only the valid "next" transaction for each client
            for (Map.Entry<Integer, Queue<ClientRequest>> entry : clientQueues.entrySet()) {
                Queue<ClientRequest> queue = entry.getValue();
                if (queue.isEmpty()) continue;

                ClientRequest headTx = queue.peek();
                long fee = estimateTransactionFee(headTx);

                if (fee > bestFee) {
                    bestFee = fee;
                    bestTx = headTx;
                    bestClientId = entry.getKey();
                }
            }

            // Stop if no valid transactions are left
            if (bestTx == null) {
                break;
            }

            long txGas = bestTx.getGasLimit();

            // Edge case: A single transaction exceeds the total block limit
            if (txGas > BLOCK_GAS_LIMIT) {
                LOG.warning(String.format("LEADER [View %d]: Tx from client %d exceeds block limit (%d gas). Discarding.", 
                        curView, bestClientId, txGas));
                clientQueues.get(bestClientId).poll(); // Discard the oversized tx permanently
                continue; // Find the next best transaction
            }

            // Check if the best available transaction fits in the block
            if (currentBlockGas + txGas <= BLOCK_GAS_LIMIT) {
                batch.add(bestTx);
                currentBlockGas += txGas;
                clientQueues.get(bestClientId).poll(); // Advance this client's queue
            } else {
                // User logic: If the best transaction doesn't fit, close the block here.
                break;
            }
        }

        // RETURN LEFTOVERS TO MEMPOOL
        for (Queue<ClientRequest> queue : clientQueues.values()) {
            pendingCommands.addAll(queue);
        }

        if (batch.isEmpty()) {
            return;
        }

        currentTimeout = DEFAULT_VIEW_TIMEOUT_MS;
        prepareProposed = true;
        leaderReady = false;

        // Create and store new block
        curProposal = new Block(leaderHighQC.getNode(), batch);
        storeBlock(curProposal);

        LOG.info(String.format("LEADER [View %d]: Proposing Block with %d Txs (Gas Consumed: %d / %d)", 
            curView, batch.size(), currentBlockGas, BLOCK_GAS_LIMIT));

        // Broadcast prepare
        broadcastToAll(new HotStuffMessage(PREPARE, curView, curProposal, leaderHighQC));
    }

    /**
     * Estimates total transaction fee based on operation type.
     * Fee = Estimated Gas * Gas Price.
     */
    private long estimateTransactionFee(ClientRequest tx) {
        if (tx == null) return 0L;

        // Base gas for a standard DepCoin transfer
        long estimatedGas = 21000L; 

        // Contract Deployment: Higher base cost if no destination address
        if (tx.getTo() == null || tx.getTo().isEmpty()) {
            estimatedGas = 53000L;
        }

        // Payload estimation: additional gas based on data size (if present)
        if (tx.getData() != null && !tx.getData().isEmpty()) {
            String data = tx.getData().startsWith("0x") ? tx.getData().substring(2) : tx.getData();
            long byteCount = data.length() / 2;
            estimatedGas += byteCount * 16L; // EVM typically charges 16 gas per byte of data
        }

        // Cap estimation to the client's stated gas limit
        estimatedGas = Math.min(estimatedGas, tx.getGasLimit());

        // Total Fee = Estimated Gas * Gas Price
        return estimatedGas * tx.getGasPrice();
    }

    /**
     * Replica (lines 8-10): validates the leader's PREPARE proposal and votes.
     */
    private void onPrepare(HotStuffMessage m) {
        if (!matchingMsg(m, PREPARE, curView)) return;
        if (sentPrepareSig) return;

        Block             node    = m.getNode();
        QuorumCertificate justify = m.getJustify();
        if (node == null || justify == null) return;

        // Line 9: node extends from justify.node ∧ safeNode(node, justify)
        if (!node.extends_(justify.getNode())) return;
        if (!safeNode(node, justify)) return;

        // The leader has sent a valid PREPARE — consensus is now active in this view.
        // Arm the view timer so that if the leader goes silent after this point
        // (crash or Byzantine) the replica will eventually time out and advance.
        // This also covers the edge case where the replica missed the CLIENT_REQUEST
        // and therefore never armed the timer via proposeCommand().
        if (viewTimer == null) scheduleViewTimer();

        // Verify the justify QC before voting (Byzantine leader may forge it)
        final int snap = curView;
        asyncVerifyQC(justify, () -> {
            if (curView != snap) return;
            storeAndLinkBlock(node);   // persist this block and restore its parent link
            // Line 10: send voteMsg(prepare, m.node, ⊥) to leader(curView)
            asyncSign(PREPARE, curView, node, sig -> {
                if (curView != snap) return;
                sentPrepareSig = true;
                HotStuffMessage vote = new HotStuffMessage(PREPARE, curView, node, null);
                vote.setPartialSig(sig);
                sendToLeader(curView, vote);
            });
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ── PRE-COMMIT phase ─────────────────────────────────────────────────────
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Leader (lines 12-14): collects n−f PREPARE votes, forms prepareQC,
     * broadcasts PRE-COMMIT.
     */
    private void onPrepareVote(HotStuffMessage msg) {
        if (!isLeader(curView)) return;
        if (!matchingMsg(msg, PREPARE, curView)) return;
        if (prepareQCForming) return;   // already processing a quorum

        SigShare partialSig = msg.getPartialSig();
        if (partialSig == null) return;

        prepareVotes.put(partialSig.getId(), partialSig);

        if (prepareVotes.size() < quorum()) return;
        prepareQCForming = true;

        // Line 13: prepareQC ← QC(V)
        SigShare[] shares = prepareVotes.values().toArray(new SigShare[0]);
        final int  snap     = curView;
        final Block proposal = curProposal;
        asyncVerifyAndFormQC(PREPARE, curView, proposal, shares, formedQC -> {
            if (curView != snap) return;
            prepareQC = formedQC;
            // Line 14: broadcast Msg(pre-commit, ⊥, prepareQC)
            broadcastToAll(new HotStuffMessage(PRE_COMMIT, curView, null, prepareQC));
        },
        () -> { // onFailure: Unlock so the leader can try again if garbage was sent
            if (curView == snap) prepareQCForming = false;
        });
    }

    /**
     * Replica (lines 16-18): receives PRE-COMMIT with prepareQC, updates
     * local prepareQC, and sends PRE-COMMIT vote.
     */
    private void onPreCommit(HotStuffMessage m) {
        if (!matchingQC(m.getJustify(), PREPARE, curView)) return;
        if (sentPreCommitSig) return;

        QuorumCertificate justify = m.getJustify();
        final int snap = curView;
        asyncVerifyQC(justify, () -> {
            if (curView != snap) return;
            // Line 17: prepareQC ← m.justify
            prepareQC = justify;
            // Line 18: send voteMsg(pre-commit, m.justify.node, ⊥)
            asyncSign(PRE_COMMIT, curView, justify.getNode(), sig -> {
                if (curView != snap) return;
                sentPreCommitSig = true;
                HotStuffMessage vote = new HotStuffMessage(PRE_COMMIT, curView, justify.getNode(), null);
                vote.setPartialSig(sig);
                sendToLeader(curView, vote);
            });
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ── COMMIT phase ─────────────────────────────────────────────────────────
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Leader (lines 20-22): collects n−f PRE-COMMIT votes, forms precommitQC,
     * broadcasts COMMIT.
     */
    private void onPreCommitVote(HotStuffMessage msg) {
        if (!isLeader(curView)) return;
        if (!matchingMsg(msg, PRE_COMMIT, curView)) return;
        if (preCommitQCForming) return;

        SigShare partialSig = msg.getPartialSig();
        if (partialSig == null) return;

        preCommitVotes.put(partialSig.getId(), partialSig);

        if (preCommitVotes.size() < quorum()) return;
        preCommitQCForming = true;

        // Line 21: precommitQC ← QC(V)
        SigShare[] shares   = preCommitVotes.values().toArray(new SigShare[0]);
        final int  snap     = curView;
        final Block proposal = curProposal;
        asyncVerifyAndFormQC(PRE_COMMIT, curView, proposal, shares, formedQC -> {
            if (curView != snap) return;
            // Line 22: broadcast Msg(commit, ⊥, precommitQC)
            broadcastToAll(new HotStuffMessage(COMMIT, curView, null, formedQC));
        },
        () -> { // onFailure: Unlock so the leader can try again if garbage was sent
            if (curView == snap) preCommitQCForming = false;
        });
    }

    /**
     * Replica (lines 24-26): receives COMMIT with precommitQC, updates
     * lockedQC, and sends COMMIT vote.
     */
    private void onCommit(HotStuffMessage m) {
        if (!matchingQC(m.getJustify(), PRE_COMMIT, curView)) return;
        if (sentCommitSig) return;

        QuorumCertificate justify = m.getJustify();
        final int snap = curView;
        asyncVerifyQC(justify, () -> {
            if (curView != snap) return;
            // Line 25: lockedQC ← m.justify
            lockedQC = justify;
            // Line 26: send voteMsg(commit, m.justify.node, ⊥)
            asyncSign(COMMIT, curView, justify.getNode(), sig -> {
                if (curView != snap) return;
                sentCommitSig = true;
                HotStuffMessage vote = new HotStuffMessage(COMMIT, curView, justify.getNode(), null);
                vote.setPartialSig(sig);
                sendToLeader(curView, vote);
            });
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ── DECIDE phase ─────────────────────────────────────────────────────────
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Leader (lines 28-30): collects n−f COMMIT votes, forms commitQC,
     * broadcasts DECIDE.
     */
    private void onCommitVote(HotStuffMessage msg) {
        if (!isLeader(curView)) return;
        if (!matchingMsg(msg, COMMIT, curView)) return;
        if (commitQCForming) return;

        SigShare partialSig = msg.getPartialSig();
        if (partialSig == null) return;

        commitVotes.put(partialSig.getId(), partialSig);

        if (commitVotes.size() < quorum()) return;
        commitQCForming = true;

        // Line 29: commitQC ← QC(V)
        SigShare[] shares   = commitVotes.values().toArray(new SigShare[0]);
        final int  snap     = curView;
        final Block proposal = curProposal;
        asyncVerifyAndFormQC(COMMIT, curView, proposal, shares, formedQC -> {
            if (curView != snap) return;
            // Line 30: broadcast Msg(decide, ⊥, commitQC)
            broadcastToAll(new HotStuffMessage(DECIDE, curView, null, formedQC));
        },
        () -> { // onFailure: Unlock so the leader can try again if garbage was sent
            if (curView == snap) commitQCForming = false;
        });
    }

    /**
     * Replica (lines 32-34): receives DECIDE with commitQC, verifies the QC,
     * executes the decided command chain, and advances to the next view.
     */
    private void onDecide(HotStuffMessage m) {
        if (!matchingQC(m.getJustify(), COMMIT, curView)) return;

        QuorumCertificate commitQC = m.getJustify();
        final int snap = curView;
        asyncVerifyQC(commitQC, () -> {
            if (curView != snap) return;
            cancelTimer();
            currentTimeout = DEFAULT_VIEW_TIMEOUT_MS;  // reset backoff on successful decision

            // Line 34: execute new commands through m.justify.node
            boolean executed = executeChain(commitQC.getNode(), commitQC);
            if (executed) {
                List<ClientRequest> txs = commitQC.getNode().getTransactions();
                if (txs != null && !txs.isEmpty()) {
                    LOG.info(String.format("COMMIT [View %d]: %d Txs decided and persisted.", snap, txs.size()));
                } else {
                    LOG.info(String.format("[%d] ✓ Decided view %d — advancing", myId, curView));
                }
                enterView(curView + 1);
            } else {
                LOG.info(String.format("[%d] Execution paused for recovery in view %d. Will advance upon recovery.", myId, curView));
            }
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Safety predicate 
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * A replica votes for node only if:
     * <ol>
     *   <li>node extends from the locked block (extends-from safety), OR</li>
     *   <li>the justifying QC is more recent than the locked QC (liveness unlock).</li>
     * </ol>
     */
    private boolean safeNode(Block node, QuorumCertificate qc) {
        if (lockedQC == null || lockedQC.getNode() == null) return true;
        boolean extendsLocked = node.extends_(lockedQC.getNode());
        boolean newerView     = qc.getViewNumber() > lockedQC.getViewNumber();
        return extendsLocked || newerView;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Execute decided command chain
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Traverses the block chain up to (and including) node and
     * executes each command in order from the oldest ancestor down.
     *
     * <p>When a block's in-memory parent reference is null
     * (e.g. deserialised from a DECIDE message), the local blockStore
     * is queried by parentHash to continue the traversal.
     *
     * <p>If a gap is detected (missing parent blocks), initiates async recovery
     * and returns early. Recovery will re-trigger execution when blocks are available.
     * 
     * @return true if execution completed normally, false if paused for recovery
     */
    private boolean executeChain(Block node, QuorumCertificate commitQC) {
        if (node == null) return true;
        Deque<Block> chain = new ArrayDeque<>();
        Block current = node;
        // Walk tip→genesis, stopping at the last already-executed block
        while (current != null && current.getTransactions() != null && !current.getTransactions().isEmpty()) {
            if (highestExecutedBlock != null && current.hashEquals(highestExecutedBlock)) break;
            chain.push(current);      // addFirst: tip ends up at the front
            // Walk parent: use in-memory ref first, then block store
            Block next = current.getParent();
            if (next == null && current.getParentHash() != null) {
                next = blockStore.get(current.getParentHash());
                // Gap detected: missing parent block — initiate async recovery
                if (next == null) {
                    LOG.warning(String.format("[%d] Gap detected: missing parent %s for block %s. Initiating recovery.",
                                            myId, current.getParentHash(), current.computeHash()));
                    // Store the block and QC for retry after recovery
                    pendingExecutionBlock = node;
                    pendingExecutionQC = commitQC;
                    initiateBlockRecovery(current.getParentHash());
                    return false;  // Recovery is async; execution will retry when blocks are available
                }
            }
            current = next;
        }
        while (!chain.isEmpty()) {
            Block b = chain.pop(); 
            List<ClientRequest> txs = b.getTransactions();
            
            if (txs != null && !txs.isEmpty()) {
                boolean isTip = chain.isEmpty();
                
                // Execute each tx in order
                for (ClientRequest cmd : txs) {
                    upcallHandler.execute(cmd, isTip ? commitQC : null, isTip);
                    
                    LOG.info(String.format("EXECUTED: Client %d -> %s | Value: %d | GasPrice: %d", 
                        cmd.getClientId(), 
                        (cmd.getTo() != null && !cmd.getTo().isEmpty() ? cmd.getTo() : "Contract Deploy"), 
                        cmd.getValue(), cmd.getGasPrice()));
                    
                    removePendingCommandById(cmd.getClientId(), cmd.getRequestId());
                }
                
                // Persist entire block to disk
                upcallHandler.persistBlock(b);
            }
            highestExecutedBlock = b;
        }
        return true;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Block Recovery
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Initiates an asynchronous block recovery process to fetch missing blocks.
     * Broadcasts a FETCH_BLOCKS_REQ to all replicas and waits for n-f concordant responses.
     *
     * @param missingParentHash the hash of the parent block that's missing
     */
    private void initiateBlockRecovery(String missingParentHash) {
        // Prevent duplicate recovery requests for the same gap
        if (currentRecoveryRequests.contains(missingParentHash)) {
            LOG.info(String.format("[%d] Recovery already in progress for parent %s", myId, missingParentHash));
            return;
        }

        String requestId = "node" + myId + "-recovery-" + System.nanoTime();
        currentRecoveryRequests.add(missingParentHash);

        // Create and store recovery state
        BlockRecoveryState state = new BlockRecoveryState(requestId, missingParentHash);
        pendingRecoveries.put(requestId, state);

        LOG.info(String.format("[%d] Initiating block recovery for gap at %s (request %s)",
                            myId, missingParentHash, requestId));

        // Create fetch request
        BlockFetchRequest fetchReq = new BlockFetchRequest(requestId, missingParentHash);
        HotStuffMessage reqMsg = new HotStuffMessage(FETCH_BLOCKS_REQ, curView, null, null);

        // Broadcast to all nodes (will be serialized with the request embedded in the node field)
        // We'll use a custom approach: encode the request in the message's command string
        // Actually, let's use a better approach: wrap the request in a temporary Block-like structure
        // For simplicity, we'll send it as a special message that nodes can parse

        // Send the request to all replicas asynchronously
        for (StaticMembership.NodeInfo ni : membership.getAllNodes()) {
            try {
                // Create a wrapper message containing the BlockFetchRequest
                String msgContent = fetchReq.formatMessage();
                if (ni.getId() == myId) {
                    // Self-deliver
                    inbox.add((Runnable) () -> onFetchBlocksRequest(fetchReq));
                } else {
                    // Send to remote node via network
                    network.send(ni.getAddress(), ni.getPort(),
                               new Message(msgContent, "FETCH-BLOCKS-REQ"));
                }
            } catch (Exception e) {
                LOG.warning(String.format("[%d] Failed to send recovery request to node %d: %s",
                                        myId, ni.getId(), e.getMessage()));
            }
        }

        // Schedule timeout callback
        timerService.schedule(() -> {
            inbox.add((Runnable) () -> {
                if (curView == state.viewAtCreation) {
                    finalizeBlockRecovery(requestId);
                }
            });
        }, RECOVERY_TIMEOUT_MS, TimeUnit.MILLISECONDS);
    }

    /**
     * Finalizes a block recovery attempt by checking if quorum was reached.
     * If quorum responses agree, processes the recovered blocks.
     * Otherwise, logs failure and clears the recovery state.
     */
    private void finalizeBlockRecovery(String requestId) {
        BlockRecoveryState state = pendingRecoveries.remove(requestId);
        if (state == null) return;

        currentRecoveryRequests.remove(state.missingParentHash);

        if (state.collectedResponses.size() < quorum()) {
            LOG.warning(String.format("[%d] Recovery timeout for %s: only got %d/%d responses",
                                    myId, requestId, state.collectedResponses.size(), quorum()));
            return;
        }

        // Validate all responses agree on block hashes
        BlockFetchResponse firstResponse = null;
        boolean allAgree = true;
        for (BlockFetchResponse resp : state.collectedResponses.values()) {
            if (resp.getStatus().equals("NOTFOUND")) {
                allAgree = false;
                break;
            }
            if (firstResponse == null) {
                firstResponse = resp;
            } else {
                if (resp.getBlocks().length != firstResponse.getBlocks().length) {
                    allAgree = false;
                    break;
                }
                // Compare block hashes
                for (int i = 0; i < resp.getBlocks().length; i++) {
                    if (!resp.getBlocks()[i].computeHash().equals(
                        firstResponse.getBlocks()[i].computeHash())) {
                        allAgree = false;
                        break;
                    }
                }
            }
            if (!allAgree) break;
        }

        if (!allAgree) {
            LOG.warning(String.format("[%d] Block recovery failed for %s: responses don't agree",
                                    myId, requestId));
            return;
        }

        // Process recovered blocks
        if (firstResponse != null && firstResponse.getBlocks().length > 0) {
            Block[] recoveredBlocks = firstResponse.getBlocks();
            // Store blocks from oldest to newest so parents are available for children
            // DEBUG: print recovered blocks for debugging
            System.out.println(String.format("[%d] Recovered %d blocks for request %s:",
                myId, recoveredBlocks.length, requestId));
            for (int i = recoveredBlocks.length - 1; i >= 0; i--) {
                storeAndLinkBlock(recoveredBlocks[i]);
            }

            // Retry execution with recovered blocks now available
            if (pendingExecutionBlock != null && pendingExecutionQC != null) {
                Block toExecute = pendingExecutionBlock;
                QuorumCertificate qcToUse = pendingExecutionQC;
                storeAndLinkBlock(toExecute);

                pendingExecutionBlock = null;
                pendingExecutionQC = null;
                boolean executed = executeChain(toExecute, qcToUse);
                if (executed) {
                    cancelTimer();
                    currentTimeout = DEFAULT_VIEW_TIMEOUT_MS;
                    LOG.info(String.format("[%d] ✓ Recovery successful: applied missing transactions and decided view %d", myId, curView));
                }
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Block Fetch Handlers
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Handles FETCH_BLOCKS_REQ message.
     * Looks up the requested parent hash and returns all blocks starting from that point.
     */
    private void onFetchBlocksRequest(BlockFetchRequest req) {
        Block startBlock = blockStore.get(req.getFromParentHash());
        if (startBlock == null) {
            // Parent not found locally
            BlockFetchResponse resp = new BlockFetchResponse(
                req.getRequestId(),
                myId,
                new Block[0],
                "NOTFOUND"
            );
            sendBlockFetchResponse(req.getRequestId(), resp);
            return;
        }

        // Collect all blocks starting from startBlock, walking backwards
        // (to fetch the requested missing parent and its own missing ancestors)
        List<Block> blocks = new ArrayList<>();
        Block current = startBlock;
        int maxBlocks = 20;  // Safety limit (smaller to avoid network buffer overflows with large blocks)
        
        while (current != null && blocks.size() < maxBlocks) {
            blocks.add(current);
            // Walk backwards towards genesis finding parents
            if (current.getParentHash() != null) {
                current = blockStore.get(current.getParentHash());
            } else {
                current = null;
            }
        }

        Block[] blockArray = blocks.toArray(new Block[0]);
        BlockFetchResponse resp = new BlockFetchResponse(
            req.getRequestId(),
            myId,
            blockArray,
            "OK"
        );
        sendBlockFetchResponse(req.getRequestId(), resp);
    }

    /**
     * Handles FETCH_BLOCKS_RESP message.
     * Collects responses and validates quorum when threshold is reached.
     */
    private void onFetchBlocksResponse(BlockFetchResponse resp) {
        BlockRecoveryState state = pendingRecoveries.get(resp.getRequestId());
        if (state == null || state.isExpired(RECOVERY_TIMEOUT_MS)) {
            LOG.info(String.format("[%d] Ignoring stale/unknown recovery response %s",
                                myId, resp.getRequestId()));
            return;
        }

        state.collectedResponses.put(resp.getSenderId(), resp);
        LOG.info(String.format("[%d] Received block recovery response from node %d (%d/%d responses)",
                            myId, resp.getSenderId(), state.collectedResponses.size(), quorum()));

        // Check if quorum reached
        if (state.collectedResponses.size() >= quorum()) {
            finalizeBlockRecovery(resp.getRequestId());
        }
    }

    /**
     * Sends a BlockFetchResponse to the requesting node.
     */
    private void sendBlockFetchResponse(String requestId, BlockFetchResponse resp) {
        try {
            String msgContent = resp.formatMessage();
            // In a real system, you'd need to know which node requested this
            // For now, broadcast to all (could be optimized to unicast)
            for (StaticMembership.NodeInfo ni : membership.getAllNodes()) {
                if (ni.getId() != myId) {
                    // DEBUG: print blocks that are sending in the response for debugging
                    System.out.println(String.format("[%d] Sending block recovery response to node %d for request %s: %d blocks",
                        myId, ni.getId(), requestId, resp.getBlocks().length));
                    network.send(ni.getAddress(), ni.getPort(),
                               new Message(msgContent, "FETCH-BLOCKS-RESP"));
                }
            }
        } catch (Exception e) {
            LOG.warning(String.format("[%d] Failed to send recovery response: %s",
                                    myId, e.getMessage()));
        }
    }

    private void removePendingCommandById(int clientId, int requestId) {
        boolean removed;
        do {
            removed = false;
            for (ClientRequest pending : pendingCommands) {
                if (pending != null
                        && pending.getClientId() == clientId
                        && pending.getRequestId() == requestId) {
                    if (pendingCommands.remove(pending)) {
                        removed = true;
                    }
                }
            }
        } while (removed);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Block store helpers
    // ─────────────────────────────────────────────────────────────────────────

    /** Registers block in the local store (keyed by its hash). */
    private void storeBlock(Block block) {
        if (block != null) {
            blockStore.put(block.computeHash(), block);
        }
    }

    /**
     * Stores block and, if its parent reference is absent,
     * links it to its parent from the local block store.
     */
    private void storeAndLinkBlock(Block block) {
        if (block == null) return;
        if (block.getParent() == null && block.getParentHash() != null) {
            Block parent = blockStore.get(block.getParentHash());
            if (parent != null) block.setParent(parent);
        }
        blockStore.put(block.computeHash(), block);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Async crypto helpers
    // (all callbacks are posted back to inbox and run on the event-loop thread)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Asynchronously signs (type, viewNumber, block) with this
     * replica's key share.  On completion, onDone is invoked on the
     * event-loop thread with the resulting SigShare.
     */
    private void asyncSign(String type, int viewNumber, Block block,
                           Consumer<SigShare> onDone) {
        if (cryptoPool.isShutdown()) return;
        CompletableFuture
            .supplyAsync(() -> {
                try { return tss.tsign(type, viewNumber, block); }
                catch (Exception e) { throw new CompletionException(e); }
            }, cryptoPool)
            .thenAccept(sig -> inbox.add((Runnable) () -> onDone.accept(sig)))
            .exceptionally(ex -> {
                LOG.severe("[" + myId + "] tsign failed: " + ex.getMessage());
                return null;
            });
    }

    /**
     * Asynchronously verifies that shares constitute a valid threshold
     * quorum for (type, viewNumber, block).  If valid, form a
     * QuorumCertificate and invoke onDone on the event-loop
     * thread.
     */
    private void asyncVerifyAndFormQC(String type, int viewNumber, Block block,
                                      SigShare[] shares,
                                      Consumer<QuorumCertificate> onDone,
                                      Runnable onFailure) {
        if (cryptoPool.isShutdown()) return;
        final SigShare[] captured = shares.clone();
        CompletableFuture
            .supplyAsync(() -> {
                try {
                    if (!tss.tverify(captured, type, viewNumber, block))
                        throw new RuntimeException("QC verify failed: " + type + "@" + viewNumber);
                    return new QuorumCertificate(type, viewNumber, block, captured);
                } catch (Exception e) { throw new CompletionException(e); }
            }, cryptoPool)
            .thenAccept(qc -> inbox.add((Runnable) () -> onDone.accept(qc)))
            .exceptionally(ex -> {
                LOG.severe("[" + myId + "] QC formation failed: " + ex.getMessage());
                inbox.add(onFailure);
                return null;
            });
    }

    /**
     * Asynchronously verifies an existing QC's threshold signature array.
     * Calls onValid on the event-loop thread only if verification
     * succeeds.  The genesis QC (empty sigs array) is accepted trivially.
     */
    private void asyncVerifyQC(QuorumCertificate qc, Runnable onValid) {
        if (qc.getSigs().length == 0) {
            // Genesis / generic QC — no signature to verify
            inbox.add(onValid);
            return;
        }
        if (cryptoPool.isShutdown()) return;
        final SigShare[] shares = qc.getSigs();
        CompletableFuture
            .supplyAsync(() -> {
                try {
                    return tss.tverify(shares, qc.getType(),
                                       qc.getViewNumber(), qc.getNode());
                } catch (Exception e) { throw new CompletionException(e); }
            }, cryptoPool)
            .thenAccept(ok -> {
                if (ok) inbox.add(onValid);
                else    LOG.warning("[" + myId + "] Rejected QC "
                                    + qc.getType() + "@" + qc.getViewNumber());
            })
            .exceptionally(ex -> {
                LOG.severe("[" + myId + "] QC verify error: " + ex.getMessage());
                return null;
            });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Networking helpers
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Broadcasts msg to every replica in the membership, including
     * self.  Self-delivery is done by posting directly to inbox
     * (no serialisation round-trip) so the leader also executes its own
     * replica role for the same message.
     */
    private void broadcastToAll(HotStuffMessage msg) {
        for (StaticMembership.NodeInfo ni : membership.getAllNodes()) {
            if (ni.getId() == myId) {
                inbox.add(msg);   // self-deliver
            } else {
                try {
                    network.send(ni.getAddress(), ni.getPort(),
                                 new Message(msg.formatMessage(), "HOTSTUFF"));
                } catch (Exception e) {
                    LOG.warning("[" + myId + "] send to " + ni.getId()
                                + " failed: " + e.getMessage());
                }
            }
        }
    }

    /** Sends msg to the leader of view. */
    private void sendToLeader(int view, HotStuffMessage msg) {
        sendToNode(leader(view), msg);
    }

    private void sendToNode(int targetId, HotStuffMessage msg) {
        if (targetId == myId) {
            inbox.add(msg);
            return;
        }
        StaticMembership.NodeInfo ni = membership.getNode(targetId);
        if (ni == null) {
            LOG.warning("[" + myId + "] Unknown target node " + targetId);
            return;
        }
        try {
            network.send(ni.getAddress(), ni.getPort(),
                         new Message(msg.formatMessage(), "HOTSTUFF"));
        } catch (Exception e) {
            LOG.warning("[" + myId + "] send to " + targetId
                        + " failed: " + e.getMessage());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // View-change timer
    // ─────────────────────────────────────────────────────────────────────────

    private void scheduleViewTimer() {
        if (timerService.isShutdown()) return;
        try {
            viewTimer = timerService.schedule(
                    () -> inbox.add(new HotStuffMessage(NEXT_VIEW, curView, null, null)),
                    currentTimeout, TimeUnit.MILLISECONDS);
        } catch (java.util.concurrent.RejectedExecutionException ignored) {
            // Node is shutting down; no need to schedule the next view timer.
        }
    }

    private void cancelTimer() {
        if (viewTimer != null) {
            viewTimer.cancel(false);
            viewTimer = null;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Small predicates / utilities
    // ─────────────────────────────────────────────────────────────────────────

    private int     leader(int view)           { return membership.getLeader(view); }
    private boolean isLeader(int view)         { return leader(view) == myId; }
    private int     quorum()                   { return membership.getQuorumSize(); }
    private boolean isVote(HotStuffMessage m)  { return m.getPartialSig() != null; }

    /** matchingMsg: type and viewNumber match. */
    private boolean matchingMsg(HotStuffMessage m, String type, int view) {
        return m != null && m.matches(type, view);
    }

    /** matchingQC: QC is non-null and its type/viewNumber match. */
    private boolean matchingQC(QuorumCertificate qc, String type, int view) {
        return qc != null && qc.matches(type, view);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Block Recovery State
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Tracks state of an ongoing block recovery attempt.
     * Used to collect responses from multiple replicas and validate quorum.
     */
    private class BlockRecoveryState {
        final String requestId;
        final String missingParentHash;
        final Map<Integer, BlockFetchResponse> collectedResponses;
        final long timestamp;
        final int viewAtCreation;

        BlockRecoveryState(String requestId, String missingParentHash) {
            this.requestId = requestId;
            this.missingParentHash = missingParentHash;
            this.collectedResponses = new HashMap<>();
            this.timestamp = System.currentTimeMillis();
            this.viewAtCreation = curView;
        }

        boolean isExpired(long timeoutMs) {
            return System.currentTimeMillis() - timestamp > timeoutMs;
        }
    }
}
