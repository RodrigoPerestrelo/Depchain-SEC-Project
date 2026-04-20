package depchain.common.utils;

import com.google.gson.Gson;

import java.io.FileReader;
import java.io.Reader;
import java.net.InetAddress;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Loads and provides access to the static membership configuration.
 */
public class StaticMembership {

    public static class NodeInfo {
        private int id;
        private String host;
        private int port;

        public NodeInfo() {} // required by Gson

        public NodeInfo(int id, String host, int port) {
            this.id = id;
            this.host = host;
            this.port = port;
        }

        public int getId() {
            return id;
        }

        public String getHost() {
            return host;
        }

        public int getPort() {
            return port;
        }
        
        /** Resolves host to an InetAddress for socket binding. */
        public InetAddress getAddress() throws Exception {
            return InetAddress.getByName(host);
        }
    }

    private static class Config {
        int f;
        List<NodeInfo> nodes;
        List<NodeInfo> clients;
    }

    private final int f;
    private final int n;
    private final int quorumSize;
    private final List<NodeInfo> nodes;
    private final Map<Integer, NodeInfo> nodeMap;
    private final List<NodeInfo> clients;
    private final Map<Integer, NodeInfo> clientMap;

    public StaticMembership(String nodePath, String clientsPath) throws Exception {
        Gson gson = new Gson();


        try (Reader reader = new FileReader(nodePath)) {
            Config config = gson.fromJson(reader, Config.class);

            this.f = config.f;
            this.nodes = Collections.unmodifiableList(config.nodes);
            this.n = config.nodes.size();
            this.quorumSize = 2 * f + 1;
            this.nodeMap = config.nodes.stream()
                    .collect(Collectors.toMap(NodeInfo::getId, ni -> ni));
        }

        try (Reader reader = new FileReader(clientsPath)) {
            Config config = gson.fromJson(reader, Config.class);

            this.clients = config.clients != null
                    ? Collections.unmodifiableList(config.clients)
                    : Collections.emptyList();
            this.clientMap = this.clients.stream()
                    .collect(Collectors.toMap(NodeInfo::getId, ni -> ni));
        }
    }

    /** Constructor for testing use. */
    public StaticMembership(int f, List<NodeInfo> nodes) {
        this.f = f;
        this.nodes = Collections.unmodifiableList(nodes);
        this.n = nodes.size();
        this.quorumSize = 2 * f + 1;
        this.nodeMap = nodes.stream()
                .collect(Collectors.toMap(NodeInfo::getId, ni -> ni));
        this.clients = Collections.emptyList();
        this.clientMap = Collections.emptyMap();
    }

    /** Constructor for testing use with both nodes and clients. */
    public StaticMembership(int f, List<NodeInfo> nodes, List<NodeInfo> clients) {
        this.f = f;
        this.nodes = Collections.unmodifiableList(nodes);
        this.n = nodes.size();
        this.quorumSize = 2 * f + 1;
        this.nodeMap = nodes.stream()
                .collect(Collectors.toMap(NodeInfo::getId, ni -> ni));
        this.clients = Collections.unmodifiableList(clients);
        this.clientMap = clients.stream()
                .collect(Collectors.toMap(NodeInfo::getId, ni -> ni));
    }

    public int getF() {
        return f;
    }

    public int getN() {
        return n;
    }

    public int getQuorumSize() {
        return quorumSize;
    }

    public NodeInfo getNode(int id) {
        return nodeMap.get(id);
    }

    public List<NodeInfo> getAllNodes() {
        return nodes;
    }

    /** Round-robin leader election. */
    public int getLeader(int viewNumber) {
        return viewNumber % n;
    }

    public List<NodeInfo> getAllClients() {
        return clients;
    }

    public NodeInfo getClient(int id) {
        return clientMap.get(id);
    }

    /** Total number of entities (nodes + clients) for key loading. */
    public int getTotalEntities() {
        return n + clients.size();
    }
}
