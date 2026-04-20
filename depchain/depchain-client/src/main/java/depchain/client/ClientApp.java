package depchain.client;

import depchain.client.core.DepChainClient;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

public class ClientApp {

    // Pre-deployed smart contract address
    private static final String ISTCOIN_ADDRESS = "0x8f7a45ebde059392e46a46dcc14ab24681a961ea";

    // ERC-20 function selectors (Keccak-256 hashes)
    private static final String SEL_NAME = "0x06fdde03";
    private static final String SEL_SYMBOL = "0x95d89b41";
    private static final String SEL_DECIMALS = "0x313ce567";
    private static final String SEL_TOTAL_SUPPLY = "0x18160ddd";
    private static final String SEL_BALANCE_OF = "0x70a08231";
    private static final String SEL_TRANSFER = "0xa9059cbb";
    private static final String SEL_TRANSFER_FROM = "0x23b872dd";
    private static final String SEL_APPROVE = "0x095ea7b3";
    private static final String SEL_ALLOWANCE = "0xdd62ed3e";
    private static final String SEL_INC_ALLOW = "0x39509351";
    private static final String SEL_DEC_ALLOW = "0xa457c2d7";

    // Left-pad hex string to 32 bytes (64 chars)
    private static String padLeft(String hex) {
        if (hex.startsWith("0x")) hex = hex.substring(2);
        return String.format("%64s", hex).replace(' ', '0');
    }

    // Format address parameter
    private static String encodeAddress(String address) {
        return padLeft(address);
    }

    // Format uint256 parameter
    private static String encodeUint256(long value) {
        return padLeft(BigInteger.valueOf(value).toString(16));
    }

    // Extract EVM return data block
    private static String extractData(String receipt) {
        if (!receipt.contains("ReturnData: 0x")) return null;
        int dataIndex = receipt.indexOf("ReturnData: 0x") + 14;
        return receipt.substring(dataIndex).trim();
    }

    // Decode uint256 or bool
    private static String decodeUint256(String receipt) {
        String hexData = extractData(receipt);
        if (hexData != null && hexData.length() <= 64) {
            try { return new BigInteger(hexData, 16).toString(); } catch (Exception ignored) {}
        }
        return "Receipt: " + receipt;
    }

    // Decode ABI dynamic string
    private static String decodeString(String receipt) {
        String hexData = extractData(receipt);
        if (hexData != null && hexData.length() >= 128) {
            try {
                int lenStr = Integer.parseInt(hexData.substring(64, 128), 16);
                String strHex = hexData.substring(128, 128 + (lenStr * 2));
                byte[] bytes = new byte[strHex.length() / 2];
                for (int i = 0; i < bytes.length; i++) {
                    bytes[i] = (byte) Integer.parseInt(strHex.substring(i * 2, i * 2 + 2), 16);
                }
                return new String(bytes, StandardCharsets.UTF_8);
            } catch (Exception ignored) {}
        }
        return "Receipt: " + receipt;
    }

    // Prompt user for gas parameters with smart defaults
    private static long[] promptGas(Scanner scanner, long defaultLimit) {
        System.out.print("Gas Limit [Press Enter for " + defaultLimit + "]: ");
        String inputLimit = scanner.nextLine().trim();
        long limit = inputLimit.isEmpty() ? defaultLimit : Long.parseLong(inputLimit);

        System.out.print("Gas Price [Press Enter for 1]: ");
        String inputPrice = scanner.nextLine().trim();
        long price = inputPrice.isEmpty() ? 1 : Long.parseLong(inputPrice);

        if (limit <= 0 || price <= 0) {
            throw new IllegalArgumentException("Gas Limit and Price must be strictly greater than 0");
        }
        return new long[]{limit, price};
    }

    public static void main(String[] args) {
        // Validate startup args
        if (args.length < 4) {
            System.err.println("Usage: java ClientApp <clientId> <nodesJson> <clientsJson> <keysDir>");
            System.exit(1);
        }

        try {
            int clientId = Integer.parseInt(args[0]);
            DepChainClient client = new DepChainClient(clientId, args[1], args[2], args[3]);
            Scanner scanner = new Scanner(System.in);

            System.out.println("Client started successfully!");

            // Main interaction loop
            while (true) {
                System.out.println("\n> ==================== MENU ====================");
                System.out.println("> --- Native ---");
                System.out.println("> 1 - Transfer DepCoin");
                System.out.println("> 2 - Check Native Balance");
                System.out.println("> --- ERC-20 Read ---");
                System.out.println("> 3 - Name | 4 - Symbol | 5 - Decimals | 6 - Total Supply");
                System.out.println("> 7 - Balance Of | 8 - Allowance");
                System.out.println("> --- ERC-20 Write ---");
                System.out.println("> 9 - Transfer | 10 - Transfer From");
                System.out.println("> 11 - Approve | 12 - Increase Allow. | 13 - Decrease Allow.");
                System.out.println("> 0 - Exit");
                System.out.println("> ==============================================");
                System.out.print("$ Select an option: ");

                String option = scanner.nextLine().trim();
                String payload = null;
                String res;

                try {
                    switch (option) {
                        case "1":
                            System.out.print("Receiver address: ");
                            String depReceiver = scanner.nextLine().trim();
                            System.out.print("Amount (DepCoin): ");
                            long depAmount = Long.parseLong(scanner.nextLine().trim());
                            
                            // Fetch user gas preferences
                            long[] gasDep = promptGas(scanner, 21000);
                            
                            res = client.sendTransaction(depReceiver, depAmount, gasDep[0], gasDep[1], null);
                            System.out.println("Result => " + res);
                            break;
                        
                        case "2":
                            System.out.print("Account address (Press enter for self): ");
                            String targetAddr = scanner.nextLine().trim();

                            if (targetAddr.isEmpty()) {
                                targetAddr = String.format("0x%040x", 0xc0 + clientId);
                            }
                            long[] gasNative = promptGas(scanner, 21000);

                            // Send native balance request using the special flag
                            String balRes = client.sendTransaction(targetAddr, 0, gasNative[0], gasNative[1], "NATIVE_BALANCE");
                            System.out.println("DepCoin Balance => " + balRes);
                            break;

                        case "3":
                            long[] gasName = promptGas(scanner, 50000);
                            res = client.sendTransaction(ISTCOIN_ADDRESS, 0, gasName[0], gasName[1], SEL_NAME);
                            System.out.println("Name => " + decodeString(res));
                            break;

                        case "4":
                            long[] gasSym = promptGas(scanner, 50000);
                            res = client.sendTransaction(ISTCOIN_ADDRESS, 0, gasSym[0], gasSym[1], SEL_SYMBOL);
                            System.out.println("Symbol => " + decodeString(res));
                            break;

                        case "5":
                            long[] gasDec = promptGas(scanner, 50000);
                            res = client.sendTransaction(ISTCOIN_ADDRESS, 0, gasDec[0], gasDec[1], SEL_DECIMALS);
                            System.out.println("Decimals => " + decodeUint256(res));
                            break;

                        case "6":
                            long[] gasSup = promptGas(scanner, 50000);
                            res = client.sendTransaction(ISTCOIN_ADDRESS, 0, gasSup[0], gasSup[1], SEL_TOTAL_SUPPLY);
                            System.out.println("Total Supply => " + decodeUint256(res));
                            break;

                        case "7":
                            System.out.print("Account address: ");
                            payload = SEL_BALANCE_OF + encodeAddress(scanner.nextLine().trim());

                            long[] gasBal = promptGas(scanner, 50000);

                            res = client.sendTransaction(ISTCOIN_ADDRESS, 0, gasBal[0], gasBal[1], payload);
                            System.out.println("Balance => " + decodeUint256(res));
                            break;

                        case "8":
                            System.out.print("Owner address: ");
                            String owner = encodeAddress(scanner.nextLine().trim());
                            System.out.print("Spender address: ");
                            String spender = encodeAddress(scanner.nextLine().trim());
                            payload = SEL_ALLOWANCE + owner + spender;

                            long[] gasAllow = promptGas(scanner, 50000);

                            res = client.sendTransaction(ISTCOIN_ADDRESS, 0, gasAllow[0], gasAllow[1], payload);
                            System.out.println("Allowance => " + decodeUint256(res));
                            break;

                        case "9":
                            System.out.print("Receiver address: ");
                            String rx = encodeAddress(scanner.nextLine().trim());
                            System.out.print("Amount (ISTCoin): ");
                            long amt = Long.parseLong(scanner.nextLine().trim());
                            payload = SEL_TRANSFER + rx + encodeUint256(amt);

                            long[] gasTx = promptGas(scanner, 100000);

                            res = client.sendTransaction(ISTCOIN_ADDRESS, 0, gasTx[0], gasTx[1], payload);
                            System.out.println("Result => " + decodeUint256(res));
                            break;

                        case "10":
                            System.out.print("From address: ");
                            String from = encodeAddress(scanner.nextLine().trim());
                            System.out.print("To address: ");
                            String to = encodeAddress(scanner.nextLine().trim());
                            System.out.print("Amount (ISTCoin): ");
                            long val = Long.parseLong(scanner.nextLine().trim());
                            payload = SEL_TRANSFER_FROM + from + to + encodeUint256(val);

                            long[] gasTxFrom = promptGas(scanner, 100000);

                            res = client.sendTransaction(ISTCOIN_ADDRESS, 0, gasTxFrom[0], gasTxFrom[1], payload);
                            System.out.println("Result => " + decodeUint256(res));
                            break;

                        case "11":
                        case "12":
                        case "13":
                            System.out.print("Spender address: ");
                            String s = encodeAddress(scanner.nextLine().trim());
                            System.out.print("Amount (ISTCoin): ");
                            long v = Long.parseLong(scanner.nextLine().trim());

                            if (option.equals("11")) payload = SEL_APPROVE + s + encodeUint256(v);
                            else if (option.equals("12")) payload = SEL_INC_ALLOW + s + encodeUint256(v);
                            else payload = SEL_DEC_ALLOW + s + encodeUint256(v);

                            long[] gasOp = promptGas(scanner, 100000);

                            res = client.sendTransaction(ISTCOIN_ADDRESS, 0, gasOp[0], gasOp[1], payload);
                            System.out.println("Result => " + decodeUint256(res));
                            break;

                        case "0":
                            System.out.println("Shutting down client...");
                            scanner.close();
                            client.close();
                            System.exit(0);
                            break;

                        default:
                            System.out.println("Invalid option.");
                    }
                } catch (Exception e) {
                    System.err.println("Transaction failed: " + e.getMessage());
                }
            }

        } catch (Exception e) {
            System.err.println("Fatal error starting client:");
            e.printStackTrace();
        }
    }
}