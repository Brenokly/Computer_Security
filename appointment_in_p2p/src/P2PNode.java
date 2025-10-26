
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

public class P2PNode {

    private final int nodeId;
    private final int port;
    private final String successorAddress;
    private final String predecessorAddress;
    private final int rangeMin;
    private final int rangeMax;

    private final byte[] aesKey = SharedConfig.getAesKey();
    private final byte[] hmacKey = SharedConfig.getHmacKey();

    public P2PNode(int nodeId) {
        this.nodeId = nodeId;
        this.port = RingConfig.getPortForNode(nodeId);
        this.successorAddress = RingConfig.getSuccessorAddress(nodeId);
        this.predecessorAddress = RingConfig.getPredecessorAddress(nodeId);
        this.rangeMin = (nodeId * 10) + 1;
        this.rangeMax = (nodeId * 10) + 10;
    }

    public int getNodeId() {
        return this.nodeId;
    }

    public void startNode() {
        new Thread(this::startServer).start();
        startUserInput();
    }

    private void startServer() {
        try (ServerSocket serverSocket = new ServerSocket(this.port)) {
            System.out.println("[NÓ " + nodeId + "] Servidor P2P iniciado. Escutando na porta " + port);
            System.out.println("[NÓ " + nodeId + "] Responsável pelos arquivos: [" + rangeMin + " - " + rangeMax + "]");
            System.out.println("[NÓ " + nodeId + "] Sucessor: " + successorAddress);
            System.out.println("[NÓ " + nodeId + "] Antecessor: " + predecessorAddress);
            System.out.println("--------------------------------------------------");

            while (true) {
                Socket clientSocket = serverSocket.accept();
                new NodeHandler(clientSocket, this).start();
            }
        } catch (Exception e) {
            System.err.println("[NÓ " + nodeId + " ERRO] Falha ao iniciar servidor: " + e.getMessage());
        }
    }

    private void startUserInput() {
        try (Scanner scanner = new Scanner(System.in)) {
            while (true) {
                System.out.println("\n[NÓ " + nodeId + "] Comandos:");
                System.out.println("  BUSCAR_H <arquivo> (Sentido Horário)");
                System.out.println("  BUSCAR_A <arquivo> (Sentido Anti-Horário)");
                System.out.println("  TEST_BUSCAR_H <arquivo> (Teste de segurança Horário)");
                System.out.println("  TEST_BUSCAR_A <arquivo> (Teste de segurança Anti-Horário)");
                System.out.print("> ");

                String input = scanner.nextLine().trim();

                if (input.equalsIgnoreCase("exit")) {
                    System.out.println("[NÓ " + nodeId + "] Encerrando...");
                    System.exit(0);
                }

                String[] parts = input.split(" ");
                if (parts.length != 2) {
                    System.out.println("Erro na entrada de dados. Tente outra vez!");
                    continue;
                }

                String command = parts[0].toUpperCase();
                if (command.startsWith("BUSCAR_") || command.startsWith("TEST_BUSCAR_")) {
                    processMessage(input);
                } else {
                    System.out.println("Erro na entrada de dados. Tente outra vez!");
                }
            }
        }
    }

    public void processMessage(String message) {
        System.out.println("\n[NÓ " + nodeId + " LOG MENSAGEM RECEBIDA] \"" + message + "\"");

        String[] parts = message.split(" ");
        String command = parts[0].toUpperCase();
        String fileName = parts[1];

        int fileId;
        try {
            fileId = Integer.parseInt(fileName.replace("arquivo", ""));
        } catch (NumberFormatException e) {
            System.out.println("[NÓ " + nodeId + " LOG] Não foi possível extrair ID do arquivo, descartando.");
            return;
        }

        if (fileId >= rangeMin && fileId <= rangeMax) {
            System.out.println("[NÓ " + nodeId + " LOG] *** ARQUIVO " + fileName + " ENCONTRADO AQUI! ***");
        } else {

            byte[] keyToUse = hmacKey;
            if (command.startsWith("TEST_")) {
                System.out.println("[NÓ " + nodeId + " LOG] *** MODO DE TESTE DE SEGURANÇA ATIVADO ***");
                keyToUse = SharedConfig.getHmacKeyRuim();
            }

            if (command.endsWith("_H")) {
                System.out.println("[NÓ " + nodeId + " LOG] Arquivo " + fileName + " não está aqui. Encaminhando (Horário) para o sucessor (" + successorAddress + ")...");
                sendToSuccessor(message, keyToUse);
            } else if (command.endsWith("_A")) {
                System.out.println("[NÓ " + nodeId + " LOG] Arquivo " + fileName + " não está aqui. Encaminhando (Anti-Horário) para o antecessor (" + predecessorAddress + ")...");
                sendToPredecessor(message, keyToUse);
            }
        }
    }

    private void sendToPeer(String address, String message, byte[] hmacKeyToUse) {
        System.out.println("[NÓ " + nodeId + " LOG MENSAGEM ENVIADA] \"" + message + "\"");
        try {
            String[] addrParts = address.split(":");
            String host = addrParts[0];

            try (
                    Socket socket = new Socket(host, Integer.parseInt(addrParts[1])); PrintWriter writer = new PrintWriter(socket.getOutputStream(), true, StandardCharsets.UTF_8)) {
                CryptoUtils.secureSendEncapsulated(writer, message, aesKey, hmacKeyToUse);
            }
        } catch (Exception e) {
            System.err.println("[NÓ " + nodeId + " ERRO] Falha ao enviar para (" + address + "): " + e.getMessage());
        }
    }

    private void sendToSuccessor(String message, byte[] hmacKeyToUse) {
        sendToPeer(this.successorAddress, message, hmacKeyToUse);
    }

    private void sendToPredecessor(String message, byte[] hmacKeyToUse) {
        sendToPeer(this.predecessorAddress, message, hmacKeyToUse);
    }
}
