
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class NodeHandler extends Thread {

    private final Socket clientSocket;
    private final P2PNode parentNode;
    private final byte[] aesKey;
    private final byte[] hmacKey;

    public NodeHandler(Socket socket, P2PNode parent) {
        this.clientSocket = socket;
        this.parentNode = parent;
        this.aesKey = SharedConfig.getAesKey();
        this.hmacKey = SharedConfig.getHmacKey();
    }

    @Override
    public void run() {
        try (
                BufferedReader reader = new BufferedReader(
                        new InputStreamReader(clientSocket.getInputStream(), StandardCharsets.UTF_8))) {

            String plaintext = CryptoUtils.secureReceiveEncapsulated(reader, aesKey, hmacKey);

            if (plaintext == null) {
                System.out.println("[NÓ " + parentNode.getNodeId() + " LOG] Pacote com HMAC inválido descartado. Vindo de: "
                        + clientSocket.getInetAddress());
                return;
            }

            parentNode.processMessage(plaintext);

        } catch (IOException e) {
            System.err.println("[NÓ " + parentNode.getNodeId() + " ERRO] Erro no handler: " + e.getMessage());
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                System.out.println(Arrays.toString(e.getStackTrace()));
            }
        }
    }
}
