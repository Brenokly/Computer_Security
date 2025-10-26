
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

public class P7 {

    public static void main(String[] args) {
        System.out.println("[INVASOR P7] Iniciando ataque...");

        byte[] aesKey = SharedConfig.getAesKey();
        byte[] hmacKeyRuim = SharedConfig.getHmacKeyRuim();
        String mensagemAtaque = "BUSCAR_H arquivo33";

        try {
            int portAlvo = RingConfig.getPortForNode(0);
            String hostAlvo = RingConfig.HOST;

            System.out.println("[INVASOR P7] Alvo: " + hostAlvo + ":" + portAlvo + " (Nó P0)");
            System.out.println("[INVASOR P7] Mensagem: " + mensagemAtaque);

            try (
                    Socket socket = new Socket(hostAlvo, portAlvo); PrintWriter writer = new PrintWriter(socket.getOutputStream(), true, StandardCharsets.UTF_8)) {
                System.out.println("[INVASOR P7] Conectado. Enviando pacote seguro com CHAVE HMAC ERRADA...");
                CryptoUtils.secureSendEncapsulated(writer, mensagemAtaque, aesKey, hmacKeyRuim);
            }
            System.out.println("[INVASOR P7] Ataque enviado. Desconectando.");

        } catch (Exception e) {
            System.err.println("[INVASOR P7] Falha no ataque: " + e.getMessage());
        }
    }
}
