
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.crypto.spec.IvParameterSpec;

/**
 * Thread que lida com uma conexão (Cliente ou Calculadora)
 */
public class DirectoryHandler extends Thread {

    private final Socket socket;
    private BufferedReader reader;
    private PrintWriter writer;
    private final Map<String, List<String>> serviceMap;
    private final byte[] aesKey = SharedConfig.getAesKey();
    private final byte[] hmacKey = SharedConfig.getHmacKey();

    public DirectoryHandler(Socket socket, Map<String, List<String>> serviceMap) {
        this.socket = socket;
        this.serviceMap = serviceMap;
    }

    @Override
    public void run() {
        try {
            this.reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            this.writer = new PrintWriter(socket.getOutputStream(), true, StandardCharsets.UTF_8);

            String cipherTextB64;
            while ((cipherTextB64 = reader.readLine()) != null) {
                String hmacB64 = reader.readLine();
                String viB64 = reader.readLine();

                if (hmacB64 == null || viB64 == null) {
                    break;
                }

                String plaintext = secureDecrypt(cipherTextB64, hmacB64, viB64);

                if (plaintext == null) {
                    continue;
                }

                processMessage(plaintext);
            }

        } catch (Exception e) {
            System.out.println("[Handler] Conexão com " + socket.getInetAddress() + " fechada.");
        } finally {
            try {
                socket.close();
            } catch (IOException e) {
                System.err.println(Arrays.toString(e.getStackTrace()));
            }
        }
    }

    private void processMessage(String plaintext) throws Exception {
        System.out.println("[Handler] Mensagem recebida de " + socket.getInetAddress() + ": " + plaintext);

        if (plaintext.startsWith("REGISTER ")) {
            String[] parts = plaintext.substring(9).split(" ", 2);
            if (parts.length == 2) {
                String serviceName = parts[0].replace("_", " ");
                String address = parts[1];

                serviceMap.putIfAbsent(serviceName, new CopyOnWriteArrayList<>());
                serviceMap.get(serviceName).add(address);

                System.out.println("[Handler] Serviço registrado: " + serviceName + " @ " + address);
                secureSend("REGISTER_OK", writer);
            }

        } else if (plaintext.startsWith("GET ")) {
            String serviceName = plaintext.substring(4).replace("_", " ");
            List<String> addresses = serviceMap.get(serviceName);

            if (addresses != null && !addresses.isEmpty()) {
                String response = String.join(",", addresses);
                secureSend(response, writer);
            } else {
                secureSend("NOT_FOUND", writer);
            }
        }
    }

    private String secureDecrypt(String cipherTextB64, String hmacB64, String viB64) {
        try {
            System.out.println("\n  [LOG-SEGURANÇA Recebimento] 1. Recebidas 3 linhas.");
            System.out.println("  [LOG-SEGURANÇA Recebimento]    > De: " + socket.getInetAddress());
            System.out.println("  [LOG-SEGURANÇA Recebimento]    > Cifra: " + cipherTextB64);
            System.out.println("  [LOG-SEGURANÇA Recebimento]    > HMAC:  " + hmacB64);
            System.out.println("  [LOG-SEGURANÇA Recebimento] 2. Verificando HMAC...");

            byte[] hmacRecebido = Base64.getDecoder().decode(hmacB64);
            boolean hmacValido = CryptoUtils.checarHmac(
                    hmacKey,
                    cipherTextB64.getBytes(StandardCharsets.UTF_8),
                    hmacRecebido);

            if (!hmacValido) {
                System.err.println("  [LOG-SEGURANÇA Recebimento] 3. FALHA! HMACs não conferem. MENSAGEM DESCARTADA.");
                return null; // Descarta a mensagem
            }

            System.out.println("  [LOG-SEGURANÇA Recebimento] 3. SUCESSO! HMAC válido.");
            System.out.println("  [LOG-SEGURANÇA Recebimento] 4. Decifrando com AES-CBC...");

            byte[] viBytes = Base64.getDecoder().decode(viB64);
            IvParameterSpec vi = new IvParameterSpec(viBytes);
            String plaintext = CryptoUtils.decifrarAES(cipherTextB64, aesKey, vi);

            System.out.println("  [LOG-SEGURANÇA Recebimento] 5. Mensagem decifrada: \"" + plaintext + "\"");

            return plaintext;

        } catch (Exception e) {
            System.err.println("[SEGURANÇA] Erro na decifragem: " + e.getMessage() + ". MENSAGEM DESCARTADA.");
            return null;
        }
    }

    private void secureSend(String plaintext, PrintWriter writer) throws Exception {

        System.out.println("\n  [LOG-SEGURANÇA Envio] Mensagem original: \"" + plaintext + "\"");
        System.out.println("  [LOG-SEGURANÇA Envio] 1. Gerando novo VI (Vetor de Inicialização)...");

        IvParameterSpec vi = CryptoUtils.gerarVI();
        byte[] viBytes = vi.getIV();
        String cipherTextB64 = CryptoUtils.cifrarAES(plaintext, aesKey, vi);

        System.out.println("  [LOG-SEGURANÇA Envio] 2. Cifrando com AES-CBC ->: " + cipherTextB64);

        byte[] hmacBytes = CryptoUtils.calcularHmacSha256(hmacKey,
                cipherTextB64.getBytes(StandardCharsets.UTF_8));
        String viB64 = Base64.getEncoder().encodeToString(viBytes);
        String hmacB64 = Base64.getEncoder().encodeToString(hmacBytes);

        System.out.println("  [LOG-SEGURANÇA Envio] 3. Calculando HMAC do texto cifrado ->: " + hmacB64);
        System.out.println("  [LOG-SEGURANÇA Envio] 4. Enviando 3 linhas (Cifra, HMAC, VI)...");

        writer.println(cipherTextB64);
        writer.println(hmacB64);
        writer.println(viB64);
    }
}
