
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.spec.IvParameterSpec;

public class CalculatorServer2 {

    private static final String DIRECTORY_ADDRESS = "localhost";
    private static final int DIRECTORY_PORT = 53432;

    private static final String MY_IP = "localhost";
    private static final int MY_PORT = 9091;
    private static final String MY_ADDRESS = MY_IP + ":" + MY_PORT;

    private static final byte[] aesKey = SharedConfig.getAesKey();
    private static final byte[] hmacKey = SharedConfig.getHmacKey();

    public static void main(String[] args) {
        new Thread(() -> registerServices()).start();

        try (ServerSocket serverSocket = new ServerSocket(MY_PORT)) {
            System.out.println("==================================================");
            System.out.println(" Calculadora 2 (" + MY_ADDRESS + ") escutando por cálculos...");
            System.out.println("==================================================");

            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("[CalcServer2] Novo cliente de cálculo conectado: " + clientSocket.getInetAddress());
                new CalculationHandler(clientSocket).start();
            }

        } catch (Exception e) {
            System.err.println("Erro fatal na Calculadora 2 (Servidor): " + e.getMessage());
            System.out.println(Arrays.toString(e.getStackTrace()));
        }
    }

    private static void registerServices() {
        String[] services = {
            "SOMA", "SUBTRACAO",
            "MULTIPLICACAO", "DIVISAO"
        };

        try (
                Socket socket = new Socket(DIRECTORY_ADDRESS, DIRECTORY_PORT); PrintWriter writer = new PrintWriter(socket.getOutputStream(), true, StandardCharsets.UTF_8); BufferedReader reader = new BufferedReader(
                        new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8))) {

            System.out.println("[Registro Calc2] Conectado ao Diretório. Registrando...");

            for (String service : services) {
                String message = "REGISTER " + service + " " + MY_ADDRESS;
                secureSend(writer, message);
                String response = secureReceive(reader);
                if (!"REGISTER_OK".equals(response)) {
                    System.err.println("[Registro Calc2] Falha ao registrar " + service);
                }
            }
            System.out.println("[Registro Calc2] Todos os serviços registrados.");

        } catch (Exception e) {
            System.err.println("Erro no registro da Calculadora 2: " + e.getMessage());
        }
    }

    private static void secureSend(PrintWriter writer, String plaintext) throws Exception {

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

    private static String secureReceive(BufferedReader reader) {
        try {
            String cipherTextB64 = reader.readLine();
            String hmacB64 = reader.readLine();
            String viB64 = reader.readLine();
            if (cipherTextB64 == null) {
                return null;
            }

            System.out.println("\n  [LOG-SEGURANÇA Recebimento] 1. Recebidas 3 linhas.");
            System.out.println("  [LOG-SEGURANÇA Recebimento]    > Cifra: " + cipherTextB64);
            System.out.println("  [LOG-SEGURANÇA Recebimento]    > HMAC:  " + hmacB64);
            System.out.println("  [LOG-SEGURANÇA Recebimento] 2. Verificando HMAC...");

            byte[] hmacRecebido = Base64.getDecoder().decode(hmacB64);
            boolean hmacValido = CryptoUtils.checarHmac(hmacKey,
                    cipherTextB64.getBytes(StandardCharsets.UTF_8), hmacRecebido);
            if (!hmacValido) {
                System.err.println("  [LOG-SEGURANÇA Recebimento] 3. FALHA! HMACs não conferem. MENSAGEM DESCARTADA.");
                return null;
            }

            System.out.println("  [LOG-SEGURANÇA Recebimento] 3. SUCESSO! HMAC válido.");
            System.out.println("  [LOG-SEGURANÇA Recebimento] 4. Decifrando com AES-CBC...");

            byte[] viBytes = Base64.getDecoder().decode(viB64);
            IvParameterSpec vi = new IvParameterSpec(viBytes);
            String plaintext = CryptoUtils.decifrarAES(cipherTextB64, aesKey, vi);

            System.out.println("  [LOG-SEGURANÇA Recebimento] 5. Mensagem decifrada: \"" + plaintext + "\"");

            return plaintext;
        } catch (Exception e) {
            System.err.println("[SEGURANÇA] Erro ao decifrar: " + e.getMessage() + ". MENSAGEM DESCARTADA.");
            return null;
        }
    }
}
