import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;
import javax.crypto.spec.IvParameterSpec;

public class ServiceClient {

  private static final String DIRECTORY_ADDRESS = "localhost";
  private static final int DIRECTORY_PORT = 53432;

  // Chaves
  private static final byte[] aesKey = SharedConfig.getAesKey();
  private static final byte[] hmacKey = SharedConfig.getHmacKey();
  private static final byte[] hmacKeyRuim = "chave-invalida-q2".getBytes(StandardCharsets.UTF_8);

  // Load Balancing
  private static int roundRobinIndex = 0;
  private static final Random random = new Random();

  private static String lastDiscoveredServer = null;
  private static String lastDiscoveredService = null;

  public static void main(String[] args) {
    // Conexão persistente com o DIRETÓRIO
    try (
        Socket dirSocket = new Socket(DIRECTORY_ADDRESS, DIRECTORY_PORT);
        PrintWriter dirWriter = new PrintWriter(dirSocket.getOutputStream(), true, StandardCharsets.UTF_8);
        BufferedReader dirReader = new BufferedReader(
            new InputStreamReader(dirSocket.getInputStream(), StandardCharsets.UTF_8));
        Scanner scanner = new Scanner(System.in)) {

      System.out.println("==================================================");
      System.out.println(" Cliente de Serviço (Seguro) conectado ao Diretório.");
      System.out.println("==================================================");
      System.out.println("Comandos disponíveis:");
      System.out.println("  GET_RR <serviço>   (Descobre e seleciona um servidor - Round Robin)");
      System.out.println("  GET_RND <serviço>  (Descobre e seleciona um servidor - Random)");
      System.out.println("  CALC <n1> <n2>     (Ex: CALC 5 7) - Usa o serviço selecionado");
      System.out.println("  TEST_GET <serviço> (Teste de segurança no Diretório)");
      System.out.println("  exit               (Para sair)");
      System.out.println("--------------------------------------------------");

      while (true) {
        System.out.print("> ");
        String input = scanner.nextLine();
        if ("exit".equalsIgnoreCase(input))
          break;

        String[] parts = input.split(" ");
        if (parts.length < 1)
          continue;

        String command = parts[0].toUpperCase();

        try {
          if (command.equals("GET_RR") || command.equals("GET_RND") || command.equals("TEST_GET")) {
            if (parts.length != 2) {
              System.out.println("Erro: Formato inválido. Use: " + command + " <nome_servico>");
              continue;
            }
            String serviceName = parts[1];
            byte[] hmacToSend = (command.equals("TEST_GET")) ? hmacKeyRuim : hmacKey;

            if (command.equals("TEST_GET")) {
              System.out.println("[TESTE] Enviando GET com chave HMAC inválida...");
            }

            secureSend(dirWriter, "GET " + serviceName, hmacToSend);

            String response = secureReceive(dirReader);

            if (response == null) {
              System.err.println("[CLIENTE] Falha na comunicação com o Diretório (Descartado?).");
              if (command.equals("TEST_GET")) {
                System.out.println("[TESTE] O servidor não respondeu. Teste OK.");
              }
              continue;
            }
            if (response.equals("NOT_FOUND")) {
              System.out.println("[CLIENTE] Serviço '" + serviceName + "' não encontrado.");
              continue;
            }

            String[] servers = response.split(",");
            String chosenServer;
            if (command.equals("GET_RR")) {
              chosenServer = getRoundRobin(servers);
            } else {
              chosenServer = getRandom(servers);
            }

            lastDiscoveredServer = chosenServer;
            lastDiscoveredService = serviceName;

            System.out.println("[CLIENTE] Servidor selecionado: " + lastDiscoveredServer);
            System.out.println("          (Serviço: " + lastDiscoveredService + ")");
            System.out.println("          Pronto para o comando 'CALC'.");

          } else if (command.equals("CALC")) {

            if (lastDiscoveredServer == null || lastDiscoveredService == null) {
              System.out.println(
                  "Erro: Você precisa descobrir um serviço primeiro. Use GET_RR ou GET_RND.");
              continue;
            }

            if (parts.length != 3) {
              System.out.println("Erro: Formato inválido. Use: CALC <num1> <num2>");
              continue;
            }
            String num1_str = parts[1];
            String num2_str = parts[2];
            try {
              Double.parseDouble(num1_str); // Apenas testa se é um número
              Double.parseDouble(num2_str); // Apenas testa se é um número
            } catch (NumberFormatException e) {
              System.out.println("Erro: Entradas inválidas. <num1> e <num2> devem ser números.");
              continue;
            }

            String calcMessage = lastDiscoveredService + " " + num1_str + " " + num2_str;

            System.out.println(
                "[CLIENTE] Enviando pedido '" + calcMessage + "' para " + lastDiscoveredServer + "...");
            String result = executeRemoteCalculation(lastDiscoveredServer, calcMessage);

            System.out.println("--------------------------------------------------");
            System.out.println("[CLIENTE] Resultado do cálculo: " + result);
            System.out.println("--------------------------------------------------");

          } else {
            System.out.println("Comando desconhecido.");
          }

        } catch (Exception e) {
          System.err.println("Erro na comunicação: " + e.getMessage());
        }
      }

    } catch (Exception e) {
      System.err.println("Erro fatal no cliente: " + e.getMessage());
      System.out.println(Arrays.toString(e.getStackTrace()));
    }
  }

  private static String executeRemoteCalculation(String serverAddress, String calcMessage) {
    try {
      String[] addrParts = serverAddress.split(":");
      String ip = addrParts[0];
      int port = Integer.parseInt(addrParts[1]);

      try (Socket calcSocket = new Socket(ip, port);
          PrintWriter calcWriter = new PrintWriter(calcSocket.getOutputStream(), true, StandardCharsets.UTF_8);
          BufferedReader calcReader = new BufferedReader(
              new InputStreamReader(calcSocket.getInputStream(), StandardCharsets.UTF_8))) {

        // Envia o pedido de cálculo (seguro)
        secureSend(calcWriter, calcMessage, hmacKey);

        // Recebe o resultado (seguro)
        String result = secureReceive(calcReader);

        return (result != null) ? result : "ERRO: Sem resposta da calculadora";

      }
    } catch (Exception e) {
      System.err.println("[CLIENTE] Erro ao conectar/calcular: " + e.getMessage());
      return "ERRO_CONEXAO";
    }
  }

  private static String getRoundRobin(String[] servers) {
    if (servers == null || servers.length == 0)
      return "NENHUM_SERVIDOR_DISPONIVEL";
    roundRobinIndex = (roundRobinIndex + 1) % servers.length;
    return servers[roundRobinIndex];
  }

  private static String getRandom(String[] servers) {
    if (servers == null || servers.length == 0)
      return "NENHUM_SERVIDOR_DISPONIVEL";
    return servers[random.nextInt(servers.length)];
  }

  private static void secureSend(PrintWriter writer, String plaintext, byte[] hmacK) throws Exception {

    System.out.println("\n  [LOG-SEGURANÇA Envio] Mensagem original: \"" + plaintext + "\"");
    System.out.println("  [LOG-SEGURANÇA Envio] 1. Gerando novo VI (Vetor de Inicialização)...");

    IvParameterSpec vi = CryptoUtils.gerarVI();
    String cipherTextB64 = CryptoUtils.cifrarAES(plaintext, aesKey, vi);

    System.out.println("  [LOG-SEGURANÇA Envio] 2. Cifrando com AES-CBC ->: " + cipherTextB64);

    byte[] hmacBytes = CryptoUtils.calcularHmacSha256(hmacK,
        cipherTextB64.getBytes(StandardCharsets.UTF_8));
    String viB64 = Base64.getEncoder().encodeToString(vi.getIV());
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
      if (cipherTextB64 == null) return null;

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