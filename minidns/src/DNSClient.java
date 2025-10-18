import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.spec.IvParameterSpec;

/**
 * Questão 1: Cliente DNS (Requisitante e Registrador)
 * Usa Socket padrão Java para conectar.
 * Usa uma Thread (ListenerThread) para escutar respostas e notificações.
 * Usa o console (Scanner) para enviar comandos.
 */
public class DNSClient {

  private static final String SERVER_ADDRESS = "localhost";
  private static final int SERVER_PORT = 34525;

  // Chaves corretas (compartilhadas com o servidor)
  private static final byte[] aesKey = SharedConfig.getAesKey();
  private static final byte[] hmacKey = SharedConfig.getHmacKey();

  // Chave HMAC ruim para o teste de segurança
  private static final byte[] hmacKeyRuim = "chave-hmac-errada-do-atacante".getBytes(StandardCharsets.UTF_8);

  public static void main(String[] args) {
    try (
        // Conecta ao servidor
        Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
        // Escritor para enviar dados ao servidor
        PrintWriter writer = new PrintWriter(socket.getOutputStream(), true, StandardCharsets.UTF_8);
        // Leitor para receber dados do servidor (será usado pela Thread)
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
        // Scanner para ler a entrada do usuário
        Scanner scanner = new Scanner(System.in)) {

      System.out.println("==================================================");
      System.out.println(" Cliente DNS (Seguro) conectado ao servidor.");
      System.out.println("==================================================");
      System.out.println("Comandos disponíveis:");
      System.out.println("  GET <nome>       (Ex: GET servidor1)");
      System.out.println("  UPDATE <nome> <ip> (Ex: UPDATE servidor4 10.0.0.1)");
      System.out.println("  TEST_GET <nome>    (Envia GET com chave HMAC errada)");
      System.out.println("  TEST_UPDATE <n> <ip> (Envia UPDATE com chave HMAC errada)");
      System.out.println("  exit               (Para sair)");
      System.out.println("--------------------------------------------------");

      // Inicia a Thread para escutar o servidor (Receber respostas e
      // notificações)
      ListenerThread listener = new ListenerThread(reader);
      listener.start();

      // Loop principal para ler a entrada do usuário
      while (true) {
        String input = scanner.nextLine();

        if ("exit".equalsIgnoreCase(input)) {
          break;
        }

        if (input.startsWith("GET ")) {
          // Envia comando GET com chave correta
          secureSend(writer, input, aesKey, hmacKey);
        } else if (input.startsWith("UPDATE ")) {
          // Envia comando UPDATE com chave correta
          secureSend(writer, input, aesKey, hmacKey);
        }
        // --- Testes de Segurança ---
        else if (input.startsWith("TEST_GET ")) {
          // Envia comando GET com chave HMAC ERRADA
          System.out.println("[TESTE] Enviando GET com chave HMAC inválida...");
          String command = "GET " + input.substring(9);
          secureSend(writer, command, aesKey, hmacKeyRuim);
        } else if (input.startsWith("TEST_UPDATE ")) {
          // Envia comando UPDATE com chave HMAC ERRADA
          System.out.println("[TESTE] Enviando UPDATE com chave HMAC inválida...");
          String command = "UPDATE " + input.substring(12);
          secureSend(writer, command, aesKey, hmacKeyRuim);
        } else {
          System.out.println("Comando inválido. Tente novamente.");
        }
      }

    } catch (Exception e) {
      System.err.println("Erro no cliente: " + e.getMessage());
    } finally {
      System.out.println("Encerrando cliente.");
    }
  }

  /**
   * Cifra, assina (HMAC) e envia uma mensagem em texto puro para o servidor.
   * Usa o protocolo de 3 linhas.
   */
  private static void secureSend(PrintWriter writer, String plaintext, byte[] aesK, byte[] hmacK) throws Exception {
    // 1. Gera um NOVO VI (Vetor de Inicialização)
    IvParameterSpec vi = CryptoUtils.gerarVI();
    byte[] viBytes = vi.getIV();

    // Cifra a mensagem (AES)
    String cipherTextB64 = CryptoUtils.cifrarAES(plaintext, aesK, vi);

    // Calcula o HMAC (Autenticidade) da mensagem cifrada
    byte[] hmacBytes = CryptoUtils.calcularHmacSha256(hmacK,
        cipherTextB64.getBytes(StandardCharsets.UTF_8));

    // Converte VI e HMAC para Base64
    String viB64 = Base64.getEncoder().encodeToString(viBytes);
    String hmacB64 = Base64.getEncoder().encodeToString(hmacBytes);

    // Envia as 3 partes, uma por linha
    writer.println(cipherTextB64);
    writer.println(hmacB64);
    writer.println(viB64);
  }

  /**
   * Classe interna que atua como uma Thread
   * para escutar continuamente o servidor.
   */
  static class ListenerThread extends Thread {
    private final BufferedReader reader;

    public ListenerThread(BufferedReader reader) {
      this.reader = reader;
    }

    @Override
    public void run() {
      try {
        String cipherTextB64;
        // Loop infinito para escutar o servidor
        while ((cipherTextB64 = reader.readLine()) != null) {

          // Protocolo: espera as 3 linhas
          String hmacB64 = reader.readLine();
          String viB64 = reader.readLine();

          if (hmacB64 == null || viB64 == null) {
            break;
          }

          // Tenta decifrar e verificar a mensagem
          String plaintext = secureDecrypt(cipherTextB64, hmacB64, viB64);

          if (plaintext != null) {
            // Exibe a mensagem recebida (Resposta ou Notificação)
            System.out.println("\n[<< Resposta do Servidor] " + plaintext);
            System.out.print("> "); // Re-imprime o prompt para o usuário
          }
        }
      } catch (IOException e) {
        // Servidor caiu ou a conexão foi fechada
        System.out.println("\n[!!!] Conexão com o servidor perdida.");
      } catch (Exception e) {
        System.err.println("\n[!!!] Erro na Thread de escuta: " + e.getMessage());
      }
    }

    /**
     * Verifica o HMAC e decifra a mensagem recebida do servidor.
     */
    private String secureDecrypt(String cipherTextB64, String hmacB64, String viB64) {
      try {
        // Decodifica o HMAC
        byte[] hmacRecebido = Base64.getDecoder().decode(hmacB64);

        // Checa o HMAC
        boolean hmacValido = CryptoUtils.checarHmac(
            hmacKey, // Usa a chave HMAC correta
            cipherTextB64.getBytes(StandardCharsets.UTF_8),
            hmacRecebido);

        if (!hmacValido) {
          System.err.println(
              "[SEGURANÇA] HMAC INVÁLIDO recebido do SERVIDOR! MENSAGEM DESCARTADA.");
          return null; // Descarta
        }

        // Decifra
        byte[] viBytes = Base64.getDecoder().decode(viB64);
        IvParameterSpec vi = new IvParameterSpec(viBytes);

        String plaintext = CryptoUtils.decifrarAES(cipherTextB64, aesKey, vi);
        return plaintext;

      } catch (Exception e) {
        System.err.println("[SEGURANÇA] Erro ao decifrar mensagem do servidor: " + e.getMessage());
        return null;
      }
    }
  }
}