import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import javax.crypto.spec.IvParameterSpec;

/**
 * Thread que lida com a lógica de um único cliente conectado.
 * Baseado no uso padrão de java.lang.Thread.
 */
public class ClientHandler extends Thread {

  private final Socket socket;
  private BufferedReader reader;
  private PrintWriter myWriter; // O escritor deste cliente
  private Map<String, String> dnsMap; // O mapa COMPARTILHADO
  private List<PrintWriter> allWriters; // A lista COMPARTILHADA
  private byte[] aesKey;
  private byte[] hmacKey;

  public ClientHandler(Socket socket, Map<String, String> dnsMap, List<PrintWriter> allWriters,
      PrintWriter myWriter) {
    this.socket = socket;
    this.dnsMap = dnsMap;
    this.allWriters = allWriters;
    this.myWriter = myWriter;
    this.aesKey = SharedConfig.getAesKey();
    this.hmacKey = SharedConfig.getHmacKey();
  }

  @Override
  public void run() {
    try {
      // Inicializa o leitor para este cliente
      this.reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));

      String cipherTextB64;
      // Loop principal: lê mensagens do cliente
      while ((cipherTextB64 = reader.readLine()) != null) {

        // Nosso protocolo seguro envia 3 linhas: Cifra, HMAC, VI
        String hmacB64 = reader.readLine();
        String viB64 = reader.readLine();

        if (hmacB64 == null || viB64 == null) {
          // Cliente enviou dados incompletos
          break;
        }

        // Tenta decifrar e verificar a mensagem
        String plaintext = secureDecrypt(cipherTextB64, hmacB64, viB64);

        if (plaintext == null) {
          // secureDecrypt() já imprimiu o erro de HMAC
          // A mensagem foi descartada e o loop continua
          continue;
        }

        // Processa a mensagem decifrada
        processMessage(plaintext);
      }

    } catch (Exception e) {
      System.out.println("[Handler] Cliente " + socket.getInetAddress() + " desconectou abruptamente.");
    } finally {
      // Bloco de limpeza: Garante que o cliente seja removido
      // da lista de notificação e que os recursos sejam fechados.
      if (myWriter != null) {
        allWriters.remove(myWriter); // Remove da lista de broadcast
      }
      try {
        socket.close(); // Fecha o socket
      } catch (IOException e) {
      }
      System.out.println("[Handler] Conexão com " + socket.getInetAddress() + " fechada. Clientes restantes: "
          + allWriters.size());
    }
  }

  // Processa a mensagem em texto puro (GET ou UPDATE).
  private void processMessage(String plaintext) throws Exception {
    System.out.println("[Handler] Mensagem recebida de " + socket.getInetAddress() + ": " + plaintext);

    if (plaintext.startsWith("GET ")) {
      // Cliente REQUISITANTE
      String name = plaintext.substring(4);
      String ip = dnsMap.getOrDefault(name, "NOT_FOUND");
      secureSend(ip, myWriter); // Envia a resposta (segura)

    } else if (plaintext.startsWith("UPDATE ")) {
      String[] parts = plaintext.substring(7).split(" ");
      if (parts.length >= 2) {
        String name = parts[0];
        String newIp = parts[1];
        dnsMap.put(name, newIp); // Atualiza o mapa

        System.out.println("[Handler] BINDING DINÂMICO: " + name + " atualizado para " + newIp);

        // Responde ao registrador que deu certo
        secureSend("UPDATE_OK", myWriter);

        // Requisito: Notificar todos os clientes
        String updateMessage = "NOTIFY: " + name + "=" + newIp;
        broadcastUpdate(updateMessage);
      }
    }
  }

  /**
   * Envia uma atualização (segura) para TODOS os clientes conectados,
   * exceto para este (que é o registrador).
   */
  private void broadcastUpdate(String updateMessage) throws Exception {
    System.out.println("[Handler] Enviando notificação para " + (allWriters.size() - 1) + " clientes...");
    for (PrintWriter writer : allWriters) {
      if (writer != myWriter) { // Não envia a notificação para quem fez o update
        secureSend(updateMessage, writer);
      }
    }
  }

  /**
   * Verifica o HMAC e decifra a mensagem.
   */
  private String secureDecrypt(String cipherTextB64, String hmacB64, String viB64) {
    try {
      // Decodifica o HMAC recebido
      byte[] hmacRecebido = Base64.getDecoder().decode(hmacB64);

      // Checa o HMAC
      boolean hmacValido = CryptoUtils.checarHmac(
          hmacKey,
          cipherTextB64.getBytes(StandardCharsets.UTF_8),
          hmacRecebido);

      if (!hmacValido) {
        // Chave HMAC errada ou mensagem adulterada
        System.err.println(
            "[SEGURANÇA] HMAC INVÁLIDO de " + socket.getInetAddress() + "! MENSAGEM DESCARTADA.");
        return null; // Descarta a mensagem
      }

      // Se o HMAC é válido, decifra a mensagem
      byte[] viBytes = Base64.getDecoder().decode(viB64);
      IvParameterSpec vi = new IvParameterSpec(viBytes);

      String plaintext = CryptoUtils.decifrarAES(cipherTextB64, aesKey, vi);
      return plaintext;

    } catch (Exception e) {
      System.err.println("[SEGURANÇA] Erro na decifragem: " + e.getMessage() + ". MENSAGEM DESCARTADA.");
      return null; // Descarta se houver qualquer erro de criptografia
    }
  }

  // Cifra, assina (HMAC) e envia uma mensagem em texto puro para um cliente.
  private void secureSend(String plaintext, PrintWriter writer) throws Exception {
    // Gera um NOVO VI (Vetor de Inicialização) para cada mensagem
    IvParameterSpec vi = CryptoUtils.gerarVI();
    byte[] viBytes = vi.getIV();

    // Cifra a mensagem (AES)
    String cipherTextB64 = CryptoUtils.cifrarAES(plaintext, aesKey, vi);

    // Calcula o HMAC (Autenticidade) da *mensagem cifrada*
    byte[] hmacBytes = CryptoUtils.calcularHmacSha256(hmacKey,
        cipherTextB64.getBytes(StandardCharsets.UTF_8));

    // Converte VI e HMAC para Base64 para envio como string
    String viB64 = Base64.getEncoder().encodeToString(viBytes);
    String hmacB64 = Base64.getEncoder().encodeToString(hmacBytes);

    // Envia as 3 partes, uma por linha
    writer.println(cipherTextB64);
    writer.println(hmacB64);
    writer.println(viB64);
  }
}