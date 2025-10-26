import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.crypto.spec.IvParameterSpec;

/**
 * Thread que lida com um único pedido de cálculo
 * no Servidor de Calculadora.
 * (Reutiliza os métodos de segurança)
 */
public class CalculationHandler extends Thread {

  private final Socket socket;
  private final byte[] aesKey;
  private final byte[] hmacKey;

  public CalculationHandler(Socket socket) {
    this.socket = socket;
    this.aesKey = SharedConfig.getAesKey();
    this.hmacKey = SharedConfig.getHmacKey();
  }

  @Override
  public void run() {
    try (
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
        PrintWriter writer = new PrintWriter(socket.getOutputStream(), true, StandardCharsets.UTF_8)) {

      // Recebe a mensagem segura
      String cipherTextB64 = reader.readLine();
      String hmacB64 = reader.readLine();
      String viB64 = reader.readLine();

      if (cipherTextB64 == null) {
        return; // Cliente desconectou
      }

      // Verifica e decifra
      String plaintext = secureDecrypt(cipherTextB64, hmacB64, viB64);

      if (plaintext == null) {
        // Erro de HMAC. Servidor descarta.
        System.err.println("[CalcHandler] HMAC Inválido recebido. Conexão descartada.");
        return;
      }

      System.out.println("[CalcHandler] Recebido pedido de cálculo: " + plaintext);

      // Processa o cálculo
      String result = performCalculation(plaintext);

      // Envia a resposta segura
      secureSend(writer, result);

    } catch (Exception e) {
      System.err.println("[CalcHandler] Erro: " + e.getMessage());
    } finally {
      try {
        socket.close();
      } catch (IOException e) {
        /* ignore */ }
    }
  }

  /**
   * Realiza a operação de cálculo.
   * Formato esperado: "soma 5 10"
   */
  private String performCalculation(String plaintext) {
    String[] parts = plaintext.split(" ");
    if (parts.length != 3) {
      return "ERRO: Formato inválido. Esperado: <operacao> <num1> <num2>";
    }

    try {
      String operacao = parts[0].toLowerCase();
      double num1 = Double.parseDouble(parts[1]);
      double num2 = Double.parseDouble(parts[2]);
      double result;

      switch (operacao) {
        case "soma" -> result = num1 + num2;
        case "subtracao" -> result = num1 - num2;
        case "multiplicacao" -> result = num1 * num2;
        case "divisao" -> {
          if (num2 == 0)
            return "ERRO: Divisão por zero";
          result = num1 / num2;
        }
        default -> {
          return "ERRO: Operação desconhecida";
        }
      }
      return String.valueOf(result);

    } catch (NumberFormatException e) {
      return "ERRO: Números inválidos";
    }
  }

  //
  // --- MÉTODOS DE SEGURANÇA (IDÊNTICOS AOS OUTROS ARQUIVOS) ---
  //

  private String secureDecrypt(String cipherTextB64, String hmacB64, String viB64) {
    try {
      byte[] hmacRecebido = Base64.getDecoder().decode(hmacB64);
      boolean hmacValido = CryptoUtils.checarHmac(
          hmacKey,
          cipherTextB64.getBytes(StandardCharsets.UTF_8),
          hmacRecebido);
      if (!hmacValido)
        return null;
      byte[] viBytes = Base64.getDecoder().decode(viB64);
      IvParameterSpec vi = new IvParameterSpec(viBytes);
      return CryptoUtils.decifrarAES(cipherTextB64, aesKey, vi);
    } catch (Exception e) {
      return null;
    }
  }

  private void secureSend(PrintWriter writer, String plaintext) throws Exception {
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