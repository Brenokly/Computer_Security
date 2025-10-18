import java.nio.charset.StandardCharsets;

/**
 * Classe para armazenar as chaves secretas compartilhadas
 * entre o servidor e os clientes.
 * * É fundamental que o cliente e o servidor tenham exatamente
 * as mesmas chaves para a comunicação funcionar.
 */
public class SharedConfig {

  // Chave para Cifragem Simétrica (AES)
  // DEVE ter 16 bytes (AES-128), 24 bytes (AES-192) ou 32 bytes (AES-256).
  // "minha-chave-aes!" tem 16 caracteres, logo, 16 bytes.
  private static final String AES_KEY_STRING = "minha-chave-aes!";

  // Chave para Autenticação (HMAC)
  private static final String HMAC_KEY_STRING = "chave-secreta-hmac";

  // Retorna os bytes da chave AES (16 bytes).
  public static byte[] getAesKey() {
    return AES_KEY_STRING.getBytes(StandardCharsets.UTF_8);
  }

  // Retorna os bytes da chave HMAC.
  public static byte[] getHmacKey() {
    return HMAC_KEY_STRING.getBytes(StandardCharsets.UTF_8);
  }
}