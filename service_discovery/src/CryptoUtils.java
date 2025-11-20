
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Classe utilitária para centralizar os métodos de criptografia
 */
public class CryptoUtils {

    // Converte array de bytes para string hex (minúscula).
    public static String bytes2Hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }

    // Calcula HMAC-SHA256 dado uma chave (bytes) e os dados (bytes).
    public static byte[] calcularHmacSha256(byte[] chave, byte[] bytesMensagem) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(chave, "HmacSHA256");
        mac.init(keySpec);
        return mac.doFinal(bytesMensagem);
    }

    // Verifica HMAC de forma segura (tempo constante).
    public static boolean checarHmac(byte[] chave, byte[] bytesMensagem, byte[] hmacRecebido) throws Exception {
        byte[] hmacCalculado = calcularHmacSha256(chave, bytesMensagem);
        System.out.println("  [LOG-SEGURANÇA Recebimento Encapsulado]    > HMAC Calculado: " + bytes2Hex(hmacCalculado));
        return MessageDigest.isEqual(hmacCalculado, hmacRecebido);
    }

    // Gera um Vetor de Inicialização (VI) aleatório de 16 bytes.
    public static IvParameterSpec gerarVI() {
        byte[] vi = new byte[16];
        new SecureRandom().nextBytes(vi);
        return new IvParameterSpec(vi);
    }

    // Codifica bytes para Base64.
    private static String codificarBase64(byte[] bytesCifrados) {
        return Base64.getEncoder().encodeToString(bytesCifrados);
    }

    // Decodifica Base64 para bytes.
    private static byte[] decodificarBase64(String mensagemCodificada) {
        return Base64.getDecoder().decode(mensagemCodificada);
    }

    /**
     * Cifra uma mensagem (String) usando AES/CBC/PKCS5Padding. Requer a chave
     * (bytes) e o VI. Retorna String em Base64.
     */
    public static String cifrarAES(String textoAberto, byte[] chave, IvParameterSpec vi) throws Exception {
        // Cria a SecretKeySpec a partir dos bytes da chave
        SecretKeySpec secretKey = new SecretKeySpec(chave, "AES");

        Cipher cifrador = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cifrador.init(Cipher.ENCRYPT_MODE, secretKey, vi);
        byte[] bytesMensagemCifrada = cifrador.doFinal(textoAberto.getBytes(StandardCharsets.UTF_8));

        // Retorna em Base64 para facilitar o envio pela rede
        return codificarBase64(bytesMensagemCifrada);
    }

    /**
     * Decifra uma mensagem (String Base64) usando AES/CBC/PKCS5Padding. Requer
     * a chave (bytes) e o VI. Retorna a String original.
     */
    public static String decifrarAES(String textoCifrado, byte[] chave, IvParameterSpec vi) throws Exception {
        // Cria a SecretKeySpec a partir dos bytes da chave
        SecretKeySpec secretKey = new SecretKeySpec(chave, "AES");

        byte[] bytesMensagemCifrada = decodificarBase64(textoCifrado);

        Cipher decriptador = Cipher.getInstance("AES/CBC/PKCS5Padding");
        decriptador.init(Cipher.DECRYPT_MODE, secretKey, vi);
        byte[] bytesMensagemDecifrada = decriptador.doFinal(bytesMensagemCifrada);

        return new String(bytesMensagemDecifrada, StandardCharsets.UTF_8);
    }
}
