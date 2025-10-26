
import java.io.BufferedReader;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.NoSuchElementException;
import java.util.StringJoiner;
import java.util.StringTokenizer;
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

    public static String decifrarAES(String textoCifrado, byte[] chave, IvParameterSpec vi) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(chave, "AES");

        byte[] bytesMensagemCifrada = decodificarBase64(textoCifrado);

        Cipher decriptador = Cipher.getInstance("AES/CBC/PKCS5Padding");
        decriptador.init(Cipher.DECRYPT_MODE, secretKey, vi);
        byte[] bytesMensagemDecifrada = decriptador.doFinal(bytesMensagemCifrada);

        return new String(bytesMensagemDecifrada, StandardCharsets.UTF_8);
    }

    public static void secureSendEncapsulated(PrintWriter writer, String plaintext, byte[] aesKey, byte[] hmacKey)
            throws Exception {
        System.out.println("\n  [LOG-SEGURANÇA Envio Encapsulado] Mensagem original: \"" + plaintext + "\"");
        System.out.println("  [LOG-SEGURANÇA Envio Encapsulado] 1. Gerando novo VI...");

        IvParameterSpec vi = gerarVI();
        byte[] viBytes = vi.getIV();
        String cipherTextB64 = cifrarAES(plaintext, aesKey, vi);
        System.out.println("  [LOG-SEGURANÇA Envio Encapsulado] 2. Cifrando com AES-CBC ->: "
                + cipherTextB64);

        byte[] hmacBytes = calcularHmacSha256(hmacKey,
                cipherTextB64.getBytes(StandardCharsets.UTF_8));
        System.out.println("  [LOG-SEGURANÇA Envio Encapsulado] 3. Calculando HMAC do texto cifrado...");

        String viB64 = Base64.getEncoder().encodeToString(viBytes);
        String hmacB64 = Base64.getEncoder().encodeToString(hmacBytes);

        StringJoiner joiner = new StringJoiner("|");
        joiner.add(cipherTextB64);
        joiner.add(hmacB64);
        joiner.add(viB64);
        String encapsulatedMessage = joiner.toString();

        System.out.println("  [LOG-SEGURANÇA Envio Encapsulado] 4. Enviando pacote encapsulado...");
        writer.println(encapsulatedMessage);
    }

    public static String secureReceiveEncapsulated(BufferedReader reader, byte[] aesKey, byte[] hmacKey) {
        try {
            String encapsulatedMessage = reader.readLine();
            if (encapsulatedMessage == null || encapsulatedMessage.isEmpty()) {
                return null;
            }

            StringTokenizer tokenizer = new StringTokenizer(encapsulatedMessage, "|");
            String cipherTextB64 = tokenizer.nextToken();
            String hmacB64 = tokenizer.nextToken();
            String viB64 = tokenizer.nextToken();

            System.out.println("\n  [LOG-SEGURANÇA Recebimento Encapsulado] 1. Recebido pacote encapsulado.");
            System.out.println("  [LOG-SEGURANÇA Recebimento Encapsulado]    > Cifra: " + cipherTextB64);
            System.out.println("  [LOG-SEGURANÇA Recebimento Encapsulado]    > HMAC:  " + hmacB64);
            System.out.println("  [LOG-SEGURANÇA Recebimento Encapsulado] 2. Verificando HMAC...");

            byte[] hmacRecebido = Base64.getDecoder().decode(hmacB64);
            boolean hmacValido = checarHmac(
                    hmacKey,
                    cipherTextB64.getBytes(StandardCharsets.UTF_8),
                    hmacRecebido);

            if (!hmacValido) {
                System.err.println("  [LOG-SEGURANÇA Recebimento Encapsulado] 3. FALHA! HMACs não conferem. PACOTE DESCARTADO.");
                return null;
            }

            System.out.println("  [LOG-SEGURANÇA Recebimento Encapsulado] 3. SUCESSO! HMAC válido.");
            System.out.println("  [LOG-SEGURANÇA Recebimento Encapsulado] 4. Decifrando com AES-CBC...");

            byte[] viBytes = Base64.getDecoder().decode(viB64);
            IvParameterSpec vi = new IvParameterSpec(viBytes);
            String plaintext = decifrarAES(cipherTextB64, aesKey, vi);

            System.out.println("  [LOG-SEGURANÇA Recebimento Encapsulado] 5. Mensagem decifrada: \"" + plaintext + "\"");

            return plaintext;

        } catch (NoSuchElementException e) {
            System.err.println("[SEGURANÇA] Erro ao separar pacote: formato inválido (esperado Cifra|HMAC|VI). PACOTE DESCARTADO.");
            return null;
        } catch (Exception e) {
            System.err.println("[SEGURANÇA] Erro na decifragem encapsulada: " + e.getMessage() + ". PACOTE DESCARTADO.");
            return null;
        }
    }
}
