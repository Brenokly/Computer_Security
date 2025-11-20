package com.ufersa.seguranca.util;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class ImplHashSalt {

    public static String getHashSenhaSegura(String senha) throws Exception {
        int iteracoes = 10000;
        char[] chars = senha.toCharArray();
        byte[] salt = getSalt();

        PBEKeySpec spec = new PBEKeySpec(chars, salt, iteracoes, 512);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hash = skf.generateSecret(spec).getEncoded();

        return iteracoes + ":" + toHex(salt) + ":" + toHex(hash);
    }

    public static boolean validarSenha(String senha, String hashArmazenado) throws Exception {
        String[] partes = hashArmazenado.split(":");
        int iteracoes = Integer.parseInt(partes[0]);
        byte[] salt = fromHex(partes[1]);
        byte[] hashOriginal = fromHex(partes[2]);

        PBEKeySpec spec = new PBEKeySpec(senha.toCharArray(), salt, iteracoes, 512);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hashTeste = skf.generateSecret(spec).getEncoded();

        int diff = hashOriginal.length ^ hashTeste.length;
        for (int i = 0; i < hashOriginal.length && i < hashTeste.length; i++) {
            diff |= hashOriginal[i] ^ hashTeste[i];
        }
        return diff == 0;
    }

    private static byte[] getSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return salt;
    }

    private static String toHex(byte[] array) {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();
        if (paddingLength > 0) {
            return String.format("%0" + paddingLength + "d", 0) + hex;
        } else {
            return hex;
        }
    }

    private static byte[] fromHex(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return bytes;
    }
}
