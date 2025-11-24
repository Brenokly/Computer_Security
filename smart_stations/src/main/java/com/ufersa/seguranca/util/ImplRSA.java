package com.ufersa.seguranca.util;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;

/**
 * Implementação de Criptografia Assimétrica (RSA).
 * Padrão: RSA de 1024 bits.
 * Uso: Troca de chaves (Key Transport). Cifra a chave AES para criar o "Envelope Digital".
 */

public class ImplRSA {

    private PublicKey chavePublica;
    private PrivateKey chavePrivada;

    public ImplRSA() throws NoSuchAlgorithmException {
        gerarChaves();
    }

    private void gerarChaves() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        SecureRandom sr = new SecureRandom();
        kpg.initialize(1024, sr);
        KeyPair kp = kpg.generateKeyPair();
        this.chavePublica = kp.getPublic();
        this.chavePrivada = kp.getPrivate();
    }

    public String getChavePublicaBase64() {
        return Base64.getEncoder().encodeToString(chavePublica.getEncoded());
    }

    public String cifrar(String msg) throws Exception {
        Cipher cifrador = Cipher.getInstance("RSA");
        cifrador.init(Cipher.ENCRYPT_MODE, chavePrivada);
        return Base64.getEncoder().encodeToString(cifrador.doFinal(msg.getBytes()));
    }

    public String decifrar(String msgCifradaBase64) throws Exception {
        byte[] bytesMsgCifrada = Base64.getDecoder().decode(msgCifradaBase64);
        Cipher decifrador = Cipher.getInstance("RSA");
        decifrador.init(Cipher.DECRYPT_MODE, chavePublica);
        return new String(decifrador.doFinal(bytesMsgCifrada));
    }

    public byte[] decifrarChaveSimetrica(byte[] chaveCifrada) throws Exception {
        Cipher decifrador = Cipher.getInstance("RSA");
        decifrador.init(Cipher.DECRYPT_MODE, chavePrivada);
        return decifrador.doFinal(chaveCifrada);
    }

    public static byte[] cifrarChaveSimetrica(byte[] chaveAES, PublicKey publicaDestino) throws Exception {
        Cipher cifrador = Cipher.getInstance("RSA");
        cifrador.init(Cipher.ENCRYPT_MODE, publicaDestino);
        return cifrador.doFinal(chaveAES);
    }
}
