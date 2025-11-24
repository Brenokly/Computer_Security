package com.ufersa.seguranca.util;

import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Implementação de Criptografia Simétrica (AES).
 * Padrão: AES/CBC/PKCS5Padding com chaves de 192 bits.
 * Uso: Cifrar o conteúdo (payload) das mensagens devido à sua alta performance.
 */

public class ImplAES {

    private final SecretKey chave;
    private IvParameterSpec vi;

    public ImplAES(int tamChave) throws Exception {
        KeyGenerator geradorDeChaves = KeyGenerator.getInstance("AES");
        geradorDeChaves.init(tamChave);
        this.chave = geradorDeChaves.generateKey();
    }

    public ImplAES(byte[] chaveBytes) {
        this.chave = new SecretKeySpec(chaveBytes, "AES");
    }

    public byte[] getChaveBytes() {
        return chave.getEncoded();
    }

    public String cifrar(String textoAberto) throws Exception {
        Cipher cifrador = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] viBytes = new byte[16];
        new SecureRandom().nextBytes(viBytes);
        this.vi = new IvParameterSpec(viBytes);

        cifrador.init(Cipher.ENCRYPT_MODE, chave, vi);
        byte[] cifrados = cifrador.doFinal(textoAberto.getBytes());

        byte[] msgCompleta = new byte[viBytes.length + cifrados.length];
        System.arraycopy(viBytes, 0, msgCompleta, 0, viBytes.length);
        System.arraycopy(cifrados, 0, msgCompleta, viBytes.length, cifrados.length);

        return Base64.getEncoder().encodeToString(msgCompleta);
    }

    public String decifrar(String textoCifrado) throws Exception {
        byte[] msgCompleta = Base64.getDecoder().decode(textoCifrado);

        byte[] viBytes = new byte[16];
        System.arraycopy(msgCompleta, 0, viBytes, 0, viBytes.length);
        this.vi = new IvParameterSpec(viBytes);

        byte[] cifrados = new byte[msgCompleta.length - 16];
        System.arraycopy(msgCompleta, 16, cifrados, 0, cifrados.length);

        Cipher decriptador = Cipher.getInstance("AES/CBC/PKCS5Padding");
        decriptador.init(Cipher.DECRYPT_MODE, chave, vi);

        byte[] decifrados = decriptador.doFinal(cifrados);
        return new String(decifrados);
    }
}
