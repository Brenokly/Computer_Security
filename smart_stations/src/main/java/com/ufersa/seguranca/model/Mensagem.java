package com.ufersa.seguranca.model;

import java.io.Serializable;

/**
 * DTO (Data Transfer Object) para o Protocolo de Segurança.
 * Estrutura do Envelope Digital:
 * 1. conteudoCifrado: Dados criptografados com AES.
 * 2. chaveSimetricaCifrada: Chave AES criptografada com RSA.
 * 3. hmac: Assinatura de integridade dos dados originais.
 * 4. tokenJwt: Prova de autenticação (Sessão).
 */

public class Mensagem implements Serializable {

    private final int tipo;
    private final String idOrigem;
    private byte[] chaveSimetricaCifrada;
    private String conteudoCifrado;
    private String hmac;
    private String tokenJwt;

    public Mensagem(int tipo, String idOrigem) {
        this.tipo = tipo;
        this.idOrigem = idOrigem;
    }

    public int getTipo() {
        return tipo;
    }

    public String getIdOrigem() {
        return idOrigem;
    }

    public byte[] getChaveSimetricaCifrada() {
        return chaveSimetricaCifrada;
    }

    public void setChaveSimetricaCifrada(byte[] chave) {
        this.chaveSimetricaCifrada = chave;
    }

    public String getConteudoCifrado() {
        return conteudoCifrado;
    }

    public void setConteudoCifrado(String conteudo) {
        this.conteudoCifrado = conteudo;
    }

    public String getHmac() {
        return hmac;
    }

    public void setHmac(String hmac) {
        this.hmac = hmac;
    }

    public String getTokenJwt() {
        return tokenJwt;
    }

    public void setTokenJwt(String token) {
        this.tokenJwt = token;
    }
}
