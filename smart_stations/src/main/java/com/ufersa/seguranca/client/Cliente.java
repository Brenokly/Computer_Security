package com.ufersa.seguranca.client;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

import com.ufersa.seguranca.model.Mensagem;
import com.ufersa.seguranca.util.Constantes;
import com.ufersa.seguranca.util.ImplAES;
import com.ufersa.seguranca.util.ImplRSA;
import com.ufersa.seguranca.util.Util;

public class Cliente {

    private static String tokenJwt;
    private static String ipCloud;
    private static int portaCloud;
    private static PublicKey chavePublicaCloud;

    public static void main(String[] args) {
        try (Scanner scanner = new Scanner(System.in)) {
            System.out.println("=== CLIENTE DE MONITORAMENTO (SECURE) ===");

            if (!realizarLogin()) {
                return;
            }
            localizarDatacenter();

            OUTER:
            while (true) {
                System.out.println("\n--- MENU ---");
                System.out.println("1. Relatorios Gerais");
                System.out.println("2. Alertas de Seguranca");
                System.out.println("0. Sair");
                System.out.print("Opcao: ");
                String op = scanner.nextLine();
                switch (op) {
                    case "1" ->
                        enviarRequisicao("GET /relatorios");
                    case "2" ->
                        enviarRequisicao("GET /alertas");
                    case "0" -> {
                        break OUTER;
                    }
                    default -> {
                    }
                }
            }
        } catch (Exception e) {
            System.out.println("Erro no cliente: " + e.getMessage());
        }
    }

    private static boolean realizarLogin() throws Exception {
        System.out.println("[CLIENTE] Iniciando autenticacao...");
        String[] dadosAuth = buscarServico("AUTH");
        PublicKey pubAuth = decodificarChavePublica(dadosAuth[1]);

        try (Socket s = new Socket(dadosAuth[0].split(":")[0], Integer.parseInt(dadosAuth[0].split(":")[1])); ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream()); ObjectInputStream in = new ObjectInputStream(s.getInputStream())) {

            ImplAES aes = new ImplAES(192);
            String creds = "cliente01:admin123";

            System.out.println("[CRYPTO-LOG] Cifrando credenciais com AES...");
            String cc = aes.cifrar(creds);

            System.out.println("[CRYPTO-LOG] Cifrando chave AES com RSA do Auth...");
            byte[] kc = ImplRSA.cifrarChaveSimetrica(aes.getChaveBytes(), pubAuth);

            System.out.println("[CRYPTO-LOG] Gerando HMAC...");
            byte[] hmac = Util.calcularHmacSha256(aes.getChaveBytes(), creds.getBytes());

            Mensagem m = new Mensagem(Constantes.TIPO_AUTH_REQ, "cliente01");
            m.setConteudoCifrado(cc);
            m.setChaveSimetricaCifrada(kc);
            m.setHmac(Base64.getEncoder().encodeToString(hmac));

            out.writeObject(m);
            String resp = aes.decifrar((String) in.readObject());

            if (resp.startsWith("OK")) {
                tokenJwt = resp.split(":")[1];
                System.out.println("[CLIENTE] Login Sucesso. Token JWT Armazenado.");
                return true;
            }
        }
        return false;
    }

    private static void enviarRequisicao(String cmd) throws Exception {
        try (Socket s = new Socket(ipCloud, portaCloud); ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream()); ObjectInputStream in = new ObjectInputStream(s.getInputStream())) {

            System.out.println("\n[CLIENTE] Preparando envio seguro...");
            ImplAES aes = new ImplAES(192);

            System.out.println("[CRYPTO-LOG] Cifrando payload: " + cmd);
            String cc = aes.cifrar(cmd);
            byte[] kc = ImplRSA.cifrarChaveSimetrica(aes.getChaveBytes(), chavePublicaCloud);
            byte[] hmac = Util.calcularHmacSha256(aes.getChaveBytes(), cmd.getBytes());

            Mensagem m = new Mensagem(Constantes.TIPO_RELATORIO_REQ, "CLIENTE");
            m.setTokenJwt(tokenJwt);
            m.setConteudoCifrado(cc);
            m.setChaveSimetricaCifrada(kc);
            m.setHmac(Base64.getEncoder().encodeToString(hmac));

            out.writeObject(m);
            System.out.println("[CLIENTE] Enviado.");

            String respCifrada = (String) in.readObject();
            System.out.println("[CLIENTE] Resposta recebida. Decifrando...");
            System.out.println(aes.decifrar(respCifrada));
        }
    }

    private static void localizarDatacenter() throws Exception {
        String[] d = buscarServico("CLOUD");
        ipCloud = d[0].split(":")[0];

        portaCloud = Constantes.PORTA_FIREWALL_1_TCP;

        chavePublicaCloud = decodificarChavePublica(d[1]);
        System.out.println("[CLIENTE] Conectando via FIREWALL DE BORDA: " + ipCloud + ":" + portaCloud);
    }

    private static String[] buscarServico(String n) throws Exception {
        try (Socket s = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_LOCALIZACAO); ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream()); ObjectInputStream in = new ObjectInputStream(s.getInputStream())) {
            out.writeObject("BUSCAR:" + n);
            return ((String) in.readObject()).split("\\|");
        }
    }

    private static PublicKey decodificarChavePublica(String b) throws Exception {
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(b)));
    }
}
