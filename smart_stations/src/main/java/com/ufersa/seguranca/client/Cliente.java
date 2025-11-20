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
            try {
                System.out.println("=================================================");
                System.out.println("[CLIENTE] Iniciando aplicacao...");

                // 1. Localizacao e Autenticacao
                if (!realizarLogin()) {
                    System.out.println("[CLIENTE] Encerrando por falha de login.");
                    return;
                }

                // 2. Redirecionamento (Discovery Cloud)
                localizarDatacenter();

                // 3. Menu Interativo
                boolean rodando = true;
                while (rodando) {
                    System.out.println("\n=================================================");
                    System.out.println("           MENU DE MONITORAMENTO AMBIENTAL       ");
                    System.out.println("=================================================");
                    System.out.println("1. Solicitar Relatorios Gerais (Estatísticas)");
                    System.out.println("2. Ver Alertas Criticos (Tempo Real)");
                    System.out.println("3. Ver Previsoes (Analise IA)");
                    System.out.println("0. Sair");
                    System.out.print(">> Escolha uma opcao: ");

                    String input = scanner.nextLine();

                    try {
                        int opcao = Integer.parseInt(input);
                        switch (opcao) {
                            case 1 ->
                                enviarRequisicao("GET /relatorios");
                            case 2 ->
                                enviarRequisicao("GET /alertas");
                            case 3 ->
                                enviarRequisicao("GET /previsoes");
                            case 0 -> {
                                System.out.println("[CLIENTE] Encerrando sessao. Ate logo!");
                                rodando = false;
                            }
                            default ->
                                System.out.println("[ERRO] Opcao invalida.");
                        }
                    } catch (NumberFormatException nfe) {
                        System.out.println("[ERRO] Digite apenas numeros.");
                    }
                }

            } catch (Exception e) {
                System.out.println("[ERRO CRITICO] " + e.getMessage());
            }
        }
    }

    private static boolean realizarLogin() throws Exception {
        System.out.print("[INIT] Buscando Servidor de Autenticacao... ");
        String[] dadosAuth = buscarServico("AUTH");
        String ipAuth = dadosAuth[0].split(":")[0];
        int portaAuth = Integer.parseInt(dadosAuth[0].split(":")[1]);
        System.out.println("Encontrado (" + ipAuth + ":" + portaAuth + ")");

        System.out.print("[CRYPTO] Processando Chave Publica do Auth... ");
        PublicKey chavePublicaAuth = decodificarChavePublica(dadosAuth[1]);
        System.out.println("OK.");

        System.out.println("[LOGIN] Conectando para autenticar...");
        try (Socket s = new Socket(ipAuth, portaAuth); ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream()); ObjectInputStream in = new ObjectInputStream(s.getInputStream())) {

            // 1. Criptografia Híbrida
            System.out.print("   -> Gerando chave AES temporaria (192 bits)... ");
            ImplAES aes = new ImplAES(192);
            System.out.println("OK.");

            String credenciais = "cliente01:admin123";
            System.out.print("   -> Cifrando credenciais e assinando (HMAC)... ");

            String conteudoCifrado = aes.cifrar(credenciais);
            byte[] chaveSimetricaCifrada = ImplRSA.cifrarChaveSimetrica(aes.getChaveBytes(), chavePublicaAuth);
            byte[] hmac = Util.calcularHmacSha256(aes.getChaveBytes(), credenciais.getBytes());
            System.out.println("OK.");

            // 2. Montar Mensagem
            Mensagem msg = new Mensagem(Constantes.TIPO_AUTH_REQ, "cliente01");
            msg.setConteudoCifrado(conteudoCifrado);
            msg.setChaveSimetricaCifrada(chaveSimetricaCifrada);
            msg.setHmac(Base64.getEncoder().encodeToString(hmac));

            // 3. Enviar
            out.writeObject(msg);

            // 4. Receber Resposta
            System.out.print("[LOGIN] Aguardando resposta... ");
            String respostaCifrada = (String) in.readObject();
            String resp = aes.decifrar(respostaCifrada);

            if (resp.startsWith("OK")) {
                tokenJwt = resp.split(":")[1];
                System.out.println("SUCESSO! Token JWT recebido.");
                return true;
            } else {
                System.out.println("NEGADO (" + resp + ")");
                return false;
            }
        } catch (Exception e) {
            System.out.println("ERRO (" + e.getMessage() + ")");
            return false;
        }
    }

    private static void localizarDatacenter() throws Exception {
        System.out.print("[INIT] Localizando Datacenter (Cloud)... ");
        String[] dadosCloud = buscarServico("CLOUD");
        ipCloud = dadosCloud[0].split(":")[0];
        portaCloud = Integer.parseInt(dadosCloud[0].split(":")[1]);
        chavePublicaCloud = decodificarChavePublica(dadosCloud[1]);
        System.out.println("OK. Redirecionado para " + ipCloud + ":" + portaCloud);
    }

    private static void enviarRequisicao(String comandoHttp) {
        System.out.println("\n[REQ] Enviando comando: " + comandoHttp);
        try (Socket socket = new Socket(ipCloud, portaCloud); ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream()); ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            // Criptografia
            System.out.print("   -> Aplicando Criptografia Hibrida e HMAC... ");
            ImplAES aes = new ImplAES(192); // Nova chave a cada requisição (Perfect Forward Secrecy "fajuto")

            String conteudoCifrado = aes.cifrar(comandoHttp);
            byte[] chaveSimetricaCifrada = ImplRSA.cifrarChaveSimetrica(aes.getChaveBytes(), chavePublicaCloud);
            byte[] hmac = Util.calcularHmacSha256(aes.getChaveBytes(), comandoHttp.getBytes());
            System.out.println("OK.");

            Mensagem msg = new Mensagem(Constantes.TIPO_RELATORIO_REQ, "CLIENTE_APP");
            msg.setTokenJwt(tokenJwt);
            msg.setChaveSimetricaCifrada(chaveSimetricaCifrada);
            msg.setConteudoCifrado(conteudoCifrado);
            msg.setHmac(Base64.getEncoder().encodeToString(hmac));

            out.writeObject(msg);
            System.out.println("   -> Enviado.");

            String respostaCifrada = (String) in.readObject();
            System.out.print("   -> Resposta recebida. Decifrando... ");
            String resposta = aes.decifrar(respostaCifrada);
            System.out.println("OK.");

            System.out.println("\n[RESPOSTA DA NUVEM]");
            System.out.println(resposta);

        } catch (Exception e) {
            System.out.println("[ERRO CONEXAO] " + e.getMessage());
        }
    }

    private static String[] buscarServico(String nome) throws Exception {
        try (Socket s = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_LOCALIZACAO); ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream()); ObjectInputStream in = new ObjectInputStream(s.getInputStream())) {
            out.writeObject("BUSCAR:" + nome);
            String resp = (String) in.readObject();
            return resp.split("\\|");
        }
    }

    private static PublicKey decodificarChavePublica(String b64) throws Exception {
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(b64)));
    }
}
