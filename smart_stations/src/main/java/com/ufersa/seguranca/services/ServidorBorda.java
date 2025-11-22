package com.ufersa.seguranca.services;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import com.ufersa.seguranca.model.DadosSensor;
import com.ufersa.seguranca.model.Mensagem;
import com.ufersa.seguranca.util.Constantes;
import com.ufersa.seguranca.util.ImplAES;
import com.ufersa.seguranca.util.ImplRSA;
import com.ufersa.seguranca.util.JwtService;
import com.ufersa.seguranca.util.Util;

public class ServidorBorda {

    private static ImplRSA rsa;
    private static PublicKey chavePublicaCloud;

    public static void main(String[] args) throws Exception {
        System.out.println("=== INICIALIZANDO SERVIDOR DE BORDA (EDGE) ===");
        rsa = new ImplRSA();
        registrarNoDiscovery();
        sincronizarChaveJwt("BORDA");
        buscarChaveCloud();

        try (DatagramSocket serverSocket = new DatagramSocket(Constantes.PORTA_BORDA_UDP)) {
            System.out.println("[BORDA] Ouvindo UDP na porta " + Constantes.PORTA_BORDA_UDP);
            System.out.println("[BORDA] Aguardando sensores...");
            byte[] receiveData = new byte[65535];

            while (true) {
                DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
                serverSocket.receive(receivePacket);
                System.out.println("\n[UDP] Pacote recebido de: " + receivePacket.getAddress() + ":" + receivePacket.getPort());
                new Thread(() -> processarPacote(receivePacket)).start();
            }
        } catch (Exception e) {
            System.out.println("[ERRO FATAL] " + e.getMessage());
        }
    }

    private static void registrarNoDiscovery() {
        try (Socket socket = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_LOCALIZACAO); ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream()); ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {
            out.writeObject("REGISTRAR_CHAVE:BORDA:" + rsa.getChavePublicaBase64());
            in.readObject();
            System.out.println("[INIT] Chave registrada no Discovery.");
        } catch (Exception e) {
            System.out.println("[INIT] Falha ao registrar: " + e.getMessage());
        }
    }

    private static void sincronizarChaveJwt(String meuNome) {
        try {
            String[] dadosAuth = buscarServico("AUTH");
            try (Socket socket = new Socket(dadosAuth[0].split(":")[0], Integer.parseInt(dadosAuth[0].split(":")[1])); ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream()); ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

                out.writeObject("SOLICITAR_CHAVE_JWT:" + meuNome);
                String chaveCifradaBase64 = (String) in.readObject();
                byte[] chaveJwtBytes = rsa.decifrarChaveSimetrica(Base64.getDecoder().decode(chaveCifradaBase64));
                JwtService.setChaveMestra(Base64.getEncoder().encodeToString(chaveJwtBytes));
                System.out.println("[INIT] Chave JWT sincronizada.");
            }
        } catch (Exception e) {
            System.out.println("[INIT] Erro ao sincronizar chave JWT: " + e.getMessage());
        }
    }

    private static void buscarChaveCloud() {
        try {
            String[] dadosCloud = buscarServico("CLOUD");
            byte[] keyBytes = Base64.getDecoder().decode(dadosCloud[1]);
            chavePublicaCloud = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyBytes));
            System.out.println("[INIT] Chave Publica da Cloud obtida.");
        } catch (Exception e) {
            System.out.println("[INIT] Erro ao buscar chave Cloud: " + e.getMessage());
        }
    }

    private static String[] buscarServico(String nomeServico) throws Exception {
        try (Socket socket = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_LOCALIZACAO); ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream()); ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {
            out.writeObject("BUSCAR:" + nomeServico);
            String resposta = (String) in.readObject();
            if (resposta.startsWith("ERRO")) {
                throw new Exception("Servico nao encontrado");
            }
            return resposta.split("\\|");
        }
    }

    private static void processarPacote(DatagramPacket packet) {
        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(packet.getData(), 0, packet.getLength());
            ObjectInputStream ois = new ObjectInputStream(bais);
            Mensagem msg = (Mensagem) ois.readObject();

            System.out.print("[PROCESSAMENTO] Sensor: " + msg.getIdOrigem() + " | Validando... ");
            if (JwtService.validarToken(msg.getTokenJwt()) == null) {
                System.out.println("TOKEN INVALIDO");
                return;
            }

            byte[] chaveAesBytes = rsa.decifrarChaveSimetrica(msg.getChaveSimetricaCifrada());
            ImplAES aes = new ImplAES(chaveAesBytes);
            String jsonConteudo = aes.decifrar(msg.getConteudoCifrado());

            byte[] hmacCalculado = Util.calcularHmacSha256(chaveAesBytes, jsonConteudo.getBytes());
            if (!java.security.MessageDigest.isEqual(hmacCalculado, Base64.getDecoder().decode(msg.getHmac()))) {
                System.out.println("HMAC INVALIDO");
                return;
            }
            System.out.println("OK.");

            DadosSensor dados = DadosSensor.fromString(jsonConteudo);
            if (dados.getTemperatura() > 40.0) {
                System.out.println(">>> [ALERTA BORDA] Temp Critica: " + dados.getTemperatura() + "C <<<");
            }

            enviarParaCloud(dados);

        } catch (Exception e) {
            System.out.println("[ERRO PROCESSAMENTO] " + e.getMessage());
        }
    }

    private static void enviarParaCloud(DadosSensor dados) throws Exception {
        if (chavePublicaCloud == null) {
            buscarChaveCloud();
        }

        try {
            ImplAES aesEnvio = new ImplAES(192);
            String conteudo = dados.toString();

            String conteudoCifrado = aesEnvio.cifrar(conteudo);
            byte[] chaveSimetricaCifrada = ImplRSA.cifrarChaveSimetrica(aesEnvio.getChaveBytes(), chavePublicaCloud);
            byte[] hmac = Util.calcularHmacSha256(aesEnvio.getChaveBytes(), conteudo.getBytes());

            Mensagem msg = new Mensagem(Constantes.TIPO_DADOS_SENSOR, "BORDA");

            // CORREÇÃO 1: Gerar Token Válido para a Borda
            String tokenBorda = JwtService.gerarToken("BORDA_GATEWAY", "SERVER");
            msg.setTokenJwt(tokenBorda);

            msg.setChaveSimetricaCifrada(chaveSimetricaCifrada);
            msg.setConteudoCifrado(conteudoCifrado);
            msg.setHmac(Base64.getEncoder().encodeToString(hmac));

            System.out.print("[CLOUD] Enviando TCP... ");

            // CORREÇÃO 2: Handshake (Esperar resposta antes de fechar)
            try (Socket socket = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_DATACENTER_TCP); ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream()); ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

                out.writeObject(msg);
                // Espera confirmação para não quebrar a conexão
                String confirmacao = (String) in.readObject();
                System.out.println("Confirmado (" + confirmacao + ").");
            }
        } catch (Exception e) {
            System.out.println("FALHA (" + e.getMessage() + ")");
            chavePublicaCloud = null;
        }
    }
}
