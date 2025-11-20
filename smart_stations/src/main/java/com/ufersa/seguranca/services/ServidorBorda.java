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
        buscarChaveCloud();

        try (DatagramSocket serverSocket = new DatagramSocket(Constantes.PORTA_BORDA_UDP);) {
            System.out.println("[BORDA] Ouvindo UDP na porta " + Constantes.PORTA_BORDA_UDP);
            System.out.println("[BORDA] Aguardando sensores...");

            byte[] receiveData = new byte[65535];

            while (true) {
                DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
                serverSocket.receive(receivePacket);

                // Log de recebimento bruto
                System.out.println("\n[UDP] Pacote recebido de: " + receivePacket.getAddress() + ":" + receivePacket.getPort());

                new Thread(() -> processarPacote(receivePacket)).start();
            }
        } catch (Exception e) {
            System.out.println("[ERRO FATAL] " + e.getMessage());
        }
    }

    private static void registrarNoDiscovery() {
        System.out.print("[INIT] Registrando chave publica no Discovery... ");
        try (Socket socket = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_LOCALIZACAO); ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream()); ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            out.writeObject("REGISTRAR_CHAVE:BORDA:" + rsa.getChavePublicaBase64());
            in.readObject();
            System.out.println("OK.");
        } catch (Exception e) {
            System.out.println("FALHA (" + e.getMessage() + ")");
        }
    }

    private static void buscarChaveCloud() {
        System.out.print("[INIT] Buscando chave publica da Cloud... ");
        try (Socket socket = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_LOCALIZACAO); ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream()); ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            out.writeObject("BUSCAR:CLOUD");
            String resposta = (String) in.readObject();

            if (resposta.startsWith("ERRO")) {
                System.out.println("NAO ENCONTRADO (Cloud offline?)");
                return;
            }

            String b64Key = resposta.split("\\|")[1];
            byte[] keyBytes = Base64.getDecoder().decode(b64Key);
            chavePublicaCloud = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyBytes));
            System.out.println("OK.");

        } catch (Exception e) {
            System.out.println("ERRO (" + e.getMessage() + ")");
        }
    }

    private static void processarPacote(DatagramPacket packet) {
        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(packet.getData(), 0, packet.getLength());
            ObjectInputStream ois = new ObjectInputStream(bais);
            Mensagem msg = (Mensagem) ois.readObject();

            System.out.print("[PROCESSAMENTO] Sensor: " + msg.getIdOrigem() + " | Validando JWT... ");

            // 1. Validar JWT
            if (JwtService.validarToken(msg.getTokenJwt()) == null) {
                System.out.println("FALHA (Token Invalido/Expirado)");
                return;
            }
            System.out.println("OK.");

            // 2. Decifrar Hibrido (RSA -> AES)
            byte[] chaveAesBytes = rsa.decifrarChaveSimetrica(msg.getChaveSimetricaCifrada());
            ImplAES aes = new ImplAES(chaveAesBytes);

            // 3. Decifrar Conteudo
            String jsonConteudo = aes.decifrar(msg.getConteudoCifrado());

            // 4. Verificar Integridade (HMAC)
            System.out.print("[PROCESSAMENTO] Verificando Integridade (HMAC)... ");
            byte[] hmacCalculado = Util.calcularHmacSha256(chaveAesBytes, jsonConteudo.getBytes());
            String hmacRecebidoStr = msg.getHmac();
            byte[] hmacRecebidoBytes = Base64.getDecoder().decode(hmacRecebidoStr);

            if (!java.security.MessageDigest.isEqual(hmacCalculado, hmacRecebidoBytes)) {
                System.out.println("FALHA (HMAC nao confere! Pacote descartado)");
                return;
            }
            System.out.println("OK.");

            DadosSensor dados = DadosSensor.fromString(jsonConteudo);
            System.out.println("[DADOS] " + dados.toString());

            // 5. Alerta Rapido (Edge Computing)
            if (dados.getTemperatura() > 40.0) {
                System.out.println(">>> [ALERTA BORDA] Temperatura CRITICA detectada: " + dados.getTemperatura() + "C <<<");
            }

            // 6. Encaminhar para Cloud (TCP + Criptografia Hibrida novamente)
            enviarParaCloud(dados);

        } catch (Exception e) {
            System.out.println("[ERRO PROCESSAMENTO] " + e.getMessage());
        }
    }

    private static void enviarParaCloud(DadosSensor dados) throws Exception {
        if (chavePublicaCloud == null) {
            System.out.println("[ALERTA] Tentando reconectar com Cloud para buscar chave...");
            buscarChaveCloud();
            if (chavePublicaCloud == null) {
                System.out.println("[ERRO] Impossivel enviar para Cloud: Chave publica nao encontrada.");
                return;
            }
        }

        System.out.print("[CLOUD] Encaminhando dados via TCP... ");
        try {
            ImplAES aesEnvio = new ImplAES(192);
            String conteudo = dados.toString();
            String conteudoCifrado = aesEnvio.cifrar(conteudo);
            byte[] chaveSimetricaCifrada = ImplRSA.cifrarChaveSimetrica(aesEnvio.getChaveBytes(), chavePublicaCloud);
            byte[] hmac = Util.calcularHmacSha256(aesEnvio.getChaveBytes(), conteudo.getBytes());

            Mensagem msg = new Mensagem(Constantes.TIPO_DADOS_SENSOR, "BORDA");
            msg.setChaveSimetricaCifrada(chaveSimetricaCifrada);
            msg.setConteudoCifrado(conteudoCifrado);
            msg.setHmac(Base64.getEncoder().encodeToString(hmac));

            // Borda envia sem token ou com token proprio para cloud (simplificado aqui sem token)
            try (Socket socket = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_DATACENTER_TCP); ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream())) {
                out.writeObject(msg);
            }
            System.out.println("Enviado com sucesso.");
        } catch (Exception e) {
            System.out.println("FALHA ao conectar com Datacenter (" + e.getMessage() + ")");
        }
    }
}
