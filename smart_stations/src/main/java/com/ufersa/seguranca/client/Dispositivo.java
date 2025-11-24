package com.ufersa.seguranca.client;

import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import static java.lang.Thread.sleep;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.ThreadLocalRandom;

import com.ufersa.seguranca.model.DadosSensor;
import com.ufersa.seguranca.model.Mensagem;
import com.ufersa.seguranca.util.Constantes;
import com.ufersa.seguranca.util.ImplAES;
import com.ufersa.seguranca.util.ImplRSA;
import com.ufersa.seguranca.util.Util;

/**
 * DISPOSITIVO SENSOR (IoT Client)
 * * Responsabilidade: Coleta de dados ambientais e envio seguro.
 * Ciclo de Segurança:
 * 1. Descoberta: Consulta o Servidor de Localização.
 * 2. Autenticação: Realiza login seguro (Híbrido) para obter Token JWT.
 * 3. Coleta: Gera dados aleatórios dentro de faixas reais (temperatura, CO2, etc).
 * 4. Envio Seguro:
 * - Gera chave AES-192 aleatória por pacote (Session Key).
 * - Cifra os dados com AES.
 * - Cifra a chave AES com a RSA Pública da Borda (Envelope Digital).
 * - Assina com HMAC-SHA256 e envia via UDP.
*/

public class Dispositivo {

    public void iniciarCiclo(String id, String usuario, String senha) {
        try {
            System.out.println("=================================================");
            System.out.println("[" + id + "] INICIALIZANDO SENSOR...");

            // 1. Descoberta Auth
            System.out.print("[" + id + "] Buscando Servidor de Autenticacao... ");
            String[] dadosAuth = buscarServico("AUTH");
            String ipAuth = dadosAuth[0].split(":")[0];
            int portaAuth = Integer.parseInt(dadosAuth[0].split(":")[1]);
            System.out.println("Encontrado (" + ipAuth + ":" + portaAuth + ")");

            // 2. Autenticacao
            String token = autenticar(ipAuth, portaAuth, usuario, senha);
            if (token == null) {
                System.out.println("[" + id + "] ERRO FATAL: Falha na autenticacao. Encerrando sensor.");
                return;
            }
            System.out.println("[" + id + "] STATUS: Online e Autenticado.");

            // 3. Descoberta Borda
            System.out.print("[" + id + "] Buscando Gateway de Borda... ");
            String[] dadosBorda = buscarServico("BORDA");
            String ipBorda = dadosBorda[0].split(":")[0];
            int portaBorda = Integer.parseInt(dadosBorda[0].split(":")[1]);
            PublicKey chavePublicaBorda = decodificarChavePublica(dadosBorda[1]);
            System.out.println("Conectado a " + ipBorda + ":" + portaBorda);

            long fim = System.currentTimeMillis() + (5 * 60 * 1000);
            System.out.println("[" + id + "] Iniciando coleta de dados (Duracao: 5 min)...");
            System.out.println("=================================================");

            try (DatagramSocket socket = new DatagramSocket()) {
                int sequencia = 1;
                while (System.currentTimeMillis() < fim) {
                    System.out.print("[" + id + "] #" + sequencia + " Gerando dados... ");
                    DadosSensor dados = new DadosSensor(id);

                    // Criptografia
                    ImplAES aes = new ImplAES(192);
                    String conteudoCifrado = aes.cifrar(dados.toString());
                    byte[] chaveSimetricaCifrada = ImplRSA.cifrarChaveSimetrica(aes.getChaveBytes(), chavePublicaBorda);
                    byte[] hmacBytes = Util.calcularHmacSha256(aes.getChaveBytes(), dados.toString().getBytes());
                    System.out.print("Cifrando (AES-192 + RSA + HMAC)... ");

                    Mensagem msg = new Mensagem(Constantes.TIPO_DADOS_SENSOR, id);
                    msg.setTokenJwt(token);
                    msg.setConteudoCifrado(conteudoCifrado);
                    msg.setChaveSimetricaCifrada(chaveSimetricaCifrada);
                    msg.setHmac(Base64.getEncoder().encodeToString(hmacBytes));

                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    ObjectOutputStream oos = new ObjectOutputStream(baos);
                    oos.writeObject(msg);
                    byte[] buffer = baos.toByteArray();

                    InetAddress address = InetAddress.getByName(ipBorda);
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length, address, portaBorda);
                    socket.send(packet);

                    System.out.println("Enviado UDP (" + buffer.length + " bytes). Temp: " + String.format("%.2f", dados.getTemperatura()) + "C");

                    sequencia++;
                    sleep(ThreadLocalRandom.current().nextInt(2000, 3001));
                }
            }

        } catch (Exception e) {
            System.out.println("[" + id + "] ERRO CRITICO: " + e.getMessage());
        }
    }

    private String[] buscarServico(String nomeServico) throws Exception {
        try (Socket socket = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_LOCALIZACAO); ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream()); ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            out.writeObject("BUSCAR:" + nomeServico);
            String resposta = (String) in.readObject();
            if (resposta.startsWith("ERRO")) {
                throw new Exception("Servico " + nomeServico + " nao encontrado.");
            }
            return resposta.split("\\|");
        }
    }

    private String autenticar(String ip, int porta, String user, String pass) {
        try {
            System.out.print("   -> [AUTH] Obtendo chave publica do Auth... ");
            String[] dadosAuth = buscarServico("AUTH");
            PublicKey chavePublicaAuth = decodificarChavePublica(dadosAuth[1]);
            System.out.println("OK.");

            try (Socket socket = new Socket(ip, porta); ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream()); ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

                // 1. Criptografia Híbrida
                System.out.print("   -> [AUTH] Cifrando credenciais... ");
                ImplAES aes = new ImplAES(192);
                String payload = user + ":" + pass;

                String conteudoCifrado = aes.cifrar(payload);
                byte[] chaveSimetricaCifrada = ImplRSA.cifrarChaveSimetrica(aes.getChaveBytes(), chavePublicaAuth);
                byte[] hmac = Util.calcularHmacSha256(aes.getChaveBytes(), payload.getBytes());

                Mensagem msg = new Mensagem(Constantes.TIPO_AUTH_REQ, user);
                msg.setConteudoCifrado(conteudoCifrado);
                msg.setChaveSimetricaCifrada(chaveSimetricaCifrada);
                msg.setHmac(Base64.getEncoder().encodeToString(hmac));

                // 3. Enviar Mensagem Segura
                out.writeObject(msg);
                System.out.println("Enviado.");

                // 4. Receber Resposta
                String respostaCifrada = (String) in.readObject();
                String resposta = aes.decifrar(respostaCifrada);

                if (resposta.startsWith("OK")) {
                    System.out.println("   -> [AUTH] Sucesso! Token recebido.");
                    return resposta.split(":")[1];
                } else {
                    System.out.println("   -> [AUTH] Falha: " + resposta);
                }
            }
        } catch (Exception e) {
            System.out.println("   -> [AUTH] Erro de conexao: " + e.getMessage());
        }
        return null;
    }

    private PublicKey decodificarChavePublica(String b64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(b64);
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyBytes));
    }
}
