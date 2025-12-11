package com.ufersa.seguranca.client;

import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
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
import com.ufersa.seguranca.util.Util;

public class SensorMalicioso {

    public static void main(String[] args) {
        new SensorMalicioso().executarAtaque();
    }

    public void executarAtaque() {
        try {
            System.out.println("=== SENSOR MALICIOSO INICIANDO ATAQUE ===");

            String id = "sensor01";

            String[] dadosAuth = buscarServico("AUTH");
            String token = autenticar(dadosAuth[0].split(":")[0], Integer.parseInt(dadosAuth[0].split(":")[1]), "sensor01", "admin123");

            if (token == null) {
                System.out.println("Falha ao obter token valido para o ataque.");
                return;
            }

            String[] dadosBorda = buscarServico("BORDA");
            PublicKey pubBorda = decodificarChavePublica(dadosBorda[1]);
            int portaDestino = Constantes.PORTA_FIREWALL_1_UDP;

            try (DatagramSocket socket = new DatagramSocket()) {
                while (true) {
                    DadosSensor dados = new DadosSensor(id);

                    alterarTemperaturaNaForca(dados, 1500.0);
                    System.out.println("[ATAQUE] Gerando dado anomalp: Temp 1500.0 C");

                    ImplAES aes = new ImplAES(192);
                    String cc = aes.cifrar(dados.toString());
                    byte[] kc = ImplRSA.cifrarChaveSimetrica(aes.getChaveBytes(), pubBorda);
                    byte[] hmac = Util.calcularHmacSha256(aes.getChaveBytes(), dados.toString().getBytes());

                    Mensagem msg = new Mensagem(Constantes.TIPO_DADOS_SENSOR, id);
                    msg.setTokenJwt(token);
                    msg.setConteudoCifrado(cc);
                    msg.setChaveSimetricaCifrada(kc);
                    msg.setHmac(Base64.getEncoder().encodeToString(hmac));

                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    ObjectOutputStream oos = new ObjectOutputStream(baos);
                    oos.writeObject(msg);
                    byte[] buffer = baos.toByteArray();

                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length, InetAddress.getByName(Constantes.IP_LOCAL), portaDestino);
                    socket.send(packet);

                    System.out.println("[ATAQUE] Pacote enviado. Aguardando deteccao...");
                    Thread.sleep(4000);
                }
            }

        } catch (Exception e) {
            System.out.println("Ataque interrompido: " + e.getMessage());
        }
    }

    private void alterarTemperaturaNaForca(DadosSensor d, double temp) throws Exception {
        Field f = DadosSensor.class.getDeclaredField("temperatura");
        f.setAccessible(true);
        f.setDouble(d, temp);
    }

    private String[] buscarServico(String nome) throws Exception {
        try (Socket s = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_LOCALIZACAO); ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream()); ObjectInputStream in = new ObjectInputStream(s.getInputStream())) {
            out.writeObject("BUSCAR:" + nome);
            return ((String) in.readObject()).split("\\|");
        }
    }

    private String autenticar(String ip, int porta, String user, String pass) {
        try {
            String[] dadosAuth = buscarServico("AUTH");
            PublicKey pubAuth = decodificarChavePublica(dadosAuth[1]);
            try (Socket s = new Socket(ip, porta); ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream()); ObjectInputStream in = new ObjectInputStream(s.getInputStream())) {
                ImplAES aes = new ImplAES(192);
                String payload = user + ":" + pass;
                Mensagem m = new Mensagem(Constantes.TIPO_AUTH_REQ, user);
                m.setConteudoCifrado(aes.cifrar(payload));
                m.setChaveSimetricaCifrada(ImplRSA.cifrarChaveSimetrica(aes.getChaveBytes(), pubAuth));
                m.setHmac(Base64.getEncoder().encodeToString(Util.calcularHmacSha256(aes.getChaveBytes(), payload.getBytes())));
                out.writeObject(m);
                String resp = aes.decifrar((String) in.readObject());
                if (resp.startsWith("OK")) {
                    return resp.split(":")[1];
                }
            }
        } catch (Exception e) {
            return null;
        }
        return null;
    }

    private PublicKey decodificarChavePublica(String b64) throws Exception {
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(b64)));
    }
}
