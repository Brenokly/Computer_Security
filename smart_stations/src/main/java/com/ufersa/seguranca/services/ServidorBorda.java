package com.ufersa.seguranca.services;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

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
    private static Socket socketProximoSalto;
    private static ObjectOutputStream outProximoSalto;
    private static final Set<String> sessoesBloqueadas = new HashSet<>();

    public static void main(String[] args) throws Exception {
        System.out.println("=== SERVIDOR DE BORDA (DMZ) ===");
        rsa = new ImplRSA();
        registrarNoDiscovery();
        sincronizarChaveJwt("BORDA");
        buscarChaveCloud();

        new Thread(ServidorBorda::iniciarListenerComandosIDS).start();

        try (DatagramSocket serverSocket = new DatagramSocket(Constantes.PORTA_BORDA_UDP)) {
            System.out.println("[BORDA] Ouvindo UDP na porta " + Constantes.PORTA_BORDA_UDP);
            System.out.println("[BORDA] Encaminhamento configurado para FIREWALL PROXY (Porta " + Constantes.PORTA_FIREWALL_2_PROXY + ")");

            garantirConexaoProximoSalto();

            byte[] receiveData = new byte[65535];
            while (true) {
                DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
                serverSocket.receive(receivePacket);
                new Thread(() -> processarPacote(receivePacket)).start();
            }
        }
    }

    private static void iniciarListenerComandosIDS() {
        try (ServerSocket server = new ServerSocket(Constantes.PORTA_IDS_CMD_BORDA)) {
            System.out.println("[BORDA] Ouvindo comandos do IDS na porta " + Constantes.PORTA_IDS_CMD_BORDA);
            while (true) {
                Socket s = server.accept();
                try (ObjectInputStream in = new ObjectInputStream(s.getInputStream())) {
                    String cmd = (String) in.readObject();
                    if (cmd.startsWith("BLOQUEAR:")) {
                        String alvo = cmd.split(":")[1];
                        sessoesBloqueadas.add(alvo);
                        System.out.println("[BORDA] !!! COMANDO IDS: Bloqueando origem '" + alvo + "' !!!");
                    }
                } catch (Exception e) {
                    System.out.println("[BORDA] Erro ao processar comando IDS: " + e.getMessage());
                }
            }
        } catch (IOException e) {
            System.out.println("[BORDA] Erro no listener de comandos IDS: " + e.getMessage());
        }
    }

    private static synchronized void garantirConexaoProximoSalto() {
        try {
            if (socketProximoSalto == null || socketProximoSalto.isClosed() || !socketProximoSalto.isConnected()) {
                System.out.print("[TCP] Conectando ao Firewall Proxy... ");
                socketProximoSalto = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_FIREWALL_2_PROXY);
                outProximoSalto = new ObjectOutputStream(socketProximoSalto.getOutputStream());
                System.out.println("CONECTADO.");
            }
        } catch (IOException e) {
            System.out.println("FALHA CONEXAO PROXY (" + e.getMessage() + ")");
            socketProximoSalto = null;
        }
    }

    private static void enviarParaProximoSalto(DadosSensor dados) throws Exception {
        if (chavePublicaCloud == null) {
            buscarChaveCloud();
        }
        garantirConexaoProximoSalto();

        if (outProximoSalto == null) {
            return;
        }
        try {
            ImplAES aesEnvio = new ImplAES(192);
            String conteudoCifrado = aesEnvio.cifrar(dados.toString());
            byte[] chaveSimetricaCifrada = ImplRSA.cifrarChaveSimetrica(aesEnvio.getChaveBytes(), chavePublicaCloud);
            byte[] hmac = Util.calcularHmacSha256(aesEnvio.getChaveBytes(), dados.toString().getBytes());

            Mensagem msg = new Mensagem(Constantes.TIPO_DADOS_SENSOR, "BORDA");
            msg.setTokenJwt(JwtService.gerarToken("BORDA_GATEWAY", "SERVER"));
            msg.setChaveSimetricaCifrada(chaveSimetricaCifrada);
            msg.setConteudoCifrado(conteudoCifrado);
            msg.setHmac(Base64.getEncoder().encodeToString(hmac));

            synchronized (outProximoSalto) {
                outProximoSalto.writeObject(msg);
                outProximoSalto.flush();
                outProximoSalto.reset();
            }
            System.out.println("[BORDA -> PROXY] Envelope enviado.");

        } catch (Exception e) {
            System.out.println("[ERRO ENVIO] " + e.getMessage());
            try {
                socketProximoSalto.close();
            } catch (IOException ex) {
            }
            socketProximoSalto = null;
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
        String ipOrigem = packet.getAddress().getHostAddress();

        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(packet.getData(), 0, packet.getLength());
            ObjectInputStream ois = new ObjectInputStream(bais);
            Mensagem msg = (Mensagem) ois.readObject();

            if (sessoesBloqueadas.contains(ipOrigem) || sessoesBloqueadas.contains(msg.getIdOrigem())) {
                System.out.println("[BORDA] Pacote descartado. Origem bloqueada pelo IDS: " + msg.getIdOrigem());
                return;
            }

            System.out.print("[BORDA] Sensor: " + msg.getIdOrigem() + " | Validando... ");
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
            enviarParaProximoSalto(dados);

        } catch (Exception e) {
            System.out.println("[ERRO PROCESSAMENTO] " + e.getMessage());
        }
    }
}
