package com.ufersa.seguranca.services;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
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

public class FirewallProxy {

    private static ImplRSA rsa;
    private static PublicKey chavePublicaCloud;
    private static Socket socketCloud;
    private static ObjectOutputStream outCloud;

    public static void main(String[] args) throws Exception {
        System.out.println("=== FIREWALL 2 (PROXY REVERSO - APLICACAO) ===");
        rsa = new ImplRSA();
        registrarNoDiscovery();
        sincronizarChaveJwt("PROXY");
        buscarChaveCloud();

        try (ServerSocket serverSocket = new ServerSocket(Constantes.PORTA_FIREWALL_2_PROXY)) {
            System.out.println("[PROXY] Monitorando porta TCP " + Constantes.PORTA_FIREWALL_2_PROXY);

            while (true) {
                Socket socketBorda = serverSocket.accept();
                new Thread(() -> processarConexao(socketBorda)).start();
            }
        }
    }

    private static void processarConexao(Socket socketBorda) {
        try (ObjectInputStream in = new ObjectInputStream(socketBorda.getInputStream())) {
            while (true) {
                Object obj = in.readObject();
                if (obj instanceof Mensagem msg) {
                    processarMensagem(msg);
                }
            }
        } catch (Exception e) {
            System.out.println("[PROXY] Conexao com Borda encerrada/interrompida.");
        }
    }

    private static void processarMensagem(Mensagem msg) {
        try {
            System.out.println("\n[PROXY] >>> Recebido Envelope Digital da Borda. Iniciando Inspecao...");

            System.out.println("[CRYPTO-LOG] 1. Validando Token JWT...");
            if (JwtService.validarToken(msg.getTokenJwt()) == null) {
                System.out.println("[PROXY] BLOQUEADO: Token JWT Invalido.");
                return;
            }
            System.out.println("[CRYPTO-LOG]    -> Token Valido.");

            System.out.println("[CRYPTO-LOG] 2. Decifrando Chave Simetrica (RSA Privada do Proxy)...");
            byte[] chaveAesBytes = rsa.decifrarChaveSimetrica(msg.getChaveSimetricaCifrada());
            System.out.println("[CRYPTO-LOG]    -> Chave AES recuperada.");

            System.out.println("[CRYPTO-LOG] 3. Decifrando Payload (AES-192)...");
            ImplAES aesEntrada = new ImplAES(chaveAesBytes);
            String jsonConteudo = aesEntrada.decifrar(msg.getConteudoCifrado());
            System.out.println("[CRYPTO-LOG]    -> Conteudo legivel recuperado.");

            System.out.println("[CRYPTO-LOG] 4. Verificando Integridade (HMAC-SHA256)...");
            byte[] hmacCalculado = Util.calcularHmacSha256(chaveAesBytes, jsonConteudo.getBytes());
            if (!java.security.MessageDigest.isEqual(hmacCalculado, Base64.getDecoder().decode(msg.getHmac()))) {
                System.out.println("[PROXY] BLOQUEADO: Falha de Integridade (HMAC).");
                return;
            }
            System.out.println("[CRYPTO-LOG]    -> Integridade confirmada.");

            DadosSensor dados = DadosSensor.fromString(jsonConteudo);
            System.out.println("[INSPECAO DE PACOTE] Analisando dados do sensor " + dados.getIdDispositivo() + "...");

            if (detectarAnomalia(dados)) {
                System.out.println("[PROXY] !!! ALERTA: ANOMALIA DETECTADA (Temp: " + dados.getTemperatura() + ") !!!");
                System.out.println("[PROXY] Acao: Descartar pacote e notificar IDS.");
                enviarAlertaIDS("ANOMALIA_DETECTADA|" + dados.getIdDispositivo() + "|Temp:" + dados.getTemperatura());
                return;
            }

            System.out.println("[PROXY] Pacote Limpo. Re-encriptando para a Cloud (Rede Interna)...");
            encaminharParaCloud(dados);

        } catch (Exception e) {
            System.out.println("[PROXY] Erro ao processar mensagem: " + e.getMessage());
        }
    }

    private static boolean detectarAnomalia(DadosSensor dados) {
        if (dados.getTemperatura() > 80.0 || dados.getTemperatura() < -20.0 || dados.getCo2() > 2000.0) {
            return true;
        }

        return false;
    }

    private static void encaminharParaCloud(DadosSensor dados) throws Exception {
        if (chavePublicaCloud == null) {
            buscarChaveCloud();
        }
        garantirConexaoCloud();

        ImplAES aesSaida = new ImplAES(192);

        System.out.println("[CRYPTO-LOG-OUT] 1. Gerando nova chave AES Sessao...");
        String conteudoCifrado = aesSaida.cifrar(dados.toString());

        System.out.println("[CRYPTO-LOG-OUT] 2. Cifrando Chave AES com RSA Publica da Cloud...");
        byte[] chaveSimetricaCifrada = ImplRSA.cifrarChaveSimetrica(aesSaida.getChaveBytes(), chavePublicaCloud);

        System.out.println("[CRYPTO-LOG-OUT] 3. Assinando com HMAC...");
        byte[] hmac = Util.calcularHmacSha256(aesSaida.getChaveBytes(), dados.toString().getBytes());

        Mensagem msg = new Mensagem(Constantes.TIPO_DADOS_SENSOR, "PROXY");
        msg.setTokenJwt(JwtService.gerarToken("PROXY_FW", "SERVER"));
        msg.setChaveSimetricaCifrada(chaveSimetricaCifrada);
        msg.setConteudoCifrado(conteudoCifrado);
        msg.setHmac(Base64.getEncoder().encodeToString(hmac));

        synchronized (outCloud) {
            outCloud.writeObject(msg);
            outCloud.flush();
            outCloud.reset();
        }
        System.out.println("[PROXY -> CLOUD] Envelope seguro enviado.");
    }

    private static synchronized void garantirConexaoCloud() {
        try {
            if (socketCloud == null || socketCloud.isClosed() || !socketCloud.isConnected()) {
                socketCloud = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_DATACENTER_TCP);
                outCloud = new ObjectOutputStream(socketCloud.getOutputStream());
            }
        } catch (IOException e) {
            System.out.println("[PROXY] Falha ao conectar na Cloud: " + e.getMessage());
        }
    }

    private static void enviarAlertaIDS(String msg) {
        try (Socket s = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_IDS); ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream())) {
            out.writeObject(msg);
            System.out.println("[PROXY] Alerta enviado ao IDS.");
        } catch (Exception e) {
            System.out.println("[PROXY] Erro ao contactar IDS.");
        }
    }

    private static void registrarNoDiscovery() {
        try (Socket socket = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_LOCALIZACAO); ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream()); ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {
            out.writeObject("REGISTRAR_CHAVE:PROXY:" + rsa.getChavePublicaBase64());
            in.readObject();
        } catch (Exception e) {
            System.out.println("[PROXY] Erro ao registrar no Discovery: " + e.getMessage());
        }
    }

    private static void sincronizarChaveJwt(String nome) {
        try (Socket socket = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_AUTH); ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream()); ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {
            out.writeObject("SOLICITAR_CHAVE_JWT:" + nome);
            String k = (String) in.readObject();
            byte[] b = rsa.decifrarChaveSimetrica(Base64.getDecoder().decode(k));
            JwtService.setChaveMestra(Base64.getEncoder().encodeToString(b));
        } catch (Exception e) {
            System.out.println("[PROXY] Erro ao sincronizar chave JWT: " + e.getMessage());
        }
    }

    private static void buscarChaveCloud() {
        try (Socket socket = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_LOCALIZACAO); ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream()); ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {
            out.writeObject("BUSCAR:CLOUD");
            String[] resp = ((String) in.readObject()).split("\\|");
            byte[] kb = Base64.getDecoder().decode(resp[1]);
            chavePublicaCloud = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(kb));
        } catch (Exception e) {
            System.out.println("[PROXY] Erro ao obter chave publica da Cloud: " + e.getMessage());
        }
    }
}
