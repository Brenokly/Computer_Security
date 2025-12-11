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
    private static ObjectInputStream inCloud;

    public static void main(String[] args) throws Exception {
        System.out.println("=== FIREWALL 2 (PROXY REVERSO - APLICACAO) ===");
        rsa = new ImplRSA();
        registrarNoDiscovery();
        sincronizarChaveJwt("PROXY");
        buscarChaveCloud();

        try (ServerSocket serverSocket = new ServerSocket(Constantes.PORTA_FIREWALL_2_PROXY)) {
            System.out.println("[PROXY] Monitorando porta TCP " + Constantes.PORTA_FIREWALL_2_PROXY);

            while (true) {
                Socket socketOrigem = serverSocket.accept();
                new Thread(() -> processarConexao(socketOrigem)).start();
            }
        }
    }

    private static void processarConexao(Socket socketOrigem) {
        try {
            ObjectOutputStream outVolta = new ObjectOutputStream(socketOrigem.getOutputStream());
            outVolta.flush();
            ObjectInputStream in = new ObjectInputStream(socketOrigem.getInputStream());

            while (true) {
                Object obj = in.readObject();
                if (obj instanceof Mensagem msg) {
                    processarMensagem(msg, outVolta);
                }
            }
        } catch (Exception e) {
            System.out.println("[PROXY] Conexao encerrada.");
        }
    }

    private static void processarMensagem(Mensagem msg, ObjectOutputStream outVolta) {
        try {
            System.out.println("\n[PROXY] >>> Inspecionando Pacote...");

            if (JwtService.validarToken(msg.getTokenJwt()) == null) {
                System.out.println("[PROXY] BLOQUEADO: Token JWT Invalido.");
                return;
            }

            byte[] chaveAesBytes = rsa.decifrarChaveSimetrica(msg.getChaveSimetricaCifrada());
            ImplAES aesEntrada = new ImplAES(chaveAesBytes);
            String jsonConteudo = aesEntrada.decifrar(msg.getConteudoCifrado());

            byte[] hmacCalculado = Util.calcularHmacSha256(chaveAesBytes, jsonConteudo.getBytes());
            if (!java.security.MessageDigest.isEqual(hmacCalculado, Base64.getDecoder().decode(msg.getHmac()))) {
                System.out.println("[PROXY] BLOQUEADO: Falha de Integridade (HMAC).");
                return;
            }

            if (msg.getTipo() == Constantes.TIPO_DADOS_SENSOR) {
                DadosSensor dados = DadosSensor.fromString(jsonConteudo);
                if (detectarAnomalia(dados)) {
                    System.out.println("[PROXY] !!! ANOMALIA DETECTADA (Temp: " + dados.getTemperatura() + ") !!!");
                    enviarAlertaIDS("ANOMALIA_DETECTADA|" + dados.getIdDispositivo() + "|Temp:" + dados.getTemperatura());
                    return;
                }
                encaminharParaCloud(jsonConteudo, msg.getTipo(), null, null);

            } else if (msg.getTipo() == Constantes.TIPO_RELATORIO_REQ) {
                System.out.println("[PROXY] Cliente validado. Buscando na Cloud...");
                encaminharParaCloud(jsonConteudo, msg.getTipo(), outVolta, aesEntrada);
            }

        } catch (Exception e) {
            System.out.println("[PROXY] Erro processamento: " + e.getMessage());
        }
    }

    private static boolean detectarAnomalia(DadosSensor dados) {
        return dados.getTemperatura() > 80.0 || dados.getTemperatura() < -20.0 || dados.getCo2() > 2000.0;
    }

    private static void encaminharParaCloud(String conteudoClaro, int tipoMsg, ObjectOutputStream outVoltaParaCliente, ImplAES aesCliente) throws Exception {
        if (chavePublicaCloud == null) {
            buscarChaveCloud();
        }
        garantirConexaoCloud();

        ImplAES aesProxyToCloud = new ImplAES(192);
        String conteudoCifrado = aesProxyToCloud.cifrar(conteudoClaro);
        byte[] chaveSimetricaCifrada = ImplRSA.cifrarChaveSimetrica(aesProxyToCloud.getChaveBytes(), chavePublicaCloud);
        byte[] hmac = Util.calcularHmacSha256(aesProxyToCloud.getChaveBytes(), conteudoClaro.getBytes());

        Mensagem msg = new Mensagem(tipoMsg, "PROXY");
        msg.setTokenJwt(JwtService.gerarToken("PROXY_FW", "SERVER"));
        msg.setChaveSimetricaCifrada(chaveSimetricaCifrada);
        msg.setConteudoCifrado(conteudoCifrado);
        msg.setHmac(Base64.getEncoder().encodeToString(hmac));

        synchronized (outCloud) {
            outCloud.writeObject(msg);
            outCloud.flush();
            outCloud.reset();
        }
        System.out.println("[PROXY -> CLOUD] Requisicao enviada.");

        if (outVoltaParaCliente != null && aesCliente != null) {
            synchronized (inCloud) {
                String respCifradaDaCloud = (String) inCloud.readObject();

                String respClaro = aesProxyToCloud.decifrar(respCifradaDaCloud);
                System.out.println("[PROXY <- CLOUD] Resposta recebida e decifrada.");
                String respCifradaParaCliente = aesCliente.cifrar(respClaro);
                
                outVoltaParaCliente.writeObject(respCifradaParaCliente);
                outVoltaParaCliente.flush();
                System.out.println("[PROXY -> CLIENTE] Resposta recifrada e devolvida.");
            }
        }
    }

    private static synchronized void garantirConexaoCloud() {
        try {
            if (socketCloud == null || socketCloud.isClosed() || !socketCloud.isConnected()) {
                socketCloud = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_DATACENTER_TCP);
                outCloud = new ObjectOutputStream(socketCloud.getOutputStream());
                outCloud.flush();
                inCloud = new ObjectInputStream(socketCloud.getInputStream());
            }
        } catch (IOException e) {
            System.out.println("[PROXY] Erro conectar Cloud: " + e.getMessage());
        }
    }

    private static void enviarAlertaIDS(String msg) {
        try (Socket s = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_IDS); ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream())) {
            out.writeObject(msg);
        } catch (Exception e) {
        }
    }

    private static void registrarNoDiscovery() {
        try (Socket s = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_LOCALIZACAO); ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream()); ObjectInputStream in = new ObjectInputStream(s.getInputStream())) {
            out.writeObject("REGISTRAR_CHAVE:PROXY:" + rsa.getChavePublicaBase64());
            in.readObject();
        } catch (Exception e) {
        }
    }

    private static void sincronizarChaveJwt(String nome) {
        try (Socket s = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_AUTH); ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream()); ObjectInputStream in = new ObjectInputStream(s.getInputStream())) {
            out.writeObject("SOLICITAR_CHAVE_JWT:" + nome);
            String k = (String) in.readObject();
            byte[] b = rsa.decifrarChaveSimetrica(Base64.getDecoder().decode(k));
            JwtService.setChaveMestra(Base64.getEncoder().encodeToString(b));
        } catch (Exception e) {
        }
    }

    private static void buscarChaveCloud() {
        try (Socket s = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_LOCALIZACAO); ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream()); ObjectInputStream in = new ObjectInputStream(s.getInputStream())) {
            out.writeObject("BUSCAR:CLOUD");
            String[] resp = ((String) in.readObject()).split("\\|");
            byte[] kb = Base64.getDecoder().decode(resp[1]);
            chavePublicaCloud = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(kb));
        } catch (Exception e) {
        }
    }
}
