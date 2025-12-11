package com.ufersa.seguranca.services;

import java.io.EOFException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import com.ufersa.seguranca.model.DadosSensor;
import com.ufersa.seguranca.model.Mensagem;
import com.ufersa.seguranca.util.Constantes;
import com.ufersa.seguranca.util.ImplAES;
import com.ufersa.seguranca.util.ImplRSA;
import com.ufersa.seguranca.util.JwtService;
import com.ufersa.seguranca.util.Util;

public class Datacenter {

    private static ImplRSA rsa;
    private static final List<DadosSensor> bancoDados = Collections.synchronizedList(new ArrayList<>());

    public static void main(String[] args) throws Exception {
        System.out.println("=== DATACENTER (CLOUD SECURE STORAGE) ===");
        rsa = new ImplRSA();
        registrarNoDiscovery();
        sincronizarChaveJwt("CLOUD");

        try (ServerSocket serverSocket = new ServerSocket(Constantes.PORTA_DATACENTER_TCP)) {
            System.out.println("[CLOUD] Aguardando conexoes seguras na porta " + Constantes.PORTA_DATACENTER_TCP);
            while (true) {
                Socket socket = serverSocket.accept();
                new Thread(() -> processarConexaoPersistente(socket)).start();
            }
        }
    }

    private static void processarConexaoPersistente(Socket socket) {
        String ip = socket.getInetAddress().getHostAddress();
        System.out.println("[CLOUD] Nova conexao estabelecida: " + ip);

        try (ObjectInputStream in = new ObjectInputStream(socket.getInputStream()); ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream())) {

            while (true) {
                try {
                    Object obj = in.readObject();
                    if (obj instanceof Mensagem msg) {
                        tratarMensagem(msg, out);
                    }
                } catch (EOFException e) {
                    System.out.println("[CLOUD] Conexao encerrada pelo cliente.");
                    break;
                } catch (Exception e) {
                    System.out.println("[CLOUD] Erro na conexao: " + e.getMessage());
                    break;
                }
            }
        } catch (Exception e) {
            System.out.println("[CLOUD] Erro ao processa conexao de " + ip + ": " + e.getMessage());
        }
    }

    private static void tratarMensagem(Mensagem msg, ObjectOutputStream out) throws Exception {
        System.out.println("\n[CLOUD] >>> Mensagem Recebida. Processo de Seguranca Iniciado:");

        System.out.println("[CRYPTO-LOG] 1. Validando Autenticidade (JWT)...");
        if (JwtService.validarToken(msg.getTokenJwt()) == null) {
            System.out.println("[CLOUD] ERRO: Token Invalido/Expirado.");
            return;
        }
        System.out.println("[CRYPTO-LOG]    -> Token Autenticad.");

        System.out.println("[CRYPTO-LOG] 2. Decifrando Chave de Sessao (RSA)...");
        byte[] chaveAesBytes = rsa.decifrarChaveSimetrica(msg.getChaveSimetricaCifrada());
        System.out.println("[CRYPTO-LOG]    -> Chave Simrtrica obtida.");

        System.out.println("[CRYPTO-LOG] 3. Decifrando Dados (AES)...");
        ImplAES aes = new ImplAES(chaveAesBytes);
        String conteudo = aes.decifrar(msg.getConteudoCifrado());

        System.out.println("[CRYPTO-LOG] 4. Validando Integridade dos Dados (HMAC)...");
        byte[] hmacCalculado = Util.calcularHmacSha256(chaveAesBytes, conteudo.getBytes());
        if (!java.security.MessageDigest.isEqual(hmacCalculado, Base64.getDecoder().decode(msg.getHmac()))) {
            System.out.println("[CLOUD] ERRO: Integridade Violada! HMAC nao confere.");
            return;
        }
        System.out.println("[CRYPTO-LOG]    -> Dados integros.");

        if (msg.getTipo() == Constantes.TIPO_DADOS_SENSOR) {
            DadosSensor dados = DadosSensor.fromString(conteudo);
            bancoDados.add(dados);
            System.out.println("[DB] Registro persistido com sucesso: " + dados.getIdDispositivo());

        } else if (msg.getTipo() == Constantes.TIPO_RELATORIO_REQ) {
            System.out.println("[API] Requisicao de Relatorio: " + conteudo);
            String resposta = processarMenuCliente(conteudo);

            System.out.println("[CLOUD] Cifrando resposta para o Cliente...");
            String respCifrada = aes.cifrar(resposta);
            out.writeObject(respCifrada);
            out.flush();
        }
    }

    private static String processarMenuCliente(String comando) {
        StringBuilder sb = new StringBuilder();
        if (comando == null) {
            return "Erro";
        }

        switch (comando) {
            case "GET /relatorios" -> {
                sb.append("=== ESTATISTICAS GERAIS ===\n");
                sb.append("Total de Registros: ").append(bancoDados.size()).append("\n");
                double mediaTemp = bancoDados.stream().mapToDouble(DadosSensor::getTemperatura).average().orElse(0.0);
                sb.append("Temp Media: ").append(String.format("%.2f", mediaTemp)).append(" C\n");
            }
            case "GET /alertas" -> {
                sb.append("=== LOGS DE SEGURANCA ===\n");
                sb.append("Consulte o painel do IDS para ver tentativas de intrusao.\n");
            }
            default ->
                sb.append("Comando desconhecido.");
        }
        return sb.toString();
    }

    private static void registrarNoDiscovery() {
        try (Socket socket = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_LOCALIZACAO); ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream()); ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {
            out.writeObject("REGISTRAR_CHAVE:CLOUD:" + rsa.getChavePublicaBase64());
            in.readObject();
        } catch (Exception e) {
            System.out.println("[CLOUD] Erro ao registrar no Discovery: " + e.getMessage());
        }
    }

    private static void sincronizarChaveJwt(String nome) {
        try {
            String[] dadosAuth = buscarServico("AUTH");
            try (Socket socket = new Socket(dadosAuth[0].split(":")[0], Integer.parseInt(dadosAuth[0].split(":")[1])); ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream()); ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {
                out.writeObject("SOLICITAR_CHAVE_JWT:" + nome);
                String k = (String) in.readObject();
                byte[] b = rsa.decifrarChaveSimetrica(Base64.getDecoder().decode(k));
                JwtService.setChaveMestra(Base64.getEncoder().encodeToString(b));
            }
        } catch (Exception e) {
            System.out.println("[CLOUD] Erro ao sincronizar chave JWT: " + e.getMessage());
        }
    }

    private static String[] buscarServico(String nome) throws Exception {
        try (Socket s = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_LOCALIZACAO); ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream()); ObjectInputStream in = new ObjectInputStream(s.getInputStream())) {
            out.writeObject("BUSCAR:" + nome);
            return ((String) in.readObject()).split("\\|");
        }
    }
}
