package com.ufersa.seguranca.services;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

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
        System.out.println("=================================================");
        System.out.println("[CLOUD] Inicializando Datacenter...");
        rsa = new ImplRSA();
        registrarNoDiscovery();
        sincronizarChaveJwt("CLOUD");

        try (ServerSocket serverSocket = new ServerSocket(Constantes.PORTA_DATACENTER_TCP)) {
            System.out.println("[CLOUD] Servidor rodando na porta TCP " + Constantes.PORTA_DATACENTER_TCP);
            System.out.println("[CLOUD] Aguardando conexoes...");
            System.out.println("=================================================");

            while (true) {
                Socket socket = serverSocket.accept();
                new Thread(() -> processarConexao(socket)).start();
            }
        }
    }

    private static void registrarNoDiscovery() {
        try (Socket socket = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_LOCALIZACAO); ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream()); ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {
            out.writeObject("REGISTRAR_CHAVE:CLOUD:" + rsa.getChavePublicaBase64());
            in.readObject();
            System.out.println("[INIT] Registrado no Discovery.");
        } catch (Exception e) {
            System.out.println("[INIT] Falha registro: " + e.getMessage());
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
                System.out.println("[INIT] Chave JWT Sincronizada.");
            }
        } catch (Exception e) {
            System.out.println("[INIT] Falha sync JWT: " + e.getMessage());
        }
    }

    private static void processarConexao(Socket socket) {
        try (ObjectInputStream in = new ObjectInputStream(socket.getInputStream()); ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream())) {

            Object obj = in.readObject();
            if (obj instanceof Mensagem msg) {
                String origem = msg.getIdOrigem();
                System.out.print("[TCP] Msg de " + origem + "... ");

                if (JwtService.validarToken(msg.getTokenJwt()) == null) {
                    System.out.println("TOKEN INVALIDO/EXPIRADO.");
                    return;
                }

                byte[] chaveAesBytes = rsa.decifrarChaveSimetrica(msg.getChaveSimetricaCifrada());
                ImplAES aes = new ImplAES(chaveAesBytes);
                String conteudo = aes.decifrar(msg.getConteudoCifrado());

                byte[] hmacCalculado = Util.calcularHmacSha256(chaveAesBytes, conteudo.getBytes());
                if (!java.security.MessageDigest.isEqual(hmacCalculado, Base64.getDecoder().decode(msg.getHmac()))) {
                    System.out.println("FALHA DE INTEGRIDADE.");
                    return;
                }
                System.out.print("Segura. ");

                if (msg.getTipo() == Constantes.TIPO_DADOS_SENSOR) {
                    DadosSensor dados = DadosSensor.fromString(conteudo);
                    bancoDados.add(dados);
                    System.out.println("-> [DB] Salvo: " + dados.getIdDispositivo());

                    // CORREÇÃO 3: Enviar confirmação para a Borda não travar
                    out.writeObject("RECEBIDO");

                } else if (msg.getTipo() == Constantes.TIPO_RELATORIO_REQ) {
                    System.out.println("-> [API] Req Cliente.");
                    String resposta = processarMenuCliente(conteudo);
                    String respCifrada = aes.cifrar(resposta);
                    out.writeObject(respCifrada);
                }
            }
        } catch (Exception e) {
            System.out.println("[ERRO CONEXAO] " + e.getMessage());
        }
    }

    private static String processarMenuCliente(String comando) {
        StringBuilder sb = new StringBuilder();
        if (comando == null) {
            return "Erro";
        }

        switch (comando) {
            case "GET /relatorios" -> {
                sb.append("=== RELATORIOS GERAIS ===\n");
                sb.append("Total de Registros: ").append(bancoDados.size()).append("\n");
                double mediaTemp = bancoDados.stream().mapToDouble(DadosSensor::getTemperatura).average().orElse(0.0);
                sb.append("Temp Media: ").append(String.format("%.2f", mediaTemp)).append(" C\n");
                long ativos = bancoDados.stream().map(DadosSensor::getIdDispositivo).distinct().count();
                sb.append("Sensores Ativos: ").append(ativos).append("\n");
            }
            case "GET /alertas" -> {
                sb.append("=== ALERTAS ===\n");
                List<DadosSensor> criticos = bancoDados.stream()
                        .filter(d -> d.getTemperatura() > 40).collect(Collectors.toList());
                if (criticos.isEmpty()) {
                    sb.append("Sem alertas.\n");
                } else {
                    criticos.forEach(d -> sb.append("[ALERTA] ").append(d.getIdDispositivo()).append(" Temp: ").append(d.getTemperatura()).append("\n"));
                }
            }
            case "GET /previsoes" -> {
                sb.append("=== PREVISOES ===\n");
                double co2 = bancoDados.stream().mapToDouble(DadosSensor::getCo2).average().orElse(0.0);
                if (co2 > 800) {
                    sb.append("Qualidade do ar PESSIMA prevista para tarde.\n");
                } else {
                    sb.append("Qualidade do ar estavel.\n");
                }
            }
            default ->
                sb.append("Comando invalido.");
        }
        return sb.toString();
    }

    private static String[] buscarServico(String nome) throws Exception {
        try (Socket s = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_LOCALIZACAO); ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream()); ObjectInputStream in = new ObjectInputStream(s.getInputStream())) {
            out.writeObject("BUSCAR:" + nome);
            String resp = (String) in.readObject();
            return resp.split("\\|");
        }
    }
}
