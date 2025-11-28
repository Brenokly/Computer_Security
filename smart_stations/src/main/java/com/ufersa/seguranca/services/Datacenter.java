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
import java.util.stream.Collectors;

import com.ufersa.seguranca.model.DadosSensor;
import com.ufersa.seguranca.model.Mensagem;
import com.ufersa.seguranca.util.Constantes;
import com.ufersa.seguranca.util.ImplAES;
import com.ufersa.seguranca.util.ImplRSA;
import com.ufersa.seguranca.util.JwtService;
import com.ufersa.seguranca.util.Util;

/**
 * DATACENTER / CLOUD (Storage & Analytics)
 * * Responsabilidade: Armazenamento centralizado e processamento de relatórios.
 * Segurança:
 * 1. Validação: Rejeita conexões sem Token JWT válido ou com falha de integridade (HMAC).
 * 2. Conexão Persistente: Gerencia threads dedicadas para conexões TCP de longa
 * duração.
 * 3. Decriptação Final: Ponto final da criptografia híbrida, onde o
 * dado é exposto apenas na memória.
 * 4. Analytics: Gera os 5 relatórios estatísticos exigidos baseados no banco em memória.
 */
public class Datacenter {

    private static ImplRSA rsa;
    private static final List<DadosSensor> bancoDados = Collections.synchronizedList(new ArrayList<>());

    public static void main(String[] args) throws Exception {
        System.out.println("=================================================");
        System.out.println("[CLOUD] Inicializando Datacenter (Persistente)...");
        rsa = new ImplRSA();
        registrarNoDiscovery();
        sincronizarChaveJwt("CLOUD");

        try (ServerSocket serverSocket = new ServerSocket(Constantes.PORTA_DATACENTER_TCP)) {
            System.out.println("[CLOUD] Ouvindo na porta " + Constantes.PORTA_DATACENTER_TCP);
            while (true) {
                Socket socket = serverSocket.accept();
                new Thread(() -> processarConexaoPersistente(socket)).start();
            }
        }
    }

    private static void processarConexaoPersistente(Socket socket) {
        String clienteIp = socket.getInetAddress().toString();
        System.out.println("[TCP] Nova conexao persistente: " + clienteIp);

        try (ObjectInputStream in = new ObjectInputStream(socket.getInputStream()); ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream())) {

            while (true) {
                try {
                    Object obj = in.readObject();

                    if (obj instanceof Mensagem msg) {
                        tratarMensagem(msg, out);
                    }
                } catch (EOFException e) {
                    System.out.println("[TCP] Cliente desconectou: " + clienteIp);
                    break;
                } catch (Exception e) {
                    System.out.println("[TCP] Erro/Queda com " + clienteIp + ": " + e.getMessage());
                    break;
                }
            }
        } catch (Exception e) {
            System.out.println("[ERRO FATAL CONEXAO] " + e.getMessage());
        }
    }

    private static void tratarMensagem(Mensagem msg, ObjectOutputStream out) throws Exception {
        // Validação de Token
        if (JwtService.validarToken(msg.getTokenJwt()) == null) {
            System.out.println("   -> Token Invalido.");
            return;
        }

        // Decifra Híbrido
        byte[] chaveAesBytes = rsa.decifrarChaveSimetrica(msg.getChaveSimetricaCifrada());
        ImplAES aes = new ImplAES(chaveAesBytes);
        String conteudo = aes.decifrar(msg.getConteudoCifrado());

        // Valida HMAC
        byte[] hmacCalculado = Util.calcularHmacSha256(chaveAesBytes, conteudo.getBytes());
        if (!java.security.MessageDigest.isEqual(hmacCalculado, Base64.getDecoder().decode(msg.getHmac()))) {
            System.out.println("   -> Falha Integridade.");
            return;
        }

        // Lógica de Negócio
        if (msg.getTipo() == Constantes.TIPO_DADOS_SENSOR) {
            DadosSensor dados = DadosSensor.fromString(conteudo);
            bancoDados.add(dados);
            System.out.println("   -> [DB] Salvo: " + dados.getIdDispositivo());

        } else if (msg.getTipo() == Constantes.TIPO_RELATORIO_REQ) {
            System.out.println("   -> [API] Req: " + conteudo);
            String resposta = processarMenuCliente(conteudo);
            String respCifrada = aes.cifrar(resposta);
            out.writeObject(respCifrada);
            out.flush();
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

    private static String processarMenuCliente(String comando) {
        StringBuilder sb = new StringBuilder();
        if (comando == null) {
            return "Erro";
        }

        switch (comando) {
            case "GET /relatorios" -> {
                sb.append("=== 5 RELATORIOS ESTATISTICOS ===\n");

                // 1. Volume de Dados Armazenados
                sb.append("1. Volume Total de Dados: ")
                        .append(bancoDados.size()).append(" registros.\n");

                // 2. Monitoramento Térmico (Média)
                double mediaTemp = bancoDados.stream()
                        .mapToDouble(DadosSensor::getTemperatura).average().orElse(0.0);
                sb.append("2. Temperatura Media da Cidade: ")
                        .append(String.format("%.2f", mediaTemp)).append(" C\n");

                // 3. Qualidade do Ar (Média de CO2)
                double mediaCo2 = bancoDados.stream()
                        .mapToDouble(DadosSensor::getCo2).average().orElse(0.0);
                sb.append("3. Concentracao Media de CO2: ")
                        .append(String.format("%.2f", mediaCo2)).append(" ppm\n");

                // 4. Monitoramento de Umidade (Média)
                // (Adicionando umidade que não estava sendo usada nos relatórios antes)
                double mediaUmidade = bancoDados.stream()
                        .mapToDouble(DadosSensor::getUmidade).average().orElse(0.0);
                sb.append("4. Umidade Relativa do Ar: ")
                        .append(String.format("%.2f", mediaUmidade)).append(" %\n");

                // Saúde da Rede (Sensores Ativos)
                long ativos = bancoDados.stream()
                        .map(DadosSensor::getIdDispositivo).distinct().count();
                sb.append("5. Sensores Ativos na Rede: ")
                        .append(ativos).append(" dispositivos.\n");
            }
            case "GET /alertas" -> {
                sb.append("=== ALERTAS CRITICOS (Ultimos Eventos) ===\n");
                List<DadosSensor> criticos = bancoDados.stream()
                        .filter(d -> d.getTemperatura() > 40 || d.getCo2() > 1000)
                        .collect(Collectors.toList());

                if (criticos.isEmpty()) {
                    sb.append("Nenhum alerta critico registrado.\n");
                } else {
                    // Mostra apenas os últimos 5 alertas para não enxer a tela
                    int inicio = Math.max(0, criticos.size() - 5);
                    for (int i = inicio; i < criticos.size(); i++) {
                        DadosSensor d = criticos.get(i);
                        sb.append("[ALERTA] ").append(d.getIdDispositivo())
                                .append(" | Temp: ").append(String.format("%.1f", d.getTemperatura()))
                                .append(" | CO2: ").append(String.format("%.1f", d.getCo2())).append("\n");
                    }
                }
            }
            case "GET /previsoes" -> {
                sb.append("=== ANALISE PREDITIVA (IA) ===\n");
                double tendenciaPm25 = bancoDados.stream()
                        .mapToDouble(DadosSensor::getPm25).average().orElse(0.0);

                sb.append("Base de analise: ").append(bancoDados.size()).append(" amostras.\n");

                if (tendenciaPm25 > 35) {
                    sb.append("-> QUALIDADE DO AR: Critica. Risco de chuva acida nas proximas 6h.\n");
                } else {
                    sb.append("-> QUALIDADE DO AR: Estavel. Sem riscos imediatos.\n");
                }

                // Previsão extra baseada na umidade
                double tendenciaUmidade = bancoDados.stream()
                        .mapToDouble(DadosSensor::getUmidade).average().orElse(0.0);
                if (tendenciaUmidade < 30) {
                    sb.append("-> ALERTA DE SECA: Umidade baixa. Risco de incendios urbanos elevado.\n");
                } else {
                    sb.append("-> CLIMA: Umidade dentro dos padroes de conforto.\n");
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
