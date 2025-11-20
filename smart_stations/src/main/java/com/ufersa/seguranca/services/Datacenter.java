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
import com.ufersa.seguranca.util.Util;

public class Datacenter {

    private static ImplRSA rsa;
    // Banco de dados em memória thread-safe
    private static final List<DadosSensor> bancoDados = Collections.synchronizedList(new ArrayList<>());

    public static void main(String[] args) throws Exception {
        System.out.println("=================================================");
        System.out.println("[CLOUD] Inicializando Datacenter...");

        System.out.print("[INIT] Gerando par de chaves RSA... ");
        rsa = new ImplRSA();
        System.out.println("OK.");

        registrarNoDiscovery();

        try (ServerSocket serverSocket = new ServerSocket(Constantes.PORTA_DATACENTER_TCP)) {
            System.out.println("[CLOUD] Servidor rodando na porta TCP " + Constantes.PORTA_DATACENTER_TCP);
            System.out.println("[CLOUD] Aguardando dados da Borda e requisicoes de Clientes...");
            System.out.println("=================================================");

            while (true) {
                Socket socket = serverSocket.accept();
                new Thread(() -> processarConexao(socket)).start();
            }
        }
    }

    private static void registrarNoDiscovery() {
        System.out.print("[INIT] Registrando chave publica no Discovery... ");
        try (Socket socket = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_LOCALIZACAO); ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream()); ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            out.writeObject("REGISTRAR_CHAVE:CLOUD:" + rsa.getChavePublicaBase64());
            in.readObject();
            System.out.println("OK.");
        } catch (Exception e) {
            System.out.println("FALHA (" + e.getMessage() + ")");
        }
    }

    private static void processarConexao(Socket socket) {
        try (ObjectInputStream in = new ObjectInputStream(socket.getInputStream()); ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream())) {

            Object obj = in.readObject();
            if (obj instanceof Mensagem msg) {
                String origem = msg.getIdOrigem();
                System.out.print("[TCP] Msg recebida de " + origem + " | Decifrando... ");

                // 1. Decifrar Chave Simétrica (Híbrido)
                byte[] chaveAesBytes = rsa.decifrarChaveSimetrica(msg.getChaveSimetricaCifrada());
                ImplAES aes = new ImplAES(chaveAesBytes);

                // 2. Decifrar Conteúdo
                String conteudo = aes.decifrar(msg.getConteudoCifrado());

                // 3. Validar Integridade (HMAC) - OBRIGATÓRIO
                byte[] hmacCalculado = Util.calcularHmacSha256(chaveAesBytes, conteudo.getBytes());
                byte[] hmacRecebido = Base64.getDecoder().decode(msg.getHmac());

                if (!java.security.MessageDigest.isEqual(hmacCalculado, hmacRecebido)) {
                    System.out.println("FALHA DE INTEGRIDADE (HMAC invalido). Conexão encerrada.");
                    return;
                }
                System.out.println("Segurança OK.");

                // 4. Processar Tipo de Mensagem
                if (msg.getTipo() == Constantes.TIPO_DADOS_SENSOR) {
                    DadosSensor dados = DadosSensor.fromString(conteudo);
                    bancoDados.add(dados);
                    System.out.println("   -> [DB] Dado persistido. Sensor: " + dados.getIdDispositivo() + " | Temp: " + dados.getTemperatura());

                } else if (msg.getTipo() == Constantes.TIPO_RELATORIO_REQ) {
                    System.out.println("   -> [API] Processando solicitacao: " + conteudo);
                    String resposta = processarMenuCliente(conteudo);

                    // Responder cifrado
                    String respCifrada = aes.cifrar(resposta);
                    out.writeObject(respCifrada);
                    System.out.println("   -> [API] Resposta enviada ao Cliente.");
                }
            }
        } catch (Exception e) {
            System.out.println("[ERRO] " + e.getMessage());
        }
    }

    private static String processarMenuCliente(String comando) {
        StringBuilder sb = new StringBuilder();

        if (null == comando) {
            sb.append("Comando nao reconhecido.");
        } else {
            switch (comando) {
                case "GET /relatorios" -> {
                    sb.append("=== RELATORIOS ESTATISTICOS (5 RELATORIOS) ===\n");

                    // Relatório 1: Volume de Dados
                    sb.append("1. Volume de Dados:\n");
                    sb.append("   - Total de Registros: ").append(bancoDados.size()).append("\n");

                    // Relatório 2: Média Térmica
                    double mediaTemp = bancoDados.stream().mapToDouble(DadosSensor::getTemperatura).average().orElse(0.0);
                    sb.append("2. Monitoramento Termico:\n");
                    sb.append("   - Temperatura Media Global: ").append(String.format("%.2f", mediaTemp)).append(" C\n");

                    // Relatório 3: Poluição
                    double mediaCo2 = bancoDados.stream().mapToDouble(DadosSensor::getCo2).average().orElse(0.0);
                    sb.append("3. Controle de Poluicao:\n");
                    sb.append("   - CO2 Medio: ").append(String.format("%.2f", mediaCo2)).append(" ppm\n");

                    // Relatório 4: Ruído Urbano
                    long ruidoso = bancoDados.stream().filter(d -> d.getRuido() > 80).count();
                    sb.append("4. Poluicao Sonora:\n");
                    sb.append("   - Ocorrencias acima de 80dB: ").append(ruidoso).append("\n");

                    // Relatório 5: Status da Rede
                    long ativos = bancoDados.stream().map(DadosSensor::getIdDispositivo).distinct().count();
                    sb.append("5. Rede de Sensores:\n");
                    sb.append("   - Dispositivos Ativos: ").append(ativos).append("\n");
                }
                case "GET /alertas" -> {
                    sb.append("=== ALERTAS CRITICOS (Tempo Real) ===\n");
                    List<DadosSensor> criticos = bancoDados.stream()
                            .filter(d -> d.getTemperatura() > 40 || d.getCo2() > 1000)
                            .collect(Collectors.toList());
                    if (criticos.isEmpty()) {
                        sb.append("Nenhum alerta critico registrado no momento.\n");
                    } else {
                        for (DadosSensor d : criticos) {
                            sb.append("[ALERTA] ID: ").append(d.getIdDispositivo())
                                    .append(" | Temp: ").append(d.getTemperatura())
                                    .append(" | CO2: ").append(d.getCo2()).append("\n");
                        }
                    }
                }
                case "GET /previsoes" -> {
                    sb.append("=== PREVISOES AMBIENTAIS (IA) ===\n");
                    double tendenciaPm25 = bancoDados.stream().mapToDouble(DadosSensor::getPm25).average().orElse(0.0);
                    double tendenciaUv = bancoDados.stream().mapToDouble(DadosSensor::getUv).average().orElse(0.0);

                    sb.append("Analise baseada em ").append(bancoDados.size()).append(" amostras:\n");

                    if (tendenciaPm25 > 30) {
                        sb.append("-> AR: Alta probabilidade de chuva acida ou poluicao severa nas proximas 4h.\n");
                    } else {
                        sb.append("-> AR: Qualidade do ar deve permanecer estavel.\n");
                    }

                    if (tendenciaUv > 6) {
                        sb.append("-> SAUDE: Risco de radiacao UV alto para amanha. Recomenda-se alerta a populacao.\n");
                    } else {
                        sb.append("-> SAUDE: Niveis de radiacao seguros.\n");
                    }
                }
                default ->
                    sb.append("Comando nao reconhecido.");
            }
        }

        return sb.toString();
    }
}
