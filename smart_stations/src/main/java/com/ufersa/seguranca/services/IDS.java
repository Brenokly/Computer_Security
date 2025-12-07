package com.ufersa.seguranca.services;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.ConcurrentHashMap;

import com.ufersa.seguranca.util.Constantes;

public class IDS {

    // Estrutura para armazenar detalhes de cada evento para o relatório final
    private static class EventoSeguranca {

        String tipo;
        String origem;
        String conteudo;
        long timestamp;

        public EventoSeguranca(String tipo, String origem, String conteudo) {
            this.tipo = tipo;
            this.origem = origem;
            this.conteudo = conteudo;
            this.timestamp = System.currentTimeMillis();
        }
    }

    private static final List<EventoSeguranca> baseDeDadosEventos = new ArrayList<>();
    private static final List<String> ipsBloqueados = new ArrayList<>();
    private static final Map<String, Integer> contadorAtaquesPorIp = new ConcurrentHashMap<>();

    public static void main(String[] args) {
        System.out.println("=== IDS (SISTEMA DE DETECCAO DE INTRUSAO) ===");
        System.out.println("[IDS] Monitorando rede na porta " + Constantes.PORTA_IDS);
        System.out.println("[IDS] Digite 'RELATORIO' a qualquer momento para ver o consolidado.");

        // Thread para escutar alertas dos Firewalls (Porta 8000)
        new Thread(IDS::iniciarServidorLogs).start();

        // Thread para interface com o Admin (Console) para gerar o relatório final
        new Thread(IDS::menuInterativo).start();
    }

    private static void menuInterativo() {
        try (Scanner scanner = new Scanner(System.in)) {
            while (true) {
                String comando = scanner.nextLine();
                if (comando.equalsIgnoreCase("RELATORIO")) {
                    gerarRelatorioFinal();
                }
            }
        }
    }

    private static void iniciarServidorLogs() {
        try (ServerSocket server = new ServerSocket(Constantes.PORTA_IDS)) {
            while (true) {
                Socket socket = server.accept();
                new Thread(() -> processarAlerta(socket)).start();
            }
        } catch (Exception e) {
            System.out.println("[IDS] Erro no servidor de logs: " + e.getMessage());
        }
    }

    private static void processarAlerta(Socket socket) {
        try (ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {
            String mensagemBruta = (String) in.readObject();

            // Formato esperado: TIPO|ORIGEM|CONTEUDO
            String[] parts = mensagemBruta.split("\\|");
            String tipo = parts.length > 0 ? parts[0] : "DESCONHECIDO";
            String origem = parts.length > 1 ? parts[1] : "N/A";
            String detalhe = parts.length > 2 ? parts[2] : "Sem detalhes";

            // Registra em memória para o relatório
            synchronized (baseDeDadosEventos) {
                baseDeDadosEventos.add(new EventoSeguranca(tipo, origem, detalhe));
            }
            contadorAtaquesPorIp.merge(origem, 1, Integer::sum);

            // Log em tempo real
            System.out.println("[ALERTA EM TEMPO REAL] Tipo: " + tipo + " | Origem: " + origem);

            // Lógica de Bloqueio Automático
            if (tipo.contains("ANOMALIA") || tipo.contains("ATAQUE")) {
                bloquearNoFirewall(origem);
            }

        } catch (Exception e) {
            System.out.println("[IDS] Erro ao processar pacote: " + e.getMessage());
        }
    }

    private static void bloquearNoFirewall(String ipAlvo) {
        if (ipsBloqueados.contains(ipAlvo)) {
            return;
        }

        System.out.println("[IDS] >>> ATIVANDO RESPOSTA ATIVA: Bloqueando " + ipAlvo);
        try (Socket socket = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_IDS_CMD_BORDA); ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream())) {

            out.writeObject("BLOQUEAR:" + ipAlvo);
            ipsBloqueados.add(ipAlvo);
            System.out.println("[IDS] Comando de bloqueio enviado para Borda/Firewall.");
        } catch (Exception e) {
            System.out.println("[IDS] Falha ao enviar comando de bloqueio: " + e.getMessage());
        }
    }

    // Cumpre o requisito de "Mostrar relatórios gerados"
    private static void gerarRelatorioFinal() {
        System.out.println("\n============================================================");
        System.out.println("          RELATORIO CONSOLIDADO DE SEGURANCA (IDS)          ");
        System.out.println("============================================================");
        System.out.println("Total de Eventos Registrados: " + baseDeDadosEventos.size());
        System.out.println("Total de IPs Bloqueados: " + ipsBloqueados.size());
        System.out.println("------------------------------------------------------------");

        System.out.println("\n[1] LISTA DE IPS BLOQUEADOS (BLACKLIST):");
        if (ipsBloqueados.isEmpty()) {
            System.out.println("   (Nenhum bloqueio realizado)");
        }
        for (String ip : ipsBloqueados) {
            System.out.println("   -> " + ip + " (Bloqueado por atividade maliciosa)");
        }

        System.out.println("\n[2] TOP OFENSORES (Origem dos Ataques):");
        contadorAtaquesPorIp.forEach((ip, count) -> {
            System.out.println("   -> IP/ID: " + ip + " | Tentativas: " + count);
        });

        System.out.println("\n[3] DETALHAMENTO DOS EVENTOS (Últimos 10):");
        int inicio = Math.max(0, baseDeDadosEventos.size() - 10);
        for (int i = inicio; i < baseDeDadosEventos.size(); i++) {
            EventoSeguranca e = baseDeDadosEventos.get(i);
            System.out.printf("   [%tT] Tipo: %-20s | Origem: %-15s | Info: %s%n",
                    e.timestamp, e.tipo, e.origem, e.conteudo);
        }
        System.out.println("============================================================\n");
    }
}
