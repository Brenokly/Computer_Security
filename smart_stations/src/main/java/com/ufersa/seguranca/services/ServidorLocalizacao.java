package com.ufersa.seguranca.services;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ConcurrentHashMap;

import com.ufersa.seguranca.util.Constantes;

public class ServidorLocalizacao {

    private static final ConcurrentHashMap<String, String> registroServicos = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, String> chavesPublicas = new ConcurrentHashMap<>();

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(Constantes.PORTA_LOCALIZACAO)) {
            System.out.println("=== SERVIDOR DE LOCALIZACAO (DNS/PKI) ===");

            // Apontando para Firewalls/DMZ
            registroServicos.put("AUTH", Constantes.IP_LOCAL + ":" + Constantes.PORTA_AUTH);

            // Sensores devem bater no Firewall 1 (UDP)
            registroServicos.put("BORDA", Constantes.IP_LOCAL + ":" + Constantes.PORTA_FIREWALL_1_UDP);

            // Clientes devem bater no Firewall 1 (TCP)
            registroServicos.put("CLOUD", Constantes.IP_LOCAL + ":" + Constantes.PORTA_FIREWALL_1_TCP);

            // Borda deve bater no Firewall 2 (Proxy)
            registroServicos.put("PROXY", Constantes.IP_LOCAL + ":" + Constantes.PORTA_FIREWALL_2_PROXY);

            System.out.println("[DNS] Tabela de Roteamento Segura:");
            System.out.println(" -> AUTH:  " + registroServicos.get("AUTH"));
            System.out.println(" -> BORDA (via FW1): " + registroServicos.get("BORDA"));
            System.out.println(" -> CLOUD (via FW1): " + registroServicos.get("CLOUD"));
            System.out.println(" -> PROXY: " + registroServicos.get("PROXY"));

            while (true) {
                Socket socket = serverSocket.accept();
                new Thread(() -> processarRequisicao(socket)).start();
            }
        } catch (Exception e) {
            System.out.println("[ERRO CRITICO] Falha no servidor: " + e.getMessage());
        }
    }

    private static void processarRequisicao(Socket socket) {
        try (ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream()); ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            String requisicao = (String) in.readObject();
            String[] partes = requisicao.split(":");
            String comando = partes[0];

            if ("REGISTRAR_CHAVE".equals(comando)) {
                String servico = partes[1];
                String chavePublica = partes[2];
                chavesPublicas.put(servico, chavePublica);
                System.out.println("[PKI] Chave recebida de: " + servico);
                out.writeObject("OK");

            } else if ("BUSCAR".equals(comando)) {
                String servico = partes[1];

                String endereco = registroServicos.get(servico);
                String chave = chavesPublicas.get(servico);

                if (endereco != null && chave != null) {
                    out.writeObject(endereco + "|" + chave);
                } else {
                    out.writeObject("ERRO: Servico nao encontrado");
                }
            }
        } catch (Exception e) {
            System.out.println("[ERRO] Falha na requisicao: " + e.getMessage());
        }
    }
}
