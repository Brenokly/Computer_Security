package com.ufersa.seguranca.services;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ConcurrentHashMap;

import com.ufersa.seguranca.util.Constantes;

/**
 * SERVIDOR DE LOCALIZAÇÃO
 * * Responsabilidade: Atua como um diretório central para a arquitetura distribuída.
 * Segurança:
 * 1. Armazena e distribui os endereços IP/Porta dos serviços (Auth, Borda, Cloud).
 * 2. Atua como uma PKI (Public Key Infrastructure) simplificada, distribuindo
 * as Chaves Públicas RSA dos componentes para permitir a Criptografia Híbrida.
 */

public class ServidorLocalizacao {

    private static final ConcurrentHashMap<String, String> registroServicos = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, String> chavesPublicas = new ConcurrentHashMap<>();

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(Constantes.PORTA_LOCALIZACAO)) {
            System.out.println("=================================================");
            System.out.println("[LOCALIZACAO] Servidor rodando na porta " + Constantes.PORTA_LOCALIZACAO);

            // Pré-registro das portas conhecidas (Simulação)
            registroServicos.put("AUTH", Constantes.IP_LOCAL + ":" + Constantes.PORTA_AUTH);
            registroServicos.put("BORDA", Constantes.IP_LOCAL + ":" + Constantes.PORTA_BORDA_UDP);
            registroServicos.put("CLOUD", Constantes.IP_LOCAL + ":" + Constantes.PORTA_DATACENTER_TCP);

            System.out.println("[LOCALIZACAO] Tabela de Endereços Inicializada:");
            System.out.println(" -> AUTH:  " + registroServicos.get("AUTH"));
            System.out.println(" -> BORDA: " + registroServicos.get("BORDA"));
            System.out.println(" -> CLOUD: " + registroServicos.get("CLOUD"));
            System.out.println("=================================================");

            while (true) {
                Socket socket = serverSocket.accept();
                // Log de nova conexão TCP (quem está batendo na porta)
                System.out.println("[CONEXAO] Novo cliente conectado: " + socket.getInetAddress());
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

                // Log importante: mostra que a infraestrutura de chaves está sendo montada
                System.out.println("[REGISTRO] Chave Pública recebida e armazenada para: " + servico);

                out.writeObject("OK");

            } else if ("BUSCAR".equals(comando)) {
                String servico = partes[1];

                // Log de operação: mostra o fluxo de descoberta
                System.out.print("[BUSCA] Solicitacao de endereco/chave para: '" + servico + "'... ");

                String endereco = registroServicos.get(servico);
                String chave = chavesPublicas.get(servico);

                if (endereco != null && chave != null) {
                    out.writeObject(endereco + "|" + chave);
                    System.out.println("ENCONTRADO. Enviando dados.");
                } else {
                    out.writeObject("ERRO: Servico nao encontrado");
                    System.out.println("FALHA. Servico ou Chave nao disponivel.");
                    if (endereco == null) {
                        System.out.println("   (Motivo: Endereco nao registrado)");
                    }
                    if (chave == null) {
                        System.out.println("   (Motivo: Chave Publica nao registrada)");
                    }
                }
            }
        } catch (Exception e) {
            System.out.println("[ERRO] Falha ao processar requisicao: " + e.getMessage());
        }
    }
}
