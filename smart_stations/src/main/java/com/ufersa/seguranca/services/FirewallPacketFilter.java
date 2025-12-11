package com.ufersa.seguranca.services;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.ufersa.seguranca.util.Constantes;

public class FirewallPacketFilter {

    private static final List<String> blacklist = Collections.synchronizedList(new ArrayList<>());
    private static final int PORTA_HONEYPOT = 9000;

    public static void main(String[] args) {
        System.out.println("=== FIREWALL 1 (PACKET FILTER - UDP/TCP + HONEYPOT) ===");
        System.out.println("[FW-FILTER] Protegendo UDP (Sensores): " + Constantes.PORTA_FIREWALL_1_UDP);
        System.out.println("[FW-FILTER] Protegendo TCP (Clientes): " + Constantes.PORTA_FIREWALL_1_TCP);
        System.out.println("[HONEYPOT]  Isca Ativa: " + PORTA_HONEYPOT);

        new Thread(FirewallPacketFilter::iniciarListenerBloqueio).start();
        new Thread(FirewallPacketFilter::iniciarHoneypot).start();
        new Thread(FirewallPacketFilter::iniciarFiltragemTCP).start();
        iniciarFiltragemUDP();
    }

    private static void iniciarFiltragemUDP() {
        try (DatagramSocket socketEntrada = new DatagramSocket(Constantes.PORTA_FIREWALL_1_UDP); DatagramSocket socketSaida = new DatagramSocket()) {

            byte[] buffer = new byte[65535];

            while (true) {
                DatagramPacket pacoteRecebido = new DatagramPacket(buffer, buffer.length);
                socketEntrada.receive(pacoteRecebido);

                String ipOrigem = pacoteRecebido.getAddress().getHostAddress();
                int portaOrigem = pacoteRecebido.getPort();

                if (blacklist.contains(ipOrigem)) {
                    System.out.print("[FW-FILTER-UDP] Bloqueado: " + ipOrigem + " (Blacklist)\r");
                    continue;
                }

                System.out.println("[FW-FILTER-UDP] Pacote Legitimo de " + ipOrigem + ":" + portaOrigem + " -> Encaminhando Borda");

                InetAddress ipBorda = InetAddress.getByName(Constantes.IP_LOCAL);
                DatagramPacket pacoteEncaminhado = new DatagramPacket(
                        pacoteRecebido.getData(),
                        pacoteRecebido.getLength(),
                        ipBorda,
                        Constantes.PORTA_BORDA_UDP
                );
                socketSaida.send(pacoteEncaminhado);
            }
        } catch (Exception e) {
            System.out.println("[FW-FILTER] Erro UDP fatal: " + e.getMessage());
        }
    }

    private static void iniciarFiltragemTCP() {
        try (ServerSocket serverSocket = new ServerSocket(Constantes.PORTA_FIREWALL_1_TCP)) {
            while (true) {
                Socket socketCliente = serverSocket.accept();
                new Thread(() -> processarConexaoTCP(socketCliente)).start();
            }
        } catch (IOException e) {
            System.out.println("[FW-FILTER] Erro TCP fatal: " + e.getMessage());
        }
    }

    private static void processarConexaoTCP(Socket socketCliente) {
        String ipOrigem = socketCliente.getInetAddress().getHostAddress();

        if (blacklist.contains(ipOrigem)) {
            System.out.println("[FW-FILTER-TCP] CONEXAO RECUSADA: " + ipOrigem + " esta na Blacklist!");
            try {
                socketCliente.close();
            } catch (IOException e) {
            }
            return;
        }

        System.out.println("[FW-FILTER-TCP] Conexao aceita de " + ipOrigem + " -> Repassando ao Proxy");

        try (Socket socketProxy = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_FIREWALL_2_PROXY)) {
            ObjectOutputStream outProxy = new ObjectOutputStream(socketProxy.getOutputStream());
            outProxy.flush();
            ObjectInputStream inProxy = new ObjectInputStream(socketProxy.getInputStream());

            ObjectOutputStream outCliente = new ObjectOutputStream(socketCliente.getOutputStream());
            outCliente.flush();
            ObjectInputStream inCliente = new ObjectInputStream(socketCliente.getInputStream());

            Object msgCliente = inCliente.readObject();

            outProxy.writeObject(msgCliente);
            outProxy.flush();

            Object msgResposta = inProxy.readObject();

            outCliente.writeObject(msgResposta);
            outCliente.flush();

            System.out.println("[FW-FILTER-TCP] Ciclo concluido para " + ipOrigem);

        } catch (Exception e) {
            System.out.println("[FW-FILTER-TCP] Erro na ponte: " + e.getMessage());
        } finally {
            try {
                socketCliente.close();
            } catch (IOException e) {
            }
        }
    }

    private static void iniciarHoneypot() {
        try (DatagramSocket socketIsca = new DatagramSocket(PORTA_HONEYPOT)) {
            byte[] buf = new byte[1024];
            while (true) {
                DatagramPacket p = new DatagramPacket(buf, buf.length);
                socketIsca.receive(p);

                String ipInvasor = p.getAddress().getHostAddress();
                System.out.println("\n[HONEYPOT] !!! ARMADILHA ACIONADA !!!");
                System.out.println("[HONEYPOT] IP Curioso detectado: " + ipInvasor);

                if (!blacklist.contains(ipInvasor)) {
                    blacklist.add(ipInvasor);
                    System.out.println("[HONEYPOT] Acao: IP adicionado a Blacklist IMEDIATAMENTE.");
                    enviarAlertaIDS("HONEYPOT_DISPARADO|" + ipInvasor + "|Port Scan na porta " + PORTA_HONEYPOT);
                }
            }
        } catch (Exception e) {
            System.out.println("[HONEYPOT] Erro fatal: " + e.getMessage());
        }
    }

    private static void iniciarListenerBloqueio() {
        try (ServerSocket server = new ServerSocket(Constantes.PORTA_IDS_CMD_BORDA + 10)) {
            while (true) {
                Socket s = server.accept();
                try (ObjectInputStream in = new ObjectInputStream(s.getInputStream())) {
                    String cmd = (String) in.readObject();
                    if (cmd.startsWith("BLOQUEAR:")) {
                        String ip = cmd.split(":")[1];
                        if (!blacklist.contains(ip)) {
                            blacklist.add(ip);
                            System.out.println("[FW-FILTER] COMANDO IDS: IP " + ip + " bloqueado.");
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.out.println("[FW-FILTER] Erro Listener Bloqueio: " + e.getMessage());
        }
    }

    private static void enviarAlertaIDS(String msg) {
        try (Socket s = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_IDS); java.io.ObjectOutputStream out = new java.io.ObjectOutputStream(s.getOutputStream())) {
            out.writeObject("[FIREWALL-FILTER] " + msg);
        } catch (Exception e) {
        }
    }
}
