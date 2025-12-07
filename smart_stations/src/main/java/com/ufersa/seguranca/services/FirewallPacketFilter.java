package com.ufersa.seguranca.services;

import java.io.IOException;
import java.io.ObjectInputStream;
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

    public static void main(String[] args) {
        System.out.println("=== FIREWALL 1 (PACKET FILTER) INICIADO ===");
        System.out.println("[FW-FILTER] Protegendo a DMZ na porta UDP " + Constantes.PORTA_FIREWALL_1_UDP);

        new Thread(FirewallPacketFilter::iniciarListenerBloqueio).start();
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

                System.out.print("[FW-FILTER] Pacote de " + ipOrigem + ":" + portaOrigem + " | ");

                if (blacklist.contains(ipOrigem)) {
                    System.out.println("ACAO: BLOQUEADO (Blacklist IDS)");
                    enviarAlertaIDS("TENTATIVA_BLOQUEADA|" + ipOrigem);
                    continue;
                }

                System.out.println("ACAO: PERMITIDO -> Encaminhando para Borda (DMZ)");

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
            System.out.println("[FW-FILTER] Erro fatal: " + e.getMessage());
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
                        blacklist.add(ip);
                        System.out.println("[FW-FILTER] COMANDO RECEBIDO: IP " + ip + " adicionado a Blacklist.");
                    }
                }
            }
        } catch (IOException | ClassNotFoundException e) {
            System.out.println("[FW-FILTER] Erro no listener de bloqueio: " + e.getMessage());
        }
    }

    private static void enviarAlertaIDS(String msg) {
        try (Socket s = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_IDS); java.io.ObjectOutputStream out = new java.io.ObjectOutputStream(s.getOutputStream())) {
            out.writeObject("[FIREWALL-FILTER] " + msg);
        } catch (Exception e) {
            System.out.println("[FW-FILTER] Falha ao alertar IDS");
        }
    }
}
