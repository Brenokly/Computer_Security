package com.ufersa.seguranca.client;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

public class SensorCurioso {

    public static void main(String[] args) throws Exception {
        System.out.println("=== ATACANTE DE PORT SCAN (SCANNER) ===");
        System.out.println("Tentando descobrir portas abertas no Firewall...");

        String payload = "Ola, tem alguem ai?";
        byte[] dados = payload.getBytes();
        InetAddress ipLocal = InetAddress.getByName("127.0.0.1");

        // Tenta porta 9000 (A armadilha)
        try (DatagramSocket s = new DatagramSocket()) {
            System.out.println("-> Testando porta 9000...");
            DatagramPacket p = new DatagramPacket(dados, dados.length, ipLocal, 9000);
            s.send(p);
            System.out.println("-> Pacote enviado para a isca.");
        }

        System.out.println("Agora tentando enviar dados normais na porta 6000...");
        try (DatagramSocket s = new DatagramSocket()) {
            DatagramPacket p = new DatagramPacket(dados, dados.length, ipLocal, 6000);
            s.send(p);
            System.out.println("-> Tentativa na porta real enviada (Deve ser bloqueada).");
        }
    }
}
