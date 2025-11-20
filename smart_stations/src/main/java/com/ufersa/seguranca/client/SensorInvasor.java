package com.ufersa.seguranca.client;

public class SensorInvasor {

    public static void main(String[] args) {
        System.out.println("=== TENTATIVA DE ACESSO NAO AUTORIZADO ===");
        new Dispositivo().iniciarCiclo("SENSOR_INVASOR", "sensor01", "senhaErrada");
    }
}
