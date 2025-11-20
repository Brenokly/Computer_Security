package com.ufersa.seguranca.model;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.ThreadLocalRandom;

public class DadosSensor implements Serializable {

    private final String idDispositivo;
    private String timestamp;
    private double co2;
    private double co;
    private double no2;
    private double so2;
    private double pm25;
    private double pm10;
    private double temperatura;
    private double umidade;
    private double ruido;
    private double uv;

    public DadosSensor(String idDispositivo) {
        this.idDispositivo = idDispositivo;
        this.timestamp = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        gerarDadosAleatorios();
    }

    private void gerarDadosAleatorios() {
        this.co2 = ThreadLocalRandom.current().nextDouble(350.0, 1200.0);
        this.co = ThreadLocalRandom.current().nextDouble(0.1, 15.0);
        this.no2 = ThreadLocalRandom.current().nextDouble(10.0, 60.0);
        this.so2 = ThreadLocalRandom.current().nextDouble(0.0, 25.0);
        this.pm25 = ThreadLocalRandom.current().nextDouble(5.0, 60.0);
        this.pm10 = ThreadLocalRandom.current().nextDouble(10.0, 100.0);
        this.temperatura = ThreadLocalRandom.current().nextDouble(18.0, 42.0);
        this.umidade = ThreadLocalRandom.current().nextDouble(25.0, 90.0);
        this.ruido = ThreadLocalRandom.current().nextDouble(40.0, 95.0);
        this.uv = ThreadLocalRandom.current().nextDouble(0.0, 12.0);
    }

    @Override
    public String toString() {
        return String.format("%s|%s|%.2f|%.2f|%.2f|%.2f|%.2f|%.2f|%.2f|%.2f|%.2f|%.2f",
                idDispositivo, timestamp, co2, co, no2, so2, pm25, pm10, temperatura, umidade, ruido, uv);
    }

    public static DadosSensor fromString(String linha) {
        String[] parts = linha.split("\\|");
        DadosSensor d = new DadosSensor(parts[0]);
        d.timestamp = parts[1];
        d.co2 = Double.parseDouble(parts[2].replace(",", "."));
        d.co = Double.parseDouble(parts[3].replace(",", "."));
        d.no2 = Double.parseDouble(parts[4].replace(",", "."));
        d.so2 = Double.parseDouble(parts[5].replace(",", "."));
        d.pm25 = Double.parseDouble(parts[6].replace(",", "."));
        d.pm10 = Double.parseDouble(parts[7].replace(",", "."));
        d.temperatura = Double.parseDouble(parts[8].replace(",", "."));
        d.umidade = Double.parseDouble(parts[9].replace(",", "."));
        d.ruido = Double.parseDouble(parts[10].replace(",", "."));
        d.uv = Double.parseDouble(parts[11].replace(",", "."));
        return d;
    }

    public String getIdDispositivo() {
        return idDispositivo;
    }

    public double getCo2() {
        return co2;
    }

    public double getTemperatura() {
        return temperatura;
    }

    public double getRuido() {
        return ruido;
    }

    public double getUv() {
        return uv;
    }

    public double getPm25() {
        return pm25;
    }
}
