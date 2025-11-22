package com.ufersa.seguranca.util;

public class Constantes {

    // Tipos de Mensagem
    public static final int TIPO_DISCOVERY = 1;
    public static final int TIPO_AUTH_REQ = 2;      // Usado no Login Seguro
    public static final int TIPO_DADOS_SENSOR = 3;  // Usado no envio de dados
    public static final int TIPO_RELATORIO_REQ = 4; // Usado pelo Cliente

    // Endereços e Portas
    public static final String IP_LOCAL = "127.0.0.1";

    // Portas dos Serviços
    public static final int PORTA_LOCALIZACAO = 5000;
    public static final int PORTA_AUTH = 5001;
    public static final int PORTA_BORDA_UDP = 6000;
    public static final int PORTA_DATACENTER_TCP = 7000;
}
