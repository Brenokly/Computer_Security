package com.ufersa.seguranca.services;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import com.ufersa.seguranca.model.Mensagem;
import com.ufersa.seguranca.util.Constantes;
import com.ufersa.seguranca.util.ImplAES;
import com.ufersa.seguranca.util.ImplHashSalt;
import com.ufersa.seguranca.util.ImplRSA;
import com.ufersa.seguranca.util.JwtService;
import com.ufersa.seguranca.util.Util;

public class ServidorAutenticacao {

    private static final Map<String, String> bancoUsuarios = new HashMap<>();
    private static ImplRSA rsa;

    public static void main(String[] args) throws Exception {
        System.out.println("=================================================");
        System.out.println("[AUTH] Inicializando Servidor de Autenticação...");

        inicializarBanco();

        System.out.print("[INIT] Gerando par de chaves RSA... ");
        rsa = new ImplRSA();
        System.out.println("OK.");

        registrarNoDiscovery();

        try (ServerSocket serverSocket = new ServerSocket(Constantes.PORTA_AUTH)) {
            System.out.println("[AUTH] Servidor SEGURO rodando na porta " + Constantes.PORTA_AUTH);
            System.out.println("[AUTH] Aguardando requisicoes de login...");
            System.out.println("=================================================");

            while (true) {
                Socket socket = serverSocket.accept();
                new Thread(() -> processarLogin(socket)).start();
            }
        }
    }

    private static void inicializarBanco() throws Exception {
        System.out.print("[INIT] Carregando banco de usuarios (Hash+Salt)... ");
        String hashPadrao = ImplHashSalt.getHashSenhaSegura("admin123");

        // Senha incorreta pre-calculada para testes (opcional)
        bancoUsuarios.put("sensor01", hashPadrao);
        bancoUsuarios.put("sensor02", hashPadrao);
        bancoUsuarios.put("sensor03", hashPadrao);
        bancoUsuarios.put("sensor04", hashPadrao);
        bancoUsuarios.put("cliente01", hashPadrao);

        System.out.println(bancoUsuarios.size() + " usuarios carregados.");
    }

    private static void registrarNoDiscovery() {
        System.out.print("[INIT] Registrando chave publica no Discovery... ");
        try (Socket socket = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_LOCALIZACAO); ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream()); ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            out.writeObject("REGISTRAR_CHAVE:AUTH:" + rsa.getChavePublicaBase64());
            in.readObject();
            System.out.println("OK.");
        } catch (Exception e) {
            System.out.println("FALHA (" + e.getMessage() + ")");
        }
    }

    private static void processarLogin(Socket socket) {
        try (ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream()); ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            System.out.print("\n[LOGIN] Conexao recebida de " + socket.getInetAddress() + "... ");

            Object obj = in.readObject();
            if (obj instanceof Mensagem msg) {

                // 1. Decifrar a chave simétrica
                byte[] chaveAesBytes = rsa.decifrarChaveSimetrica(msg.getChaveSimetricaCifrada());
                ImplAES aes = new ImplAES(chaveAesBytes);

                // 2. Decifrar o conteúdo
                String credenciais = aes.decifrar(msg.getConteudoCifrado());

                // 3. Verificar HMAC
                byte[] hmacCalculado = Util.calcularHmacSha256(chaveAesBytes, credenciais.getBytes());
                byte[] hmacRecebido = Base64.getDecoder().decode(msg.getHmac());

                if (!java.security.MessageDigest.isEqual(hmacCalculado, hmacRecebido)) {
                    System.out.println("ERRO DE INTEGRIDADE (HMAC invalido).");
                    out.writeObject("ERRO: Integridade violada");
                    return;
                }

                String[] parts = credenciais.split(":");
                if (parts.length != 2) {
                    System.out.println("FORMATO INVALIDO.");
                    out.writeObject("ERRO: Formato invalido");
                    return;
                }

                String usuario = parts[0];
                String senha = parts[1];

                System.out.print("Usuario: " + usuario + " | Validando senha... ");

                if (bancoUsuarios.containsKey(usuario)) {
                    boolean valida = ImplHashSalt.validarSenha(senha, bancoUsuarios.get(usuario));
                    if (valida) {
                        System.out.println("SUCESSO.");
                        String role = usuario.startsWith("sensor") ? "DEVICE" : "CLIENT";
                        String token = JwtService.gerarToken(usuario, role);

                        // Resposta cifrada
                        String tokenCifrado = aes.cifrar("OK:" + token);
                        out.writeObject(tokenCifrado);
                        System.out.println("   -> Token JWT gerado e enviado (Cifrado).");
                        return;
                    } else {
                        System.out.println("SENHA INCORRETA.");
                    }
                } else {
                    System.out.println("USUARIO NAO ENCONTRADO.");
                }

                String erroCifrado = aes.cifrar("ERRO: Credenciais Invalidas");
                out.writeObject(erroCifrado);
            }

        } catch (Exception e) {
            System.out.println("[ERRO LOGIN] " + e.getMessage());
        }
    }
}
