package com.ufersa.seguranca.services;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import com.ufersa.seguranca.model.Mensagem;
import com.ufersa.seguranca.util.Constantes;
import com.ufersa.seguranca.util.ImplAES;
import com.ufersa.seguranca.util.ImplArgon2;
import com.ufersa.seguranca.util.ImplRSA;
import com.ufersa.seguranca.util.JwtService;
import com.ufersa.seguranca.util.Util;

public class ServidorAutenticacao {

    private static final Map<String, String> bancoUsuarios = new HashMap<>();
    private static ImplRSA rsa;
    private static String SEGREDO_JWT_BASE64;

    public static void main(String[] args) throws Exception {
        System.out.println("=== SERVIDOR DE AUTENTICACAO (SECURE LOGS) ===");

        SEGREDO_JWT_BASE64 = JwtService.inicializarChaveAleatoria();
        inicializarBanco();
        rsa = new ImplRSA();
        registrarNoDiscovery();

        try (ServerSocket serverSocket = new ServerSocket(Constantes.PORTA_AUTH)) {
            System.out.println("[AUTH] Ouvindo na porta " + Constantes.PORTA_AUTH);
            while (true) {
                Socket socket = serverSocket.accept();
                new Thread(() -> processarRequisicao(socket)).start();
            }
        }
    }

    private static void inicializarBanco() {
        String hashPadrao = ImplArgon2.gerarHash("admin123");
        bancoUsuarios.put("sensor01", hashPadrao);
        bancoUsuarios.put("sensor02", hashPadrao);
        bancoUsuarios.put("sensor03", hashPadrao);
        bancoUsuarios.put("sensor04", hashPadrao);
        bancoUsuarios.put("cliente01", hashPadrao);
        bancoUsuarios.put("invasor", ImplArgon2.gerarHash("senhaerrada"));
    }

    private static void registrarNoDiscovery() {
        try (Socket socket = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_LOCALIZACAO); ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream()); ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {
            out.writeObject("REGISTRAR_CHAVE:AUTH:" + rsa.getChavePublicaBase64());
            in.readObject();
        } catch (Exception e) {
            System.out.println("[AUTH] Erro ao registrar no Discovery: " + e.getMessage());
        }
    }

    private static void processarRequisicao(Socket socket) {
        try (ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream()); ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            Object obj = in.readObject();

            if (obj instanceof String comando && comando.startsWith("SOLICITAR_CHAVE_JWT:")) {
                String quemPede = comando.split(":")[1];
                System.out.println("[AUTH] Sincronizacao de Chave JWT solicitada por: " + quemPede);

                String[] dadosRequester = buscarServico(quemPede);
                byte[] keyBytes = Base64.getDecoder().decode(dadosRequester[1]);
                PublicKey publicaRequester = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyBytes));

                byte[] segredoCifrado = ImplRSA.cifrarChaveSimetrica(Base64.getDecoder().decode(SEGREDO_JWT_BASE64), publicaRequester);
                out.writeObject(Base64.getEncoder().encodeToString(segredoCifrado));
                return;
            }

            if (obj instanceof Mensagem msg) {
                System.out.println("\n[AUTH] >>> Processando Login Seguro...");

                System.out.println("[CRYPTO-LOG] 1. Decifrando Chave Simetrica (RSA Privada)...");
                byte[] chaveAesBytes = rsa.decifrarChaveSimetrica(msg.getChaveSimetricaCifrada());
                System.out.println("[CRYPTO-LOG]    -> Chave AES obtida.");

                System.out.println("[CRYPTO-LOG] 2. Decifrando Credenciais (AES)...");
                ImplAES aes = new ImplAES(chaveAesBytes);
                String credenciais = aes.decifrar(msg.getConteudoCifrado());

                System.out.println("[CRYPTO-LOG] 3. Verificando Integridade (HMAC)...");
                byte[] hmacCalculado = Util.calcularHmacSha256(chaveAesBytes, credenciais.getBytes());
                if (!java.security.MessageDigest.isEqual(hmacCalculado, Base64.getDecoder().decode(msg.getHmac()))) {
                    System.out.println("[AUTH] ERRO: HMAC Invalido!");
                    out.writeObject("ERRO: Integridade falhou");
                    return;
                }
                System.out.println("[CRYPTO-LOG]    -> Integridade OK.");

                String[] parts = credenciais.split(":");
                String usuario = parts[0];
                String senha = parts[1];

                System.out.println("[AUTH] Verificando Hash Argon2 para usuario: " + usuario);
                if (bancoUsuarios.containsKey(usuario)) {
                    if (ImplArgon2.verificarSenha(bancoUsuarios.get(usuario), senha)) {
                        String role = usuario.startsWith("sensor") ? "DEVICE" : "CLIENT";
                        String token = JwtService.gerarToken(usuario, role);

                        System.out.println("[AUTH] Sucesso. Gerando Token JWT.");
                        String tokenCifrado = aes.cifrar("OK:" + token);
                        out.writeObject(tokenCifrado);
                        return;
                    }
                }
                System.out.println("[AUTH] Falha: Credenciais invalidas.");
                out.writeObject(aes.cifrar("ERRO: Login falhou"));
            }

        } catch (Exception e) {
            System.out.println("[AUTH] Erro ao processar requisicao: " + e.getMessage());
        }
    }

    private static String[] buscarServico(String nome) throws Exception {
        try (Socket s = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_LOCALIZACAO); ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream()); ObjectInputStream in = new ObjectInputStream(s.getInputStream())) {
            out.writeObject("BUSCAR:" + nome);
            return ((String) in.readObject()).split("\\|");
        }
    }
}
