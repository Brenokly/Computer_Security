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
import com.ufersa.seguranca.util.ImplHashSalt;
import com.ufersa.seguranca.util.ImplRSA;
import com.ufersa.seguranca.util.JwtService;
import com.ufersa.seguranca.util.Util;

/**
 * SERVIDOR DE AUTENTICAÇÃO
 * * Responsabilidade: Gerenciar identidades, validar credenciais e emitir tokens de sessão.
 * Tecnologias de Segurança:
 * 1. PBKDF2 com Salt (Prática 8.1): Armazenamento seguro de senhas, resistente a Rainbow Tables.
 * 2. Criptografia Híbrida (RSA + AES): Descriptografa as credenciais recebidas protegidas por envelope digital.
 * 3. HMAC-SHA256: Verifica a integridade do pacote de login antes de processar.
 * 4. JWT (JSON Web Token): Gera tokens assinados com chave secreta dinâmica para autenticação stateless.
 */
public class ServidorAutenticacao {

    private static final Map<String, String> bancoUsuarios = new HashMap<>();
    private static ImplRSA rsa;
    private static String SEGREDO_JWT_BASE64;

    public static void main(String[] args) throws Exception {
        System.out.println("=================================================");
        System.out.println("[AUTH] Inicializando Servidor de Autenticação...");

        SEGREDO_JWT_BASE64 = JwtService.inicializarChaveAleatoria();
        System.out.println("[SECURITY] Chave Mestra JWT gerada (em memoria).");

        inicializarBanco();

        System.out.print("[INIT] Gerando par de chaves RSA... ");
        rsa = new ImplRSA();
        System.out.println("OK.");

        registrarNoDiscovery();

        try (ServerSocket serverSocket = new ServerSocket(Constantes.PORTA_AUTH)) {
            System.out.println("[AUTH] Servidor SEGURO rodando na porta " + Constantes.PORTA_AUTH);
            System.out.println("[AUTH] Aguardando requisicoes...");
            System.out.println("=================================================");

            while (true) {
                Socket socket = serverSocket.accept();
                new Thread(() -> processarRequisicao(socket)).start();
            }
        }
    }

    private static void inicializarBanco() throws Exception {
        System.out.print("[INIT] Carregando banco de usuarios... ");
        String hashPadrao = ImplHashSalt.getHashSenhaSegura("admin123");

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

    /*
     * Processa requisições seguras:
     * 1. Login: Recebe envelope digital, valida HMAC, decifra AES, valida Hash da senha e retorna JWT cifrado.
     * 2. Sincronização: Distribui a Chave Mestra do JWT (AES-256) cifrada com RSA para Borda e Cloud.
    */
    private static void processarRequisicao(Socket socket) {
        try (ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream()); ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            Object obj = in.readObject();

            if (obj instanceof String comando && comando.startsWith("SOLICITAR_CHAVE_JWT:")) {
                String quemPede = comando.split(":")[1];
                System.out.print("\n[SYNC] " + quemPede + " solicitou chave JWT... ");

                String[] dadosRequester = buscarServico(quemPede);
                byte[] keyBytes = Base64.getDecoder().decode(dadosRequester[1]);
                PublicKey publicaRequester = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyBytes));

                byte[] segredoCifrado = ImplRSA.cifrarChaveSimetrica(Base64.getDecoder().decode(SEGREDO_JWT_BASE64), publicaRequester);

                out.writeObject(Base64.getEncoder().encodeToString(segredoCifrado));
                System.out.println("Enviada (Protegida por RSA).");
                return;
            }

            if (obj instanceof Mensagem msg) {
                System.out.print("\n[LOGIN] Nova tentativa... ");

                byte[] chaveAesBytes = rsa.decifrarChaveSimetrica(msg.getChaveSimetricaCifrada());
                ImplAES aes = new ImplAES(chaveAesBytes);

                String credenciais = aes.decifrar(msg.getConteudoCifrado());

                byte[] hmacCalculado = Util.calcularHmacSha256(chaveAesBytes, credenciais.getBytes());
                byte[] hmacRecebido = Base64.getDecoder().decode(msg.getHmac());

                if (!java.security.MessageDigest.isEqual(hmacCalculado, hmacRecebido)) {
                    System.out.println("ERRO: HMAC invalido.");
                    out.writeObject("ERRO: Integridade violada");
                    return;
                }

                String[] parts = credenciais.split(":");
                if (parts.length != 2) {
                    out.writeObject("ERRO: Formato invalido");
                    return;
                }

                String usuario = parts[0];
                String senha = parts[1];

                if (bancoUsuarios.containsKey(usuario)) {
                    boolean valida = ImplHashSalt.validarSenha(senha, bancoUsuarios.get(usuario));
                    if (valida) {
                        String role = usuario.startsWith("sensor") ? "DEVICE" : "CLIENT";
                        String token = JwtService.gerarToken(usuario, role);

                        String tokenCifrado = aes.cifrar("OK:" + token);
                        out.writeObject(tokenCifrado);
                        System.out.println("SUCESSO (" + usuario + ")");
                        return;
                    }
                }
                System.out.println("FALHA (Credenciais invalidas)");
                String erroCifrado = aes.cifrar("ERRO: Credenciais Invalidas");
                out.writeObject(erroCifrado);
            }

        } catch (Exception e) {
            System.out.println("[ERRO PROC] " + e.getMessage());
        }
    }

    private static String[] buscarServico(String nome) throws Exception {
        try (Socket s = new Socket(Constantes.IP_LOCAL, Constantes.PORTA_LOCALIZACAO); ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream()); ObjectInputStream in = new ObjectInputStream(s.getInputStream())) {
            out.writeObject("BUSCAR:" + nome);
            String resp = (String) in.readObject();
            return resp.split("\\|");
        }
    }
}
