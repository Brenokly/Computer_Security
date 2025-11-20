
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Questão 2: Servidor de Diretório Escuta por conexões e inicia Threads
 * (DirectoryHandler) para lidar com Clientes e Servidores de Calculadora.
 */
public class DirectoryServer {

    private static final int PORT = 53432;

    // Mapa de Serviços. Chave: Nome do Serviço, Valor: Lista de Endereços
    // Ex: "Calcular soma" -> ["10.0.0.1:9090", "10.0.0.2:9091"]
    private static final Map<String, List<String>> serviceMap = new ConcurrentHashMap<>();

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("==================================================");
            System.out.println(" Servidor de Diretório (Seguro) iniciado na porta " + PORT);
            System.out.println(" Aguardando conexões...");
            System.out.println("==================================================");

            while (true) {
                Socket socket = serverSocket.accept();
                System.out.println("[Servidor] Nova conexão: " + socket.getInetAddress());

                DirectoryHandler handler = new DirectoryHandler(socket, serviceMap);
                handler.start();
            }

        } catch (IOException e) {
            System.err.println("Erro no Servidor de Diretório: " + e.getMessage());
            System.err.println(Arrays.toString(e.getStackTrace()));
        }
    }
}
