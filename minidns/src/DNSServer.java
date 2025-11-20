
import java.io.IOException;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Questão 1: Servidor Mini-DNS Usa ServerSocket padrão Java para escutar. Usa
 * ConcurrentHashMap para o mapa (thread-safe). Usa CopyOnWriteArrayList para a
 * lista de clientes (thread-safe). Dispara uma nova Thread (ClientHandler) para
 * cada cliente.
 */
public class DNSServer {

    // Porta em que o servidor escuta
    private static final int PORT = 34525;

    // Mapa de DNS (Thread-Safe)
    private static final Map<String, String> dnsMap = new ConcurrentHashMap<>();

    // Lista de escritores de todos os clientes conectados.
    // Usada para o binding dinâmico (notificar todos sobre atualizações).
    private static List<PrintWriter> clientWriters = new CopyOnWriteArrayList<>();

    public static void main(String[] args) {
        // Popula o mapa inicial com os 10 servidores
        populateInitialMap();

        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("==================================================");
            System.out.println(" Servidor DNS (Seguro) iniciado na porta " + PORT);
            System.out.println(" Aguardando conexões de clientes...");
            System.out.println("==================================================");

            // Loop infinito para aceitar conexões de clientes
            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("[Servidor] Novo cliente conectado: " + clientSocket.getInetAddress());

                // Cria um escritor para este cliente
                PrintWriter writer = new PrintWriter(clientSocket.getOutputStream(), true);

                // Adiciona o escritor à lista compartilhada (para notificações)
                clientWriters.add(writer);

                // Cria e inicia a Thread (ClientHandler) para cuidar deste cliente
                ClientHandler handler = new ClientHandler(clientSocket, dnsMap, clientWriters, writer);
                handler.start();
            }

        } catch (IOException e) {
            System.err.println("Erro no Servidor DNS: " + e.getMessage());
        }
    }

    /**
     * Preenche o mapa de DNS com os valores iniciais, conforme solicitado no
     * PDF .
     */
    private static void populateInitialMap() {
        dnsMap.put("servidor1", "192.168.0.10");
        dnsMap.put("servidor2", "192.168.0.20");
        dnsMap.put("servidor3", "192.168.0.30");
        dnsMap.put("servidor4", "192.168.0.40");
        dnsMap.put("servidor5", "192.168.0.50");
        dnsMap.put("servidor6", "192.168.0.60");
        dnsMap.put("servidor7", "192.168.0.70");
        dnsMap.put("servidor8", "192.168.0.80");
        dnsMap.put("servidor9", "192.168.0.90");
        dnsMap.put("servidor10", "192.168.0.100");
    }

    public static List<PrintWriter> getClientWriters() {
        return clientWriters;
    }

    public static void setClientWriters(List<PrintWriter> clientWriters) {
        DNSServer.clientWriters = clientWriters;
    }
}
