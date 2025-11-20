
import java.util.HashMap;
import java.util.Map;

public class RingConfig {

    public static final String HOST = "localhost";

    private static final Map<Integer, Integer> NODE_PORTS = new HashMap<>();
    private static final Map<Integer, String> SUCCESSOR_ADDRESSES = new HashMap<>();
    private static final Map<Integer, String> PREDECESSOR_ADDRESSES = new HashMap<>();

    static {
        int basePort = 9000;

        for (int i = 0; i < 6; i++) {
            NODE_PORTS.put(i, basePort + i);
        }

        SUCCESSOR_ADDRESSES.put(0, HOST + ":" + NODE_PORTS.get(1)); // P0 -> P1
        SUCCESSOR_ADDRESSES.put(1, HOST + ":" + NODE_PORTS.get(2)); // P1 -> P2
        SUCCESSOR_ADDRESSES.put(2, HOST + ":" + NODE_PORTS.get(3)); // P2 -> P3
        SUCCESSOR_ADDRESSES.put(3, HOST + ":" + NODE_PORTS.get(4)); // P3 -> P4
        SUCCESSOR_ADDRESSES.put(4, HOST + ":" + NODE_PORTS.get(5)); // P4 -> P5
        SUCCESSOR_ADDRESSES.put(5, HOST + ":" + NODE_PORTS.get(0)); // P5 -> P0

        PREDECESSOR_ADDRESSES.put(0, HOST + ":" + NODE_PORTS.get(5)); // P0 <- P5
        PREDECESSOR_ADDRESSES.put(1, HOST + ":" + NODE_PORTS.get(0)); // P1 <- P0
        PREDECESSOR_ADDRESSES.put(2, HOST + ":" + NODE_PORTS.get(1)); // P2 <- P1
        PREDECESSOR_ADDRESSES.put(3, HOST + ":" + NODE_PORTS.get(2)); // P3 <- P2
        PREDECESSOR_ADDRESSES.put(4, HOST + ":" + NODE_PORTS.get(3)); // P4 <- P3
        PREDECESSOR_ADDRESSES.put(5, HOST + ":" + NODE_PORTS.get(4)); // P5 <- P4
    }

    public static int getPortForNode(int nodeId) {
        return NODE_PORTS.get(nodeId);
    }

    public static String getSuccessorAddress(int nodeId) {
        return SUCCESSOR_ADDRESSES.get(nodeId);
    }

    public static String getPredecessorAddress(int nodeId) {
        return PREDECESSOR_ADDRESSES.get(nodeId);
    }
}
