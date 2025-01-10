import java.io.*;
import java.util.*;

public class FlowLogParser {
    private Map<PortProtocol, String> tagMapping = new HashMap<>();
    private Map<String, Integer> tagCounts = new HashMap<>();
    private Map<PortProtocol, Integer> portProtocolCounts = new HashMap<>();

    static class PortProtocol {
        String port;
        String protocol;

        PortProtocol(String port, String protocol) {
            this.port = port;
            this.protocol = protocol.toLowerCase();
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            PortProtocol that = (PortProtocol) o;
            return Objects.equals(port, that.port) && Objects.equals(protocol, that.protocol);
        }

        @Override
        public int hashCode() {
            return Objects.hash(port, protocol);
        }
    }

    public void loadLookupTable(String lookupFile) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(lookupFile))) {
            String line = reader.readLine();
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts.length >= 3) {
                    PortProtocol key = new PortProtocol(parts[0], parts[1]);
                    tagMapping.put(key, parts[2]);
                }
            }
        }
    }

    private String normalizeProtocol(String protocol) {
        Map<String, String> protocolMap = new HashMap<>();
        protocolMap.put("6", "tcp");
        protocolMap.put("17", "udp");
        protocolMap.put("1", "icmp");
        return protocolMap.getOrDefault(protocol.toLowerCase(), protocol.toLowerCase());
    }

    public void parseFlowLogs(String flowLogFile) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(flowLogFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] fields = line.trim().split("\\s+");
                if (fields.length >= 14 && fields[0].equals("2")) {
                    String dstPort = fields[6];
                    String protocol = normalizeProtocol("tcp");

                    PortProtocol key = new PortProtocol(dstPort, protocol);
                    portProtocolCounts.merge(key, 1, Integer::sum);

                    String tag = tagMapping.getOrDefault(key, "Untagged");
                    tagCounts.merge(tag, 1, Integer::sum);
                }
            }
        }
    }

    public void writeResults(String outputFile) throws IOException {
        try (PrintWriter writer = new PrintWriter(new FileWriter(outputFile))) {
            writer.println("Tag Counts:\nTag,Count");
            List<Map.Entry<String, Integer>> sortedTags = new ArrayList<>(tagCounts.entrySet());
            sortedTags.sort(Map.Entry.comparingByKey());
            for (Map.Entry<String, Integer> entry : sortedTags) {
                writer.printf("%s,%d%n", entry.getKey(), entry.getValue());
            }

            writer.println("\nPort/Protocol Combination Counts:\nPort,Protocol,Count");
            List<Map.Entry<PortProtocol, Integer>> sortedPorts = new ArrayList<>(portProtocolCounts.entrySet());
            sortedPorts.sort((a, b) -> a.getKey().port.compareTo(b.getKey().port));
            for (Map.Entry<PortProtocol, Integer> entry : sortedPorts) {
                writer.printf("%s,%s,%d%n",
                        entry.getKey().port,
                        entry.getKey().protocol,
                        entry.getValue());
            }
        }
    }

    public static void main(String[] args) {
        try {
            FlowLogParser parser = new FlowLogParser();
            parser.loadLookupTable("lookup.csv");
            parser.parseFlowLogs("flow_logs.txt");
            parser.writeResults("analysis_results.csv");
        } catch (IOException e) {
            System.err.println("Error processing files: " + e.getMessage());
            System.exit(1);
        }
    }
}