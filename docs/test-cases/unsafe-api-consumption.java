// Unsafe API consumption — intentionally vulnerable. DO NOT deploy.
import java.net.http.*;
import java.net.URI;
import com.fasterxml.jackson.databind.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;

@RestController
public class PartnerSyncController {

    private final JdbcTemplate db;
    private final HttpClient client = HttpClient.newHttpClient();
    private final ObjectMapper mapper = new ObjectMapper();

    public PartnerSyncController(JdbcTemplate db) { this.db = db; }

    // BUG: external API data injected into SQL via string concatenation
    @PostMapping("/sync-products")
    public String syncProducts() throws Exception {
        var req = HttpRequest.newBuilder()
            .uri(URI.create("https://api.partner.com/products"))
            .build();
        var resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        var products = mapper.readTree(resp.body());
        for (var p : products) {
            // SQL injection — partner API response is untrusted
            db.execute("INSERT INTO products (name, price) VALUES ('"
                + p.get("name").asText() + "', " + p.get("price").asText() + ")");
        }
        return "synced";
    }

    // BUG: no response size limit — partner API could return 10GB
    @GetMapping("/partner-data")
    public String fetchPartnerData() throws Exception {
        var req = HttpRequest.newBuilder()
            .uri(URI.create("https://api.partner.com/data"))
            .build();
        // No timeout, no size limit
        var resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        return resp.body(); // reflected directly to user — XSS if HTML
    }
}
