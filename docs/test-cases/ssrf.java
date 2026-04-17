// SSRF — intentionally vulnerable. DO NOT deploy.
import java.net.*;
import java.io.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class SsrfController {

    // BUG: fetches any URL the caller supplies
    @GetMapping("/preview")
    public String preview(@RequestParam String url) throws Exception {
        // No validation — attacker can reach cloud metadata, internal services
        URL target = new URL(url);
        HttpURLConnection conn = (HttpURLConnection) target.openConnection();
        conn.setInstanceFollowRedirects(true); // follows redirects to internal
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(conn.getInputStream()));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) sb.append(line);
        return sb.toString();
    }

    // BUG: webhook with no URL validation
    @PostMapping("/webhook")
    public String registerWebhook(@RequestBody WebhookRequest req) throws Exception {
        URL callback = new URL(req.callbackUrl);
        HttpURLConnection conn = (HttpURLConnection) callback.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.getOutputStream().write("{\"status\":\"ok\"}".getBytes());
        return "registered";
    }

    record WebhookRequest(String callbackUrl) {}
}
