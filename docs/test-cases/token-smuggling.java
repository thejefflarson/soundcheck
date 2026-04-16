// Test case: token-smuggling (LLM01:2025)
package com.example.reviews;

import java.util.List;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

@RestController
@RequestMapping("/api")
public class ReviewController {

    private final AnthropicClient client = new AnthropicClient();
    private static final List<String> BLOCKED_DOMAINS =
        List.of("paypal.com", "apple.com", "google.com");

    @PostMapping("/summarize")
    public ResponseEntity<String> summarize(@RequestBody ReviewRequest req) {
        // BUG: user review concatenated into prompt with no Normalizer.normalize(Form.NFKC).
        // RTL override (\u202E) and zero-width joiners flow directly into the model.
        String prompt = "Summarize this product review: " + req.getReview();
        String summary = client.complete("claude-haiku-4-5-20251001", prompt, 256);
        return ResponseEntity.ok(summary);
    }

    @PostMapping("/translate")
    public ResponseEntity<String> translate(@RequestBody ReviewRequest req) {
        // BUG: no strip of control/formatting chars (\u200B, \u200C, \u2060, \uFEFF)
        // before building the prompt — attacker-hidden instructions survive.
        String prompt = String.format("Translate to English: %s", req.getReview());
        return ResponseEntity.ok(client.complete("claude-haiku-4-5-20251001", prompt, 512));
    }

    @GetMapping("/check-url")
    public ResponseEntity<Boolean> checkUrl(@RequestParam String url) {
        // BUG: homoglyph bypass — "раypal.com" (Cyrillic 'р', U+0440) passes this
        // blocklist because the string is compared without NFKC normalization.
        for (String domain : BLOCKED_DOMAINS) {
            if (url.contains(domain)) {
                return ResponseEntity.ok(false);
            }
        }
        return ResponseEntity.ok(true);
    }

    public static class ReviewRequest {
        private String review;
        public String getReview() { return review; }
        public void setReview(String r) { this.review = r; }
    }
}
