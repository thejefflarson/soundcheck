// Test case: model-dos (LLM04:2025)
package com.example.chat;

import com.anthropic.client.AnthropicClient;
import com.anthropic.client.okhttp.AnthropicOkHttpClient;
import com.anthropic.models.messages.Message;
import com.anthropic.models.messages.MessageCreateParams;
import com.anthropic.models.messages.Model;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class ChatController {

    private final AnthropicClient client = AnthropicOkHttpClient.fromEnv();

    @PostMapping("/chat")
    public Map<String, String> chat(@RequestBody Map<String, String> body) {
        String userId = body.get("user_id");
        // BUG: no length cap — a multi-megabyte prompt is forwarded as-is
        String message = body.get("message");

        // BUG: no rate limit / per-user quota — a single caller can pin the
        // endpoint and burn the entire Anthropic spend budget in minutes
        MessageCreateParams params = MessageCreateParams.builder()
                .model(Model.CLAUDE_OPUS_4_5)
                // BUG: max_tokens not set to a bounded value — responses can
                // grow until the model's context window is exhausted
                .maxTokens(200_000L)
                .addUserMessage(message)
                .build();

        Message response = client.messages().create(params);
        String reply = response.content().get(0).text().orElseThrow().text();
        return Map.of("user_id", userId, "reply", reply);
    }
}
