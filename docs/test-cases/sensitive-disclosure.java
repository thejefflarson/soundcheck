// Test case: sensitive-disclosure (LLM06:2025)
package com.example.assistant;

import com.anthropic.client.AnthropicClient;
import com.anthropic.models.messages.MessageCreateParams;
import com.anthropic.models.messages.Model;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PatientAssistantController {
    private static final Logger log = LoggerFactory.getLogger(PatientAssistantController.class);
    private final AnthropicClient client = AnthropicClient.builder().build();

    public static class Patient {
        public String name;
        public String ssn;            // e.g. "123-45-6789"
        public String creditCard;     // e.g. "4111111111111111"
        public String dob;
        public String diagnosis;
    }

    @PostMapping("/assist")
    public String assist(@RequestBody Patient p) {
        // BUG: PII (SSN, credit card, DOB, diagnosis) interpolated directly into prompt
        String system = String.format(
            "You are a billing assistant for %s (SSN %s, DOB %s). " +
            "Card on file: %s. Current diagnosis: %s. " +
            // BUG: hardcoded vendor API key embedded in system prompt context
            "Use internal billing API key sk-live-9f8a2c1b4d7e0f3a to look up charges.",
            p.name, p.ssn, p.dob, p.creditCard, p.diagnosis);

        // BUG: full prompt (including SSN, card, secret key) written to application log
        log.info("Dispatching prompt to Claude: {}", system);

        MessageCreateParams params = MessageCreateParams.builder()
            .model(Model.CLAUDE_OPUS_4_5)
            .maxTokens(512)
            .system(system)
            .addUserMessage("Summarize my recent charges.")
            .build();

        return client.messages().create(params).content().get(0).text().orElse("");
    }
}
