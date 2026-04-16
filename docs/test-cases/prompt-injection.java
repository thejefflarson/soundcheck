// Test case: prompt-injection (LLM01:2025)
package com.example.assistant;

import dev.langchain4j.model.chat.ChatLanguageModel;
import dev.langchain4j.model.anthropic.AnthropicChatModel;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/assistant")
public class AssistantController {

    private final ChatLanguageModel chatModel = AnthropicChatModel.builder()
            .apiKey(System.getenv("ANTHROPIC_API_KEY"))
            .modelName("claude-opus-4-6")
            .build();

    @PostMapping("/summarize")
    public String summarize(@RequestBody String userDoc) {
        // BUG: untrusted document concatenated directly into the instruction
        String prompt = "Summarize this document in 3 bullets: " + userDoc;
        return chatModel.generate(prompt);
    }

    @PostMapping("/rag")
    public String ragAnswer(@RequestParam String question, @RequestBody List<String> retrievedDocs) {
        // BUG: retrieved RAG context appended without delimiter tags, and the user
        // question lands in the system prompt tier
        StringBuilder system = new StringBuilder("You are a company knowledge assistant.\n");
        for (String doc : retrievedDocs) {
            system.append("\n").append(doc);  // no <context> markers, no escaping
        }
        system.append("\nUser asked: ").append(question);
        return chatModel.generate(system.toString());
    }

    @PostMapping("/email-triage")
    public String triageEmail(@RequestBody EmailPayload email) {
        // BUG: inbound email body (attacker-controlled) spliced into an instruction
        // string; a malicious sender can inject "ignore previous instructions..."
        String prompt = String.format(
                "Classify the following email as spam/ham and extract action items:\nFrom: %s\nSubject: %s\nBody: %s",
                email.from, email.subject, email.body);
        return chatModel.generate(prompt);
    }

    static class EmailPayload {
        public String from;
        public String subject;
        public String body;
    }
}
