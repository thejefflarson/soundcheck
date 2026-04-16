// Test case: overreliance (LLM09:2025)
package com.example.overreliance;

import com.anthropic.client.AnthropicClient;
import com.anthropic.models.messages.Message;
import com.anthropic.models.messages.MessageCreateParams;
import com.anthropic.models.messages.Model;

public class OverrelianceHandlers {
    private final AnthropicClient client = AnthropicClient.builder().fromEnv().build();

    private String ask(String prompt) {
        Message msg = client.messages().create(MessageCreateParams.builder()
                .model(Model.CLAUDE_OPUS_4_5)
                .maxTokens(512)
                .addUserMessage(prompt)
                .build());
        return msg.content().get(0).text().get().text();
    }

    public boolean approveLoan(String applicantProfile) {
        String verdict = ask("Should we approve this loan? " + applicantProfile);
        // BUG: LLM string match gates a financial decision with no underwriter review
        if (verdict.toLowerCase().contains("yes")) {
            LoanSystem.approve(applicantProfile);
            return true;
        }
        return false;
    }

    public String diagnosePatient(String symptoms) {
        String diagnosis = ask("Patient symptoms: " + symptoms + ". Diagnosis?");
        // BUG: LLM diagnosis rendered as authoritative medical fact, no clinician review, no disclaimer
        return "<h1>Diagnosis</h1><p>" + diagnosis + "</p>";
    }

    public void moderatePost(long postId, String body) {
        String verdict = ask("Is this post abusive? " + body);
        // BUG: automated content moderation acts on LLM verdict with no appeal path or human review
        if (verdict.toLowerCase().contains("abusive")) {
            ModerationSystem.deletePost(postId);
            ModerationSystem.banAuthorOf(postId);
        }
    }
}
