// Test case: insecure-output-handling (LLM02:2025)
package com.example.ai;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

@Controller
public class AiController {

    private String callClaude(String prompt) {
        // Pretend this calls the Anthropic SDK and returns response.content[0].text
        return AnthropicClient.complete("claude-opus-4-6", prompt);
    }

    @GetMapping("/summary")
    public String summary(@RequestParam String topic, Model model) {
        String aiHtml = callClaude("Write an HTML summary of: " + topic);
        // BUG: rendered with Thymeleaf th:utext — raw HTML from LLM → stored XSS
        model.addAttribute("aiHtml", aiHtml);
        return "summary"; // template: <div th:utext="${aiHtml}"></div>
    }

    @GetMapping("/report")
    public String report(@RequestParam String question, Model model) throws Exception {
        String sql = callClaude("Translate to SQL against users table: " + question);
        // BUG: LLM-generated SQL concatenated into a Statement — SQL injection
        Connection conn = DriverManager.getConnection("jdbc:postgresql://db/app");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        model.addAttribute("rows", rs);
        return "report";
    }

    @GetMapping("/run")
    public String run(@RequestParam String task) throws Exception {
        String cmd = callClaude("Bash one-liner to: " + task);
        // BUG: LLM output executed as a shell command — RCE
        Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});
        p.waitFor();
        return "done";
    }
}
