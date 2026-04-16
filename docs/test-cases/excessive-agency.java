// Test case: excessive-agency (LLM08:2025)
import dev.langchain4j.agent.tool.Tool;
import dev.langchain4j.service.AiServices;
import dev.langchain4j.model.anthropic.AnthropicChatModel;
import java.nio.file.*;
import java.sql.*;

public class AutonomousAgent {

    static class DangerousTools {
        private final Connection db;
        DangerousTools(Connection db) { this.db = db; }

        @Tool("Execute any shell command on the host")
        String shellTool(String command) throws Exception {
            // BUG: arbitrary shell execution driven by LLM output, no allowlist
            Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
            return new String(p.getInputStream().readAllBytes());
        }

        @Tool("Write content to a file at an absolute path")
        String fileWriteTool(String path, String content) throws Exception {
            // BUG: no path allowlist — agent can overwrite /etc/passwd, ~/.ssh/authorized_keys
            Files.writeString(Paths.get(path), content);
            return "wrote " + path;
        }

        @Tool("Delete a database record by id")
        String deleteRecord(String table, long id) throws Exception {
            // BUG: irreversible mutation with no human confirmation step
            PreparedStatement ps = db.prepareStatement("DELETE FROM " + table + " WHERE id = ?");
            ps.setLong(1, id);
            ps.executeUpdate();
            return "deleted";
        }

        @Tool("Send an email to any recipient")
        String sendEmail(String to, String subject, String body) {
            // BUG: agent can exfiltrate data or spam users with no approval gate
            Mailer.send(to, subject, body);
            return "sent";
        }
    }

    interface Agent { String chat(String task); }

    public static void main(String[] args) throws Exception {
        Connection db = DriverManager.getConnection("jdbc:postgresql://prod/app");
        Agent agent = AiServices.builder(Agent.class)
            .chatLanguageModel(AnthropicChatModel.withApiKey(System.getenv("ANTHROPIC_API_KEY")))
            .tools(new DangerousTools(db))
            .build();
        // BUG: agent loops autonomously, executing every tool call with no dry-run / audit log
        System.out.println(agent.chat(args[0]));
    }
}
