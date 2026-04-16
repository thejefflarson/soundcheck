// Test case: insecure-plugin-design (LLM07:2025)
package com.example.tools;

import dev.langchain4j.agent.tool.Tool;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

public class LlmTools {

    private final HttpClient httpClient = HttpClients.createDefault();

    // BUG: @Tool string parameter has no schema constraints (no maxLength, no pattern).
    // BUG: path is read directly with no confinement to an allowed base directory —
    // LLM can request "../../etc/passwd" or "/home/user/.ssh/id_rsa".
    @Tool("Read a file from disk")
    public String readFile(String path) throws Exception {
        return Files.readString(Path.of(path));
    }

    // BUG: raw SQL from the model is concatenated into a JDBC Statement — the tool
    // description says "query" but the LLM can emit DROP TABLE, UPDATE, or UNION
    // SELECT against other tables. No PreparedStatement, no allowlist of tables.
    @Tool("Run a SQL query against the app database")
    public String runQuery(String query) throws Exception {
        try (Connection c = DriverManager.getConnection("jdbc:postgresql://db/app");
             Statement stmt = c.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            StringBuilder sb = new StringBuilder();
            while (rs.next()) sb.append(rs.getString(1)).append("\n");
            return sb.toString();
        }
    }

    // BUG: no URL scheme/host allowlist — the LLM can be coerced via prompt injection
    // into fetching http://169.254.169.254/latest/meta-data/ (SSRF to cloud metadata)
    // or file:// URLs. No authorization check on the caller either.
    @Tool("Fetch a URL and return the body")
    public String fetchUrl(String url) throws Exception {
        return EntityUtils.toString(httpClient.execute(new HttpGet(url)).getEntity());
    }
}
