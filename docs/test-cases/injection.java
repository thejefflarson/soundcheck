// Test case: injection (A05:2025)
package com.example.app;

import java.sql.*;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;
import freemarker.template.*;

@RestController
public class UserController {

    @GetMapping("/users")
    public String getUser(HttpServletRequest req) throws Exception {
        String userId = req.getParameter("id");
        Connection conn = DriverManager.getConnection("jdbc:postgresql://db/app");
        Statement stmt = conn.createStatement();
        // BUG: SQL injection via string concatenation
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
        return rs.next() ? rs.getString("name") : "none";
    }

    @GetMapping("/convert")
    public String convertFile(@RequestParam String filename) throws Exception {
        // BUG: shell injection — Runtime.exec with user input parsed by the shell
        Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", "convert " + filename + " out.png"});
        return "ok: " + p.waitFor();
    }

    @GetMapping("/greet")
    public String greet(@RequestParam String name) throws Exception {
        Configuration cfg = new Configuration(Configuration.VERSION_2_3_31);
        // BUG: server-side template injection — user input compiled as a FreeMarker template
        Template t = new Template("greet", new java.io.StringReader("Hello " + name + "!"), cfg);
        java.io.StringWriter out = new java.io.StringWriter();
        t.process(new java.util.HashMap<>(), out);
        return out.toString();
    }
}
