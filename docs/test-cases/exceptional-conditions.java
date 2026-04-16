// Test case: exceptional-conditions (A10:2025)
package com.example.api;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
public class AdminController {

    private final AuthService auth = new AuthService();
    private final AdminService admin = new AdminService();

    public boolean isAuthorized(String token, String resource) {
        try {
            return auth.checkPermission(token, resource);
        } catch (Exception e) {
            // BUG: fail-open — any exception grants access
            return true;
        }
    }

    @GetMapping("/admin/report")
    public ResponseEntity<String> report(@RequestHeader("X-Token") String token) {
        try {
            String data = admin.generateReport(token);
            return ResponseEntity.ok(data);
        } catch (Exception e) {
            // BUG: stack trace / internal message leaked to client
            return ResponseEntity.status(500).body(e.toString());
        }
    }

    @PostMapping("/admin/purge")
    public ResponseEntity<String> purge(@RequestHeader("X-Token") String token) {
        try {
            admin.purgeAll(token);
        } catch (Throwable t) {
            // BUG: swallows Throwable including OutOfMemoryError and StackOverflowError
        }
        return ResponseEntity.ok("done");
    }
}
