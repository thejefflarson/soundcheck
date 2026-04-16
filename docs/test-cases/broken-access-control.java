// Test case: broken-access-control (A01:2025)
// Spring Boot controller with IDOR, missing role gate, and SSRF.
package com.example.shop;

import java.net.URL;
import java.net.HttpURLConnection;
import java.io.InputStream;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;

@RestController
public class OrderController {

    @Autowired private OrderRepository orders;
    @Autowired private UserRepository users;

    // BUG: IDOR — looks up order by path id with no ownership check.
    // Any authenticated user can read any other user's order.
    @GetMapping("/orders/{id}")
    public Order getOrder(@PathVariable Long id) {
        return orders.findById(id).orElse(null);
    }

    // BUG: admin endpoint missing @PreAuthorize("hasRole('ADMIN')").
    // Vertical privilege escalation — any authenticated caller can delete users.
    @DeleteMapping("/admin/users/{userId}")
    public void deleteUser(@PathVariable Long userId) {
        users.deleteById(userId);
    }

    // BUG: SSRF — fetches arbitrary user-supplied URL with no allowlist.
    // Attacker can pivot to internal services (169.254.169.254, localhost, etc.).
    @GetMapping("/preview")
    public String preview(@RequestParam("url") String userUrl) throws Exception {
        URL u = new URL(userUrl);
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
        try (InputStream in = conn.getInputStream()) {
            return new String(in.readAllBytes());
        }
    }

    // BUG: ownership check happens AFTER the destructive action.
    @PostMapping("/orders/{id}/cancel")
    public void cancel(@PathVariable Long id, @RequestHeader("X-User-Id") Long uid) {
        orders.markCancelled(id);
        Order o = orders.findById(id).orElse(null);
        if (o != null && !o.getOwnerId().equals(uid)) {
            throw new RuntimeException("not yours");
        }
    }
}
