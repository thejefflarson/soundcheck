// Test case: logging-failures (A09:2025)
package com.example.app;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

@RestController
public class AccountController {
    private static final Logger log = LoggerFactory.getLogger(AccountController.class);

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password) {
        // BUG: secret (password) written to log in plaintext
        log.info("user " + username + " password " + password);

        User user = authService.authenticate(username, password);
        if (user == null) {
            // BUG: failed login attempt is not logged as a security event
            return "invalid";
        }
        return issueToken(user);
    }

    @GetMapping("/profile")
    public String profile(@RequestParam String username) {
        // BUG: CRLF/log injection — username may contain \r\n and forge new log lines
        log.info("Profile viewed for username=" + username);
        return profileService.lookup(username);
    }

    @PostMapping("/admin/role")
    public String changeRole(@RequestParam String target, @RequestParam String role) {
        roleService.assign(target, role);
        // BUG: permission change logged without actor identity or timestamp/event id
        log.info("role changed");
        return "ok";
    }
}
