// Test case: insecure-design (A06:2025)
package com.example.bank;

import java.util.Random;
import org.springframework.web.bind.annotation.*;

@RestController
public class AccountController {

    private final UserRepo users = new UserRepo();
    private final Random rng = new Random();

    @PostMapping("/login")
    public String login(@RequestBody LoginRequest req) {
        // BUG: no lockout or rate limit after repeated failed attempts
        User u = users.findByName(req.username);
        if (u == null) return "no such user"; // BUG: reveals account existence
        if (!u.password.equals(req.password)) return "bad password";
        return Session.create(u);
    }

    @PostMapping("/password-reset")
    public String requestReset(@RequestParam String email) {
        // BUG: 4-digit int reset token — only 10000 possibilities, brute-forceable in seconds
        int token = rng.nextInt(10000);
        users.storeResetToken(email, token);
        Mailer.send(email, "Your reset code: " + token);
        return "sent";
    }

    @PostMapping("/transfer")
    public String transfer(@RequestBody TransferRequest req) {
        // BUG: no rate limit, no daily cap, no re-authentication or confirmation gate
        // for an arbitrary-amount money movement
        Ledger.move(req.from, req.to, req.amount);
        return "ok";
    }
}
