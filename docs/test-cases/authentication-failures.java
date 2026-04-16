// Test case: authentication-failures (A07:2025)
package com.example.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import java.security.MessageDigest;
import java.util.Random;
import org.springframework.web.bind.annotation.*;

@RestController
public class AuthController {

    private static final String JWT_KEY = "secret";
    private final Random random = new Random();

    // BUG: SHA-1 (unsalted, fast hash) used for password storage
    public String storePassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest(password.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password) throws Exception {
        String stored = lookupHash(username);
        String candidate = storePassword(password);
        // BUG: String.equals is timing-unsafe — leaks hash bytes via response time
        if (!stored.equals(candidate)) {
            return "denied";
        }
        // BUG: session token from java.util.Random (non-cryptographic PRNG)
        long sessionId = random.nextLong();
        return "session=" + Long.toHexString(sessionId);
    }

    public Claims verifyToken(String token) {
        // BUG: parser does not pin algorithm — accepts alg:none / HS256 confusion
        return Jwts.parser().setSigningKey(JWT_KEY).parseClaimsJws(token).getBody();
    }

    private String lookupHash(String username) { return ""; }
}
