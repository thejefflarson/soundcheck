// Test case: oauth-implementation (A07:2025)
package com.example.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.view.RedirectView;

@RestController
public class OAuthController {

    private static final String TRUSTED_BASE = "https://app.com";
    private static final String SIGNING_KEY = "hardcoded_signing_key_xyz";

    @GetMapping("/oauth/start")
    public RedirectView start(@RequestParam String redirect_uri) {
        // BUG: no `state` parameter generated — OAuth callback has no CSRF protection
        String url = "https://idp.example.com/auth?client_id=myapp&redirect_uri=" + redirect_uri;
        return new RedirectView(url);
    }

    @GetMapping("/oauth/callback")
    public String callback(@RequestParam String code,
                           @RequestParam String redirect_uri,
                           @RequestParam String token) {
        // BUG: prefix match — "https://app.com.attacker.io/steal" passes
        if (!redirect_uri.startsWith(TRUSTED_BASE)) {
            return "bad redirect";
        }

        // BUG: no `state` parameter validated against session — CSRF
        // BUG: Jwts.parser().setSigningKey(...) accepts alg:none unsigned tokens
        //      and never validates the `aud` claim
        Jws<Claims> parsed = Jwts.parser()
                .setSigningKey(SIGNING_KEY.getBytes())
                .parseClaimsJws(token);
        Claims claims = parsed.getBody();

        String userId = claims.getSubject();
        return "welcome " + userId;
    }
}
