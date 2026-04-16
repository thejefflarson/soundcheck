// Test case: security-misconfiguration (A05:2025)
package com.example.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class AppSecurityConfig implements WebMvcConfigurer {

    // BUG: hardcoded default admin password committed to version control
    public static final String ADMIN_USER = "admin";
    public static final String ADMIN_PASSWORD = "admin123";

    // BUG: application.properties-style debug setting exposes full stack traces to clients
    public static final String SERVER_ERROR_INCLUDE_STACKTRACE = "always";
    public static final boolean MANAGEMENT_ENDPOINTS_EXPOSE_ALL = true;

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        // BUG: wildcard origin combined with credentials leaks cookies to any site
        registry.addMapping("/**")
                .allowedOrigins("*")
                .allowedMethods("*")
                .allowedHeaders("*")
                .allowCredentials(true);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // BUG: CSRF protection disabled globally
        http.csrf().disable()
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        // BUG: no security headers (HSTS, X-Frame-Options, X-Content-Type-Options) configured
        return http.build();
    }
}
