package com.example.security.jwt.service;

import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;

public class JwtServiceTest {

    private static  String secret(String text){
        return Base64.getEncoder().encodeToString(text.getBytes(StandardCharsets.UTF_8));
    }

    private static final String SECRET = secret("test-secret-key-must-be-at-least-32-bytes-long!");

    private final UserDetails admin = User.withUsername("admin")
            .password("ignored").roles("ADMIN").build();   // becomes ROLE_ADMIN

    @Test
    void generatedToken_ContainsUsernameAndRoles() {
        JwtService service = new JwtService(SECRET, 60_000);

        Claims claims = service.parse(service.generateToken(admin));
        assertEquals("admin", claims.getSubject());
        assertTrue(((List<?>) claims.get("roles")).contains("ROLE_ADMIN"));
    }

    @Test
    void tamperedToken_isRejected() {
        JwtService service = new JwtService(SECRET, 60_000);
        String token = service.generateToken(admin);

        // Change the last character of the signature
        char last = token.charAt(token.length() - 1);
        String tampered = token.substring(0, token.length() - 1) + (last == 'a' ? 'b' : 'a');

        assertThrows(JwtException.class, () -> service.parse(tampered));
    }

    @Test
    void expiredToken_isRejected() {
        JwtService service = new JwtService(SECRET, -1_000);   // already expired

        String token = service.generateToken(admin);

        assertThrows(ExpiredJwtException.class, () -> service.parse(token));
    }

    @Test
    void tokenSignedWithOtherKey_isRejected() {
        JwtService signer = new JwtService(secret("another-secret-key-also-32-bytes-or-more!!"), 60_000);
        JwtService verifier = new JwtService(SECRET, 60_000);

        String token = signer.generateToken(admin);

        assertThrows(JwtException.class, () -> verifier.parse(token));
    }
}

