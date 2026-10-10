package com.example.security.jwt.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;

@Service
public class JwtService {

    private final SecretKey key;
    private final long expirationMs;

    public JwtService(@Value("${app.jwt.secret}") String secret,
                      @org.springframework.beans.factory.annotation.Value("${app.jwt.expiration-ms}") long expirationMs){
        this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
        this.expirationMs = expirationMs;
    }

    /** Build a signed token for a logged-in user. */
    public String generateToken(UserDetails user) {
        Date now = new Date();
        List<String> roles = user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)   // e.g. "ROLE_ADMIN"
                .toList();

        return Jwts.builder()
                .subject(user.getUsername())           // "sub" claim
                .claim("roles", roles)                 // custom claim
                .issuedAt(now)                         // "iat"
                .expiration(new Date(now.getTime() + expirationMs))   // "exp"
                .signWith(key)                         // HS256 chosen from key size
                .compact();                            // header.payload.signature
    }

    /** Verify signature and expiry, then return the claims.
     *  Throws JwtException if the token is tampered, malformed or expired. */
    public Claims parse(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String extractUsername(String token) {
        return parse(token).getSubject();
    }

}
