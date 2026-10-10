package com.example.security.jwt.filter;

import java.io.IOException;
import java.util.List;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.security.jwt.service.JwtService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {   // runs once per request

    private final JwtService jwtService;

    public JwtAuthFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        String header = request.getHeader("Authorization");

        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);   // drop the "Bearer " prefix
            try {
                Claims claims = jwtService.parse(token);   // verifies signature + expiry

                // Turn the "roles" claim (["ROLE_ADMIN"]) into Spring authorities
                List<SimpleGrantedAuthority> authorities = extractAuthorities(claims);

                // Mark this request as authenticated for the rest of its life
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(claims.getSubject(), null, authorities);
                SecurityContextHolder.getContext().setAuthentication(authentication);

            } catch (JwtException | IllegalArgumentException e) {
                // Bad, tampered or expired token: stay unauthenticated
                SecurityContextHolder.clearContext();
            }
        }

        // ALWAYS continue the chain, so later filters and the controller still run
        chain.doFilter(request, response);
    }

    private List<SimpleGrantedAuthority> extractAuthorities(Claims claims) {
        Object roles = claims.get("roles");
        if (roles instanceof List<?> list) {
            return list.stream()
                    .map(role -> new SimpleGrantedAuthority(role.toString()))
                    .toList();
        }
        return List.of();
    }
}