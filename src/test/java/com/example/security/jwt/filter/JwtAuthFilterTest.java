package com.example.security.jwt.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import com.example.security.jwt.service.JwtService;

import jakarta.servlet.FilterChain;

class JwtAuthFilterTest {

    private static final String SECRET = Base64.getEncoder().encodeToString(
            "test-secret-key-must-be-at-least-32-bytes-long!".getBytes(StandardCharsets.UTF_8));

    private final JwtService jwtService = new JwtService(SECRET, 60_000);
    private final JwtAuthFilter filter = new JwtAuthFilter(jwtService);

    private final MockHttpServletRequest request = new MockHttpServletRequest();
    private final MockHttpServletResponse response = new MockHttpServletResponse();
    private final FilterChain chain = mock(FilterChain.class);   // fake chain that records calls

    @AfterEach
    void cleanUp() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void validToken_setsAuthenticationWithRoles() throws Exception {
        UserDetails admin = User.withUsername("admin").password("x").roles("ADMIN").build();
        request.addHeader("Authorization", "Bearer " + jwtService.generateToken(admin));

        filter.doFilter(request, response, chain);

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(auth).isNotNull();
        assertThat(auth.getName()).isEqualTo("admin");
        assertThat(auth.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_ADMIN");
        verify(chain).doFilter(request, response);   // the chain continued
    }

    @Test
    void noHeader_leavesRequestUnauthenticated() throws Exception {
        filter.doFilter(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(chain).doFilter(request, response);
    }

    @Test
    void garbageToken_leavesRequestUnauthenticated() throws Exception {
        request.addHeader("Authorization", "Bearer abc.def.ghi");

        filter.doFilter(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(chain).doFilter(request, response);   // filter never blocks, it only identifies
    }

    @Test
    void nonBearerHeader_isIgnored() throws Exception {
        request.addHeader("Authorization", "Basic dXNlcjpwYXNz");

        filter.doFilter(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(chain).doFilter(request, response);
    }
}