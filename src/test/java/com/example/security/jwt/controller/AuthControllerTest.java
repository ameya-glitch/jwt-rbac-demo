package com.example.security.jwt.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import com.example.security.jwt.config.SecurityConfig;
import com.example.security.jwt.model.AppUser;
import com.example.security.jwt.repository.UserRepository;
import com.example.security.jwt.service.JwtService;

@WebMvcTest(AuthController.class)   // loads ONLY the web layer + this controller
@Import({SecurityConfig.class, GlobalExceptionHandler.class})   // slices skip @Configuration, so import it
class AuthControllerTest {

    @Autowired MockMvc mvc;

    // Fake the collaborators: no DB, no real password check, no real tokens
    @MockitoBean UserRepository repo;
    @MockitoBean JwtService jwtService;
    @MockitoBean AuthenticationManager authManager;

    private static final String VALID_BODY = "{\"username\":\"alice\",\"password\":\"pw12345\"}";

    @Test
    void register_newUser_returns201() throws Exception {
        when(repo.existsByUsername("alice")).thenReturn(false);

        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON).content(VALID_BODY))
                .andExpect(status().isCreated());

        verify(repo).save(any(AppUser.class));
    }

    @Test
    void register_existingUsername_returns409() throws Exception {
        when(repo.existsByUsername("alice")).thenReturn(true);

        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON).content(VALID_BODY))
                .andExpect(status().isConflict());
    }

    @Test
    void register_blankUsername_returns400() throws Exception {
        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"\",\"password\":\"pw12345\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void login_validCredentials_returnsToken() throws Exception {
        UserDetails principal = User.withUsername("alice").password("x").roles("USER").build();
        when(authManager.authenticate(any()))
                .thenReturn(new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities()));
        when(jwtService.generateToken(any(UserDetails.class))).thenReturn("fake.jwt.token");

        mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON).content(VALID_BODY))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("fake.jwt.token"));
    }

    @Test
    void login_wrongPassword_returns401() throws Exception {
        when(authManager.authenticate(any())).thenThrow(new BadCredentialsException("bad"));

        mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON).content(VALID_BODY))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("Invalid username or password"));
    }
}