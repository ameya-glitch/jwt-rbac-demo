package com.example.security.jwt.controller;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import com.example.security.jwt.config.SecurityConfig;
import com.example.security.jwt.service.JwtService;

@WebMvcTest(DemoController.class)
@Import(SecurityConfig.class)
class DemoControllerTest {

    @Autowired MockMvc mvc;

    // JwtAuthFilter (loaded by the slice) needs a JwtService. Here the tests
    // use @WithMockUser instead of real tokens, so a mock is enough.
    @MockitoBean JwtService jwtService;

    @Test
    void publicEndpoint_noLogin_returns200() throws Exception {
        mvc.perform(get("/api/public/hello"))
                .andExpect(status().isOk())
                .andExpect(content().string("Hello, anyone"));
    }

    @Test
    void protectedEndpoint_noLogin_returns401() throws Exception {
        mvc.perform(get("/api/user/me")).andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "alice", roles = "USER")   // simulates a logged-in USER
    void protectedEndpoint_asUser_returns200() throws Exception {
        mvc.perform(get("/api/user/me")).andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "alice", roles = "USER")
    void adminEndpoint_asUser_returns403() throws Exception {
        mvc.perform(get("/api/admin/dashboard")).andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "root", roles = "ADMIN")
    void adminEndpoint_asAdmin_returns200() throws Exception {
        mvc.perform(get("/api/admin/dashboard")).andExpect(status().isOk());
    }
}