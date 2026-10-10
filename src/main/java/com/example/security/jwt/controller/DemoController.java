package com.example.security.jwt.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {

    @GetMapping("/api/public/hello")
    public String hello() {
        return "Hello, anyone";
    }

    @GetMapping("/api/user/me")
    public String me(Authentication authentication) {
        return "Hi " + authentication.getName() + " " + authentication.getAuthorities();
    }

    @GetMapping("/api/admin/dashboard")
    public String adminDashboard() {
        return "Admin only data";
    }
}