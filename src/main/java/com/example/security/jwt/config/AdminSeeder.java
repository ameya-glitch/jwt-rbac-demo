package com.example.security.jwt.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.example.security.jwt.model.AppUser;
import com.example.security.jwt.model.Role;
import com.example.security.jwt.repository.UserRepository;

@Component
public class AdminSeeder implements CommandLineRunner {   // runs once at startup

    private final UserRepository repo;
    private final PasswordEncoder encoder;

    public AdminSeeder(UserRepository repo, PasswordEncoder encoder) {
        this.repo = repo;
        this.encoder = encoder;
    }

    @Override
    public void run(String... args) {
        if (!repo.existsByUsername("admin")) {   // idempotent: safe on every restart
            AppUser admin = new AppUser();
            admin.setUsername("admin");
            admin.setPassword(encoder.encode("admin123"));   // demo only
            admin.setRole(Role.ADMIN);
            repo.save(admin);
        }
    }
}