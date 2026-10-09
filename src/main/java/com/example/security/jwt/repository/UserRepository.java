package com.example.security.jwt.repository;

import com.example.security.jwt.model.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<AppUser, Long> {

    // SELECT * FROM users WHERE username = ?
    Optional<AppUser> findByUsername(String username);

    // SELECT COUNT(*) > 0 FROM users WHERE username = ?
    boolean existsByUsername(String username);
}
