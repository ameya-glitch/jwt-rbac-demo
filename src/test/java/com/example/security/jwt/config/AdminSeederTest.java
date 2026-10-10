package com.example.security.jwt.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.example.security.jwt.model.AppUser;
import com.example.security.jwt.model.Role;
import com.example.security.jwt.repository.UserRepository;

@ExtendWith(MockitoExtension.class)
class AdminSeederTest {

    @Mock UserRepository repo;
    @Mock PasswordEncoder encoder;
    @InjectMocks AdminSeeder seeder;

    @Test
    void noAdminYet_savesAdminWithEncodedPassword() {
        when(repo.existsByUsername("admin")).thenReturn(false);
        when(encoder.encode("admin123")).thenReturn("ENCODED");

        seeder.run();

        // The captor grabs the object that was passed to repo.save(...), so we can inspect it
        ArgumentCaptor<AppUser> captor = ArgumentCaptor.forClass(AppUser.class);
        verify(repo).save(captor.capture());
        AppUser saved = captor.getValue();

        assertThat(saved.getUsername()).isEqualTo("admin");
        assertThat(saved.getPassword()).isEqualTo("ENCODED");   // never the plain text
        assertThat(saved.getRole()).isEqualTo(Role.ADMIN);
    }

    @Test
    void adminAlreadyExists_doesNotSaveAgain() {
        when(repo.existsByUsername("admin")).thenReturn(true);

        seeder.run();

        verify(repo, never()).save(any());
    }
}