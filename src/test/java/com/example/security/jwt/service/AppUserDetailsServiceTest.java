package com.example.security.jwt.service;

import com.example.security.jwt.model.AppUser;
import com.example.security.jwt.model.Role;
import com.example.security.jwt.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Optional;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class AppUserDetailsServiceTest {

    @Mock
    UserRepository repository;

    @InjectMocks
    AppUserDetailsService service;

    @Test
    void existingUser_isMappedToUserDetailsWithRoleAuthority(){
        // Arrange
        AppUser user = new AppUser();
        user.setUsername("kevin");
        user.setPassword("$2a$10$fakeHashForTest");
        user.setRole(Role.ADMIN);
        when(repository.findByUsername("kevin")).thenReturn(Optional.of(user));

        // Act
        UserDetails result = service.loadUserByUsername("kevin");

        //assert
        assertThat(result.getUsername()).isEqualTo("kevin");
        assertThat(result.getPassword()).isEqualTo("$2a$10$fakeHashForTest");
        assertThat(result.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_ADMIN");
        verify(repository).findByUsername("kevin");
    }

    @Test
    void unknownUser_throwsUserNameNotFoundException() {
        when(repository.findByUsername("ghost")).thenReturn(Optional.empty());

        assertThrows(UsernameNotFoundException.class,
                () -> service.loadUserByUsername("ghost"));
    }

}
