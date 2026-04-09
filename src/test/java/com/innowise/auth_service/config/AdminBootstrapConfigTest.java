package com.innowise.auth_service.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import com.innowise.auth_service.model.Role;
import com.innowise.auth_service.model.UserCredential;
import com.innowise.auth_service.repository.UserCredentialRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AdminBootstrapConfigTest {

    @Mock
    private UserCredentialRepository userCredentialRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    private AdminBootstrapConfig config;

    @BeforeEach
    void setUp() {
        config = new AdminBootstrapConfig(userCredentialRepository, passwordEncoder);
        ReflectionTestUtils.setField(config, "bootstrapLogin", "admin");
        ReflectionTestUtils.setField(config, "bootstrapPassword", "admin123");
        ReflectionTestUtils.setField(config, "bootstrapUserId", 1L);
    }


    @Test
    void run_WhenAdminNotExists_ShouldSaveAdminCredential(){
        when(userCredentialRepository.existsByLogin("admin")).thenReturn(false);
        when(passwordEncoder.encode("admin123")).thenReturn("$2a$hashed");

        config.run(new DefaultApplicationArguments());

        ArgumentCaptor<UserCredential> captor = ArgumentCaptor.forClass(UserCredential.class);
        verify(userCredentialRepository).save(captor.capture());

        UserCredential saved = captor.getValue();
        assertThat(saved.getLogin()).isEqualTo("admin");
        assertThat(saved.getPassword()).isEqualTo("$2a$hashed");
        assertThat(saved.getUserId()).isEqualTo(1L);
        assertThat(saved.getRole()).isEqualTo(Role.ADMIN);
    }

    @Test
    void run_WhenAdminNotExists_ShouldEncodePassword(){
        when(userCredentialRepository.existsByLogin("admin")).thenReturn(false);
        when(passwordEncoder.encode("admin123")).thenReturn("$2a$hashed");

        config.run(new DefaultApplicationArguments());

        verify(passwordEncoder).encode("admin123");
    }


    @Test
    void run_WhenAdminAlreadyExists_ShouldNotSaveAnything(){
        when(userCredentialRepository.existsByLogin("admin")).thenReturn(true);

        config.run(new DefaultApplicationArguments());

        verify(userCredentialRepository, never()).save(any());
        verifyNoInteractions(passwordEncoder);
    }


    @Test
    void run_CalledTwice_WhenAdminCreatedOnFirstRun_ShouldSaveOnlyOnce(){
        when(userCredentialRepository.existsByLogin("admin"))
                .thenReturn(false)  
                .thenReturn(true); 
        when(passwordEncoder.encode(any())).thenReturn("$2a$hashed");

        config.run(new DefaultApplicationArguments());
        config.run(new DefaultApplicationArguments());

        verify(userCredentialRepository, times(1)).save(any());
    }


    @Test
    void run_SavedCredential_ShouldAlwaysHaveAdminRole(){
        when(userCredentialRepository.existsByLogin("admin")).thenReturn(false);
        when(passwordEncoder.encode(any())).thenReturn("hash");

        config.run(new DefaultApplicationArguments());

        ArgumentCaptor<UserCredential> captor = ArgumentCaptor.forClass(UserCredential.class);
        verify(userCredentialRepository).save(captor.capture());
        assertThat(captor.getValue().getRole()).isEqualTo(Role.ADMIN);
    }


    @Test
    void run_ShouldUseConfiguredLoginAndUserId(){
        ReflectionTestUtils.setField(config, "bootstrapLogin", "superadmin");
        ReflectionTestUtils.setField(config, "bootstrapUserId", 99L);
        when(userCredentialRepository.existsByLogin("superadmin")).thenReturn(false);
        when(passwordEncoder.encode(any())).thenReturn("hash");

        config.run(new DefaultApplicationArguments());

        ArgumentCaptor<UserCredential> captor = ArgumentCaptor.forClass(UserCredential.class);
        verify(userCredentialRepository).save(captor.capture());
        assertThat(captor.getValue().getLogin()).isEqualTo("superadmin");
        assertThat(captor.getValue().getUserId()).isEqualTo(99L);
    }
}