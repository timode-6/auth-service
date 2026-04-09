package com.innowise.auth_service.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.innowise.auth_service.filter.JwtAuthenticationFilter;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class SecurityConfigTest {

    @Mock
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    private SecurityConfig securityConfig;

    @BeforeEach
    void setUp() {
        securityConfig = new SecurityConfig(jwtAuthenticationFilter);
    }


    @Test
    void passwordEncoder_ShouldReturnBCryptPasswordEncoder() {
        PasswordEncoder encoder = securityConfig.passwordEncoder();
        assertThat(encoder).isInstanceOf(BCryptPasswordEncoder.class);
    }

    @Test
    void passwordEncoder_ShouldSuccessfullyEncodePassword() {
        PasswordEncoder encoder = securityConfig.passwordEncoder();
        String raw = "testPassword123";

        String encoded = encoder.encode(raw);

        assertThat(!encoded.isEmpty() && !encoded.equals(raw)).isTrue();
    }

    @Test
    void passwordEncoder_EncodedPassword_ShouldMatchOriginal() {
        PasswordEncoder encoder = securityConfig.passwordEncoder();
        String raw = "testPassword123";

        String encoded = encoder.encode(raw);

        assertThat(encoder.matches(raw, encoded)).isTrue();
    }

    @Test
    void passwordEncoder_ShouldGenerateUniqueSaltPerEncoding() {
        PasswordEncoder encoder = securityConfig.passwordEncoder();
        String raw = "samePassword";

        String firstEncoding = encoder.encode(raw);
        String secondEncoding = encoder.encode(raw);

        assertThat(firstEncoding).isNotEqualTo(secondEncoding);
        assertThat(encoder.matches(raw, firstEncoding)).isTrue();
        assertThat(encoder.matches(raw, secondEncoding)).isTrue();
    }

    @Test
    void passwordEncoder_WrongPassword_ShouldNotMatch() {
        PasswordEncoder encoder = securityConfig.passwordEncoder();

        String encoded = encoder.encode("correctPassword");

        assertThat(encoder.matches("wrongPassword", encoded)).isFalse();
    }

    @Test
    void passwordEncoder_ShouldBeSingletonSafe_ReturnFreshInstanceEachCall() {
        PasswordEncoder first = securityConfig.passwordEncoder();
        PasswordEncoder second = securityConfig.passwordEncoder();

        String encoded = first.encode("password");
        assertThat(second.matches("password", encoded)).isTrue();
    }
}