package com.innowise.auth_service.unit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.innowise.auth_service.dto.*;
import com.innowise.auth_service.exception.InvalidCredentialsException;
import com.innowise.auth_service.exception.InvalidTokenException;
import com.innowise.auth_service.exception.UserAlreadyExistsException;
import com.innowise.auth_service.model.Role;
import com.innowise.auth_service.model.UserCredential;
import com.innowise.auth_service.repository.UserCredentialRepository;
import com.innowise.auth_service.service.*;

import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    @Mock
    private UserCredentialRepository userCredentialRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @InjectMocks
    private AuthServiceImpl authService;

    @Test
    void register_WithNewUser_ShouldReturnTokens() {
        RegisterRequest request = RegisterRequest.builder()
                .login("testuser")
                .password("password123")
                .userId(10L)
                .build();

        when(userCredentialRepository.existsByLogin("testuser")).thenReturn(false);
        when(passwordEncoder.encode("password123")).thenReturn("$2a$10$hashed");
        when(userCredentialRepository.save(any(UserCredential.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(jwtService.generateAccessToken(10L, "USER")).thenReturn("access-token");
        when(jwtService.generateRefreshToken(10L, "USER")).thenReturn("refresh-token");

        AuthResponse response = authService.register(request);

        assertThat(response.getAccessToken()).isEqualTo("access-token");
        assertThat(response.getRefreshToken()).isEqualTo("refresh-token");
        verify(userCredentialRepository).save(any(UserCredential.class));
    }

    @Test
    void register_WithExistingLogin_ShouldThrowException() {
        RegisterRequest request = RegisterRequest.builder()
                .login("existing")
                .password("pass")
                .userId(1L)
                .build();

        when(userCredentialRepository.existsByLogin("existing")).thenReturn(true);

        assertThatThrownBy(() -> authService.register(request))
                .isInstanceOf(UserAlreadyExistsException.class);
    }

    @Test
    void createToken_WithValidCredentials_ShouldReturnTokens() {
        AuthRequest request = AuthRequest.builder()
                .login("user1")
                .password("pass")
                .build();

        UserCredential credential = UserCredential.builder()
                .login("user1")
                .password("$2a$10$hashed")
                .userId(5L)
                .role(Role.USER)
                .build();

        when(userCredentialRepository.findByLogin("user1")).thenReturn(Optional.of(credential));
        when(passwordEncoder.matches("pass", "$2a$10$hashed")).thenReturn(true);
        when(jwtService.generateAccessToken(5L, "USER")).thenReturn("access-token");
        when(jwtService.generateRefreshToken(5L, "USER")).thenReturn("refresh-token");

        AuthResponse response = authService.createToken(request);

        assertThat(response.getAccessToken()).isEqualTo("access-token");
        assertThat(response.getRefreshToken()).isEqualTo("refresh-token");
    }

    @Test
    void createToken_WithWrongPassword_ShouldThrowException() {
        AuthRequest request = AuthRequest.builder()
                .login("user1")
                .password("wrong")
                .build();

        UserCredential credential = UserCredential.builder()
                .login("user1")
                .password("$2a$10$hashed")
                .userId(5L)
                .role(Role.USER)
                .build();

        when(userCredentialRepository.findByLogin("user1")).thenReturn(Optional.of(credential));
        when(passwordEncoder.matches("wrong", "$2a$10$hashed")).thenReturn(false);

        assertThatThrownBy(() -> authService.createToken(request))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void createToken_WithNonExistentUser_ShouldThrowException() {
        AuthRequest request = AuthRequest.builder()
                .login("ghost")
                .password("pass")
                .build();

        when(userCredentialRepository.findByLogin("ghost")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.createToken(request))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void validateToken_WithValidToken_ShouldReturnValidResponse() {
        TokenValidationRequest request = TokenValidationRequest.builder()
                .token("valid-token")
                .build();

        when(jwtService.validateToken("valid-token")).thenReturn(true);
        when(jwtService.extractUserId("valid-token")).thenReturn(5L);
        when(jwtService.extractRole("valid-token")).thenReturn("USER");

        TokenValidationResponse response = authService.validateToken(request);

        assertThat(response.isValid()).isTrue();
        assertThat(response.getUserId()).isEqualTo(5L);
        assertThat(response.getRole()).isEqualTo("USER");
    }

    @Test
    void validateToken_WithInvalidToken_ShouldReturnInvalidResponse() {
        TokenValidationRequest request = TokenValidationRequest.builder()
                .token("bad-token")
                .build();

        when(jwtService.validateToken("bad-token")).thenReturn(false);

        TokenValidationResponse response = authService.validateToken(request);

        assertThat(response.isValid()).isFalse();
        assertThat(response.getUserId()).isNull();
    }

    @Test
    void refreshToken_WithValidRefreshToken_ShouldReturnNewTokens() {
        RefreshTokenRequest request = RefreshTokenRequest.builder()
                .refreshToken("valid-refresh")
                .build();

        when(jwtService.validateToken("valid-refresh")).thenReturn(true);
        when(jwtService.extractTokenType("valid-refresh")).thenReturn("REFRESH");
        when(jwtService.extractUserId("valid-refresh")).thenReturn(5L);
        when(jwtService.extractRole("valid-refresh")).thenReturn("USER");
        when(jwtService.generateAccessToken(5L, "USER")).thenReturn("new-access");
        when(jwtService.generateRefreshToken(5L, "USER")).thenReturn("new-refresh");

        AuthResponse response = authService.refreshToken(request);

        assertThat(response.getAccessToken()).isEqualTo("new-access");
        assertThat(response.getRefreshToken()).isEqualTo("new-refresh");
    }

    @Test
    void refreshToken_WithInvalidToken_ShouldThrowException() {
        RefreshTokenRequest request = RefreshTokenRequest.builder()
                .refreshToken("invalid")
                .build();

        when(jwtService.validateToken("invalid")).thenReturn(false);

        assertThatThrownBy(() -> authService.refreshToken(request))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void refreshToken_WithAccessTokenInstead_ShouldThrowException() {
        RefreshTokenRequest request = RefreshTokenRequest.builder()
                .refreshToken("access-token-not-refresh")
                .build();

        when(jwtService.validateToken("access-token-not-refresh")).thenReturn(true);
        when(jwtService.extractTokenType("access-token-not-refresh")).thenReturn("ACCESS");

        assertThatThrownBy(() -> authService.refreshToken(request))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("not a refresh token");
    }
}