package com.example.auth_service.service;

import com.example.auth_service.dto.*;
import com.example.auth_service.exception.InvalidCredentialsException;
import com.example.auth_service.exception.InvalidTokenException;
import com.example.auth_service.exception.UserAlreadyExistsException;
import com.example.auth_service.model.Role;
import com.example.auth_service.model.UserCredential;
import com.example.auth_service.repository.UserCredentialRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserCredentialRepository userCredentialRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    @Override
    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userCredentialRepository.existsByLogin(request.getLogin())) {
            throw new UserAlreadyExistsException(request.getLogin());
        }

        UserCredential credential = UserCredential.builder()
                .login(request.getLogin())
                .password(passwordEncoder.encode(request.getPassword()))
                .userId(request.getUserId())
                .role(Role.USER)
                .build();

        userCredentialRepository.save(credential);

        String accessToken = jwtService.generateAccessToken(credential.getUserId(), credential.getRole().name());
        String refreshToken = jwtService.generateRefreshToken(credential.getUserId(), credential.getRole().name());

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    @Override
    public AuthResponse createToken(AuthRequest request) {
        UserCredential credential = userCredentialRepository.findByLogin(request.getLogin())
                .orElseThrow(() -> new InvalidCredentialsException("Invalid login or password"));

        if (!passwordEncoder.matches(request.getPassword(), credential.getPassword())) {
            throw new InvalidCredentialsException("Invalid login or password");
        }

        String accessToken = jwtService.generateAccessToken(credential.getUserId(), credential.getRole().name());
        String refreshToken = jwtService.generateRefreshToken(credential.getUserId(), credential.getRole().name());

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    @Override
    public TokenValidationResponse validateToken(TokenValidationRequest request) {
        String token = request.getToken();
        boolean valid = jwtService.validateToken(token);

        if (!valid) {
            return TokenValidationResponse.builder()
                    .valid(false)
                    .build();
        }

        return TokenValidationResponse.builder()
                .valid(true)
                .userId(jwtService.extractUserId(token))
                .role(jwtService.extractRole(token))
                .build();
    }

    @Override
    public AuthResponse refreshToken(RefreshTokenRequest request) {
        String refreshToken = request.getRefreshToken();

        if (!jwtService.validateToken(refreshToken)) {
            throw new InvalidTokenException("Invalid or expired refresh token");
        }

        String tokenType = jwtService.extractTokenType(refreshToken);
        if (!"REFRESH".equals(tokenType)) {
            throw new InvalidTokenException("Provided token is not a refresh token");
        }

        Long userId = jwtService.extractUserId(refreshToken);
        String role = jwtService.extractRole(refreshToken);

        String newAccessToken = jwtService.generateAccessToken(userId, role);
        String newRefreshToken = jwtService.generateRefreshToken(userId, role);

        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .build();
    }
}