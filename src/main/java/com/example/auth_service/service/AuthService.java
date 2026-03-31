package com.example.auth_service.service;

import com.example.auth_service.dto.*;

public interface AuthService {

    AuthResponse register(RegisterRequest request);

    AuthResponse createToken(AuthRequest request);

    TokenValidationResponse validateToken(TokenValidationRequest request);

    AuthResponse refreshToken(RefreshTokenRequest request);
}