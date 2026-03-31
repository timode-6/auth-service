package com.example.auth_service.controller;

import com.example.auth_service.dto.*;
import com.example.auth_service.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        AuthResponse response = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/token")
    public ResponseEntity<AuthResponse> createToken(@Valid @RequestBody AuthRequest request) {
        AuthResponse response = authService.createToken(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/token/validate")
    public ResponseEntity<TokenValidationResponse> validateToken(
            @Valid @RequestBody TokenValidationRequest request) {
        TokenValidationResponse response = authService.validateToken(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/token/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        AuthResponse response = authService.refreshToken(request);
        return ResponseEntity.ok(response);
    }
}