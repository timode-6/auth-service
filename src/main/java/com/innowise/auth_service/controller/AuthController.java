package com.innowise.auth_service.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.innowise.auth_service.dto.*;
import com.innowise.auth_service.service.AuthService;

import org.springframework.security.access.prepost.PreAuthorize;

/**
 * REST controller exposing authentication endpoints.
 *
 * <p>All endpoints are public (no JWT required) and are routed through the
 * API Gateway. The gateway's {@code JwtAuthenticationFilter} is bypassed for
 * every path under {@code /api/auth/**}.
 *
 * <p>Base path: {@code /api/auth}
 *
 * <p>Endpoint summary:
 * <pre>
 *   POST /api/auth/register        – register a new user and return a token pair
 *   POST /api/auth/token           – authenticate and return a token pair
 *   POST /api/auth/token/validate  – verify a token's signature and expiry
 *   POST /api/auth/token/refresh   – rotate a token pair using a refresh token
 * </pre>
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * Registers a new user and issues an initial JWT token pair.
     *
     * <p>The login (email) must be unique across the system. If it already
     * exists a {@code 409 Conflict} is returned. The password is hashed with
     * BCrypt before being stored — the plain-text value is never persisted.
     *
     * @param request validated registration payload containing login and password
     * @return {@code 201 Created} with an {@link AuthResponse} containing
     *         {@code accessToken} and {@code refreshToken} on success;
     *         {@code 409 Conflict} if the login is already taken;
     *         {@code 400 Bad Request} if validation fails
     */
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        AuthResponse response = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Authenticates a user by credentials and issues a JWT token pair.
     *
     * <p>Both the login and the BCrypt-hashed password are verified. A generic
     * error message is returned for both "user not found" and "wrong password"
     * cases to prevent user-enumeration attacks.
     *
     * @param request validated payload containing {@code login} and {@code password}
     * @return {@code 200 OK} with an {@link AuthResponse} containing
     *         {@code accessToken} and {@code refreshToken} on success;
     *         {@code 401 Unauthorized} if credentials are invalid;
     *         {@code 400 Bad Request} if validation fails
     */
    @PostMapping("/token")
    public ResponseEntity<AuthResponse> createToken(@Valid @RequestBody AuthRequest request) {
        AuthResponse response = authService.createToken(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Validates a JWT token's signature, structure, and expiry.
     *
     * <p>This endpoint is intended for internal use by other microservices or
     * the API Gateway to verify tokens without sharing the signing secret.
     * It does <em>not</em> check a revocation list — combine with a Redis
     * blacklist check on the gateway side for full revocation support.
     *
     * @param request payload containing the {@code token} string to verify
     * @return {@code 200 OK} with a {@link TokenValidationResponse}; the
     *         {@code valid} field is {@code true} when the token is usable,
     *         accompanied by {@code userId} and {@code role} claims extracted
     *         from the payload; {@code valid} is {@code false} when the token
     *         is expired, malformed, or has an invalid signature —
     *         no error status is thrown in that case, allowing callers to
     *         branch on the boolean themselves
     */
    @PostMapping("/token/validate")
    public ResponseEntity<TokenValidationResponse> validateToken(
            @Valid @RequestBody TokenValidationRequest request) {
        TokenValidationResponse response = authService.validateToken(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Rotates a JWT token pair by exchanging a valid refresh token for a new
     * access token and a new refresh token.
     *
     * <p>The provided token must satisfy all of the following:
     * <ul>
     *   <li>Valid signature</li>
     *   <li>Not yet expired</li>
     *   <li>Claim {@code type == "REFRESH"} — access tokens are explicitly rejected</li>
     * </ul>
     *
     * <p>After a successful rotation the old refresh token should be considered
     * spent; re-using it will succeed until it expires unless a revocation list
     * is maintained.
     *
     * @param request payload containing the {@code refreshToken} string
     * @return {@code 200 OK} with a new {@link AuthResponse} token pair on success;
     *         {@code 401 Unauthorized} if the token is expired, invalid, or is
     *         an access token rather than a refresh token
     */
    @PostMapping("/token/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        AuthResponse response = authService.refreshToken(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Creates a new account with a caller-specified role. Requires the caller
     * to hold a valid JWT with role {@code ADMIN}.
     *
     * <p>This is the <em>only</em> runtime path for provisioning admin accounts.
     * The initial (bootstrap) admin is created at application startup by
     * {@link com.innowise.auth_service.config.AdminBootstrapConfig} when the
     * {@code admin.bootstrap.enabled=true} property is set.
     *
     * <p>Security layers:
     * <ol>
     *   <li>URL-level: {@code .requestMatchers("/api/auth/admin/**").hasRole("ADMIN")}
     *       in {@link com.innowise.auth_service.config.SecurityConfig}</li>
     *   <li>Method-level: {@code @PreAuthorize("hasRole('ADMIN')")} on
     *       {@link com.innowise.auth_service.service.AuthServiceImpl#registerAdmin}</li>
     * </ol>
     *
     * @param request validated payload including target {@code role}
     *                ({@code USER} or {@code ADMIN}); role defaults to
     *                {@code USER} when omitted
     * @return {@code 201 Created} with an {@link AuthResponse} token pair for
     *         the new account;
     *         {@code 401 Unauthorized} if no valid JWT is supplied;
     *         {@code 403 Forbidden} if the JWT does not carry {@code ADMIN} role;
     *         {@code 409 Conflict} if the login is already registered
     */
    @PostMapping("/admin/register")
    @PreAuthorize("hasRole('ADMIN')")   
    public ResponseEntity<AuthResponse> registerAdmin(
            @Valid @RequestBody AdminRegisterRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.registerAdmin(request));
    }
}