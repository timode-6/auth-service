package com.innowise.auth_service.service;

import com.innowise.auth_service.dto.*;

/**
 * Core authentication service.
 *
 * <p>Handles the full lifecycle of user credentials and JWT tokens:
 * registration, authentication, token validation, and token rotation.
 * All token operations use a shared HMAC-SHA256 signing key configured
 * via {@code jwt.secret} in {@code application.yml}.
 *
 * <p>Token anatomy:
 * <pre>
 *   Subject  – userId (Long, stored as String)
 *   Claims   – "role"  : the user's authority (e.g. "USER", "ADMIN")
 *              "type"  : "ACCESS" | "REFRESH"
 * </pre>
 *
 * <p>Implementations must be stateless with respect to token storage —
 * revocation is delegated to a Redis blacklist maintained by the API Gateway.
 */
public interface AuthService {

    /**
     * Registers a new user, persists BCrypt-hashed credentials, and returns
     * an initial JWT token pair.
     *
     * <p>The login field is treated as a unique identifier. If it is already
     * present in the data store a {@code UserAlreadyExistsException} is thrown
     * and no token is issued.
     *
     * @param request registration payload; must contain a non-blank {@code login}
     *                and a {@code password} that satisfies the configured
     *                complexity rules
     * @return an {@link AuthResponse} holding a short-lived {@code accessToken}
     *         and a long-lived {@code refreshToken}
     * @throws com.innowise.auth_service.exception.UserAlreadyExistsException
     *         if {@code request.getLogin()} is already registered
     */
    AuthResponse register(RegisterRequest request);

    /**
     * Authenticates a user by verifying the supplied plaintext password against
     * the stored BCrypt hash, then issues a fresh JWT token pair.
     *
     * <p>Both "user not found" and "wrong password" conditions raise the same
     * exception with the same message to prevent user-enumeration attacks.
     *
     * @param request authentication payload containing {@code login} and
     *                {@code password}
     * @return an {@link AuthResponse} holding a new {@code accessToken} and
     *         {@code refreshToken}
     * @throws com.innowise.auth_service.exception.InvalidCredentialsException
     *         if the login does not exist or the password does not match
     */
    AuthResponse createToken(AuthRequest request);

    /**
     * Verifies a JWT token's signature, structure, and expiry without throwing
     * an exception on failure.
     *
     * <p>Returns a result object rather than throwing so that callers can make
     * a policy decision (redirect, 401, partial response) based on the
     * {@code valid} flag. When {@code valid} is {@code true} the response also
     * carries the {@code userId} and {@code role} extracted from the token
     * payload, avoiding a second database round-trip for the caller.
     *
     * @param request payload wrapping the raw JWT string to inspect
     * @return a {@link TokenValidationResponse} where {@code valid == true}
     *         means the token is structurally sound and not yet expired;
     *         {@code userId} and {@code role} are populated only when valid
     */
    TokenValidationResponse validateToken(TokenValidationRequest request);

    /**
     * Issues a new token pair in exchange for a valid, non-expired refresh token.
     *
     * <p>Validation rules applied before rotation:
     * <ol>
     *   <li>Signature must be valid</li>
     *   <li>Token must not be expired</li>
     *   <li>The {@code type} claim must equal {@code "REFRESH"} — submitting
     *       an access token is explicitly rejected</li>
     * </ol>
     *
     * <p>The {@code userId} and {@code role} claims are forwarded from the
     * incoming refresh token into both new tokens, so role changes made after
     * the original login take effect only at next full re-authentication.
     *
     * @param request payload containing the {@code refreshToken} string
     * @return an {@link AuthResponse} with a new {@code accessToken} and a
     *         new {@code refreshToken}; the old refresh token is not explicitly
     *         invalidated here — the API Gateway's Redis blacklist handles that
     * @throws com.innowise.auth_service.exception.InvalidTokenException
     *         if the token is expired, has an invalid signature, or has
     *         {@code type != "REFRESH"}
     */
    AuthResponse refreshToken(RefreshTokenRequest request);

    /**
     * Registers a new account with a caller-specified role.
     *
     * <p>This method must only be invoked from a controller method annotated
     * with {@code @PreAuthorize("hasRole('ADMIN')")}. It is the only path
     * through which a new {@code ADMIN} account can be created at runtime.
     *
     * <p>Typical uses:
     * <ul>
     *   <li>Provisioning additional admin accounts after the bootstrap admin
     *       has been seeded via {@code admin.bootstrap.*} properties.</li>
     *   <li>Creating service-account credentials with a specific role for
     *       internal microservice authentication.</li>
     * </ul>
     *
     * @param request registration payload including the target {@link
     *                com.innowise.auth_service.model.Role}; defaults to
     *                {@code USER} if the field is omitted
     * @return an {@link AuthResponse} containing {@code accessToken} and
     *         {@code refreshToken} for the new account
     * @throws com.innowise.auth_service.exception.UserAlreadyExistsException
     *         if {@code request.getLogin()} is already taken
     */
    AuthResponse registerAdmin(AdminRegisterRequest request);
}