package com.example.auth_service.unit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

import com.example.auth_service.service.*;

class JwtServiceTest {

    private JwtService jwtService;

    private static final String TEST_SECRET =
            "dGVzdFNlY3JldEtleUZvckpXVFRva2VuU2lnbmluZzEyMzQ1Njc4OTBBQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFla";

    @BeforeEach
    void setUp() {
        jwtService = new JwtService(TEST_SECRET, 3600000L, 86400000L);
    }

    @Test
    void generateAccessToken_ShouldContainUserIdAndRole() {
        String token = jwtService.generateAccessToken(42L, "USER");

        assertThat(token).isNotBlank();
        assertThat(jwtService.extractUserId(token)).isEqualTo(42L);
        assertThat(jwtService.extractRole(token)).isEqualTo("USER");
        assertThat(jwtService.extractTokenType(token)).isEqualTo("ACCESS");
    }

    @Test
    void generateRefreshToken_ShouldContainUserIdAndRefreshType() {
        String token = jwtService.generateRefreshToken(42L, "ADMIN");

        assertThat(token).isNotBlank();
        assertThat(jwtService.extractUserId(token)).isEqualTo(42L);
        assertThat(jwtService.extractRole(token)).isEqualTo("ADMIN");
        assertThat(jwtService.extractTokenType(token)).isEqualTo("REFRESH");
    }

    @Test
    void validateToken_WithValidToken_ShouldReturnTrue() {
        String token = jwtService.generateAccessToken(1L, "USER");

        assertThat(jwtService.validateToken(token)).isTrue();
    }

    @Test
    void validateToken_WithInvalidToken_ShouldReturnFalse() {
        assertThat(jwtService.validateToken("__invalid__")).isFalse();
    }

    @Test
    void validateToken_WithNullToken_ShouldReturnFalse() {
        assertThat(jwtService.validateToken(null)).isFalse();
    }

    @Test
    void validateToken_WithExpiredToken_ShouldReturnFalse() {
        JwtService shortLivedJwtService = new JwtService(TEST_SECRET, -1000L, -1000L);
        String token = shortLivedJwtService.generateAccessToken(1L, "USER");

        assertThat(jwtService.validateToken(token)).isFalse();
    }

    @Test
    void extractUserId_WithAdminToken_ShouldReturnCorrectId() {
        String token = jwtService.generateAccessToken(99L, "ADMIN");

        assertThat(jwtService.extractUserId(token)).isEqualTo(99L);
    }

    @Test
    void extractRole_WithUserToken_ShouldReturnUser() {
        String token = jwtService.generateAccessToken(1L, "USER");

        assertThat(jwtService.extractRole(token)).isEqualTo("USER");
    }

    @Test
    void extractRole_WithAdminToken_ShouldReturnAdmin() {
        String token = jwtService.generateAccessToken(1L, "ADMIN");

        assertThat(jwtService.extractRole(token)).isEqualTo("ADMIN");
    }
}