package com.example.auth_service.exception;

import com.example.auth_service.dto.*;
import com.example.auth_service.repository.UserCredentialRepository;
import com.example.auth_service.controller.*;
import com.example.auth_service.service.AuthService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.OverrideAutoConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


@WebMvcTest(AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import(GlobalExceptionHandler.class)
@TestPropertySource(properties = "spring.liquibase.enabled=false")
@OverrideAutoConfiguration(enabled = false)
class GlobalExceptionHandlerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AuthService authService; 

    @MockitoBean
    private UserCredentialRepository userCredentialRepository; 

private ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void handleInvalidCredentials_ShouldReturn401WithMessage() throws Exception {
        when(authService.createToken(any()))
                .thenThrow(new InvalidCredentialsException("Invalid login or password"));

        mockMvc.perform(post("/api/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                AuthRequest.builder().login("u").password("p").build())))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.message").value("Invalid login or password"));
    }


    @Test
    void handleInvalidToken_ShouldReturn401WithMessage() throws Exception {
        when(authService.refreshToken(any()))
                .thenThrow(new InvalidTokenException("Invalid or expired refresh token"));

        mockMvc.perform(post("/api/auth/token/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                RefreshTokenRequest.builder().refreshToken("bad").build())))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.message").value("Invalid or expired refresh token"));
    }


    @Test
    void handleUserAlreadyExists_ShouldReturn409WithMessage() throws Exception {
        when(authService.register(any()))
                .thenThrow(new UserAlreadyExistsException("taken"));

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                RegisterRequest.builder().login("taken").password("p").userId(1L).build())))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value(409));
    }


    @Test
    void handleValidation_MissingLogin_ShouldReturn400WithFieldError() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                RegisterRequest.builder().password("p").userId(1L).build())))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.login").exists());
    }

    @Test
    void handleValidation_MissingPassword_ShouldReturn400WithFieldError() throws Exception {
        mockMvc.perform(post("/api/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                AuthRequest.builder().login("user").build())))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.password").exists());
    }

    @Test
    void handleValidation_MissingUserId_ShouldReturn400WithFieldError() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                RegisterRequest.builder().login("u").password("p").build())))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.userId").exists());
    }

    @Test
    void handleValidation_MissingRefreshToken_ShouldReturn400WithFieldError() throws Exception {
        mockMvc.perform(post("/api/auth/token/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.refreshToken").exists());
    }

    @Test
    void handleGeneral_UnexpectedException_ShouldReturn500() throws Exception {
        when(authService.createToken(any()))
                .thenThrow(new RuntimeException("Unexpected failure"));

        mockMvc.perform(post("/api/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                AuthRequest.builder().login("u").password("p").build())))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.status").value(500))
                .andExpect(jsonPath("$.message").value("Internal server error"));
    }


    @Test
    void errorResponse_ShouldAlwaysContainTimestampAndError() throws Exception {
        when(authService.createToken(any()))
                .thenThrow(new InvalidCredentialsException("bad"));

        mockMvc.perform(post("/api/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                AuthRequest.builder().login("u").password("p").build())))
                .andExpect(jsonPath("$.timestamp").exists())
                .andExpect(jsonPath("$.error").exists());
    }
}