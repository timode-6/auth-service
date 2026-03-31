package com.example.auth_service.controller;

import com.example.auth_service.dto.*;
import com.example.auth_service.exception.GlobalExceptionHandler;
import com.example.auth_service.repository.UserCredentialRepository;
import com.example.auth_service.service.AuthService;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.*;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.boot.test.autoconfigure.OverrideAutoConfiguration;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import org.springframework.test.context.bean.override.mockito.MockitoBean;

@WebMvcTest(AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import(GlobalExceptionHandler.class)
@TestPropertySource(properties = "spring.liquibase.enabled=false")
@OverrideAutoConfiguration(enabled = false)
class AuthControllerValidationTest {


    @BeforeAll
    static void printCause() {
        System.setProperty("spring.test.context.failure.threshold", "1");
        Thread.setDefaultUncaughtExceptionHandler((t, e) -> e.printStackTrace());
    }

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AuthService authService; 

    @MockitoBean
    private UserCredentialRepository userCredentialRepository; 

    private ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void register_BlankLogin_ShouldReturn400() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                RegisterRequest.builder().login("  ").password("p").userId(1L).build())))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.login").exists());
    }

    @Test
    void register_BlankPassword_ShouldReturn400() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                RegisterRequest.builder().login("u").password("").userId(1L).build())))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.password").exists());
    }

    @Test
    void createToken_BlankLogin_ShouldReturn400() throws Exception {
        mockMvc.perform(post("/api/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                AuthRequest.builder().login("").password("p").build())))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.login").exists());
    }

    @Test
    void createToken_EmptyBody_ShouldReturn400() throws Exception {
        mockMvc.perform(post("/api/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void validateToken_BlankToken_ShouldReturn400() throws Exception {
        mockMvc.perform(post("/api/auth/token/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                TokenValidationRequest.builder().token("").build())))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.token").exists());
    }

    @Test
    void refreshToken_BlankToken_ShouldReturn400() throws Exception {
        mockMvc.perform(post("/api/auth/token/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                RefreshTokenRequest.builder().refreshToken("  ").build())))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.refreshToken").exists());
    }
}