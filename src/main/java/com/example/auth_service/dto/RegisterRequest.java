package com.example.auth_service.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {

    @NotBlank(message = "Login is required")
    private String login;

    @NotBlank(message = "Password is required")
    private String password;

    @NotNull(message = "User ID is required")
    private Long userId;
}