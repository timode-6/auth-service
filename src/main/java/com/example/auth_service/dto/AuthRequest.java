package com.example.auth_service.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthRequest {

    @NotBlank(message = "Login is required")
    private String login;

    @NotBlank(message = "Password is required")
    private String password;
}