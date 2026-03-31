package com.example.auth_service.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenValidationRequest {

    @NotBlank(message = "Token is required")
    private String token;
}