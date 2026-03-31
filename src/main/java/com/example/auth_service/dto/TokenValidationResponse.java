package com.example.auth_service.dto;

import lombok.*;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenValidationResponse {

    private boolean valid;
    private Long userId;
    private String role;
}