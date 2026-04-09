package com.innowise.auth_service.config;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.innowise.auth_service.model.Role;
import com.innowise.auth_service.model.UserCredential;
import com.innowise.auth_service.repository.UserCredentialRepository;

import org.springframework.beans.factory.annotation.Value;

@Component
@RequiredArgsConstructor
@ConditionalOnProperty(name = "admin.bootstrap.enabled", havingValue = "true")
public class AdminBootstrapConfig implements ApplicationRunner {

    private final UserCredentialRepository userCredentialRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${admin.bootstrap.login}")
    private String bootstrapLogin;

    @Value("${admin.bootstrap.password}")
    private String bootstrapPassword;

    @Value("${admin.bootstrap.user-id}")
    private Long bootstrapUserId;

    @Override
    public void run(ApplicationArguments args) {
        if (userCredentialRepository.existsByLogin(bootstrapLogin)) {
            return;
        }

        UserCredential admin = UserCredential.builder()
                .login(bootstrapLogin)
                .password(passwordEncoder.encode(bootstrapPassword))
                .userId(bootstrapUserId)
                .role(Role.ADMIN)
                .build();

        userCredentialRepository.save(admin);
    }
}