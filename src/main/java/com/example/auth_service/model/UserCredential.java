package com.example.auth_service.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDate;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;

@Entity
@Table(name = "user_credentials")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserCredential {
    
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "user_credentials_gen")
    @SequenceGenerator(name = "user_credentials_gen", sequenceName = "user_credentials_seq", allocationSize = 50)
    private Long id;

    @Column(unique = true, nullable = false)
    private String login;

    @Column(nullable = false)
    private String password;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    @CreatedDate
    @Column(name = "created_at", columnDefinition = "TIMESTAMP")
    private LocalDate createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", columnDefinition = "TIMESTAMP")
    private LocalDate updatedAt;

    @PrePersist
    public void onCreate() {
        createdAt = LocalDate.now();
        updatedAt = LocalDate.now();
    }

    @PreUpdate
    public void onUpdate() {
        updatedAt = LocalDate.now();
    }
}
