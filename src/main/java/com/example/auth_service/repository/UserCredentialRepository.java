package com.example.auth_service.repository;

import com.example.auth_service.model.UserCredential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserCredentialRepository extends JpaRepository<UserCredential, Long> {

    Optional<UserCredential> findByLogin(String login);

    boolean existsByLogin(String login);

    Optional<UserCredential> findByUserId(Long userId);
}