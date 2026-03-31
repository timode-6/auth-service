package com.example.auth_service.unit;

import org.junit.jupiter.api.Test;
import com.example.auth_service.model.*;

import static org.assertj.core.api.Assertions.*;

class UserCredentialTest {

    @Test
    void onCreate_ShouldSetCreatedDateAndUpdatedDate() {
        UserCredential credential = UserCredential.builder()
                .login("user")
                .password("hashed")
                .userId(1L)
                .role(Role.USER)
                .build();

        credential.onCreate();

        assertThat(credential.getCreatedAt()).isNotNull();
        assertThat(credential.getUpdatedAt()).isNotNull();
    }

    @Test
    void onUpdate_ShouldUpdateOnlyUpdatedDate(){
        UserCredential credential = UserCredential.builder()
                .login("user")
                .password("hashed")
                .userId(1L)
                .role(Role.USER)
                .build();

        credential.onCreate();
        var createdDate = credential.getCreatedAt();

        credential.onUpdate();

        assertThat(credential.getCreatedAt()).isEqualTo(createdDate);
        assertThat(credential.getUpdatedAt()).isAfterOrEqualTo(createdDate);
    }

    @Test
    void builder_ShouldSetAllFields() {
        UserCredential credential = UserCredential.builder()
                .id(42L)
                .login("admin")
                .password("hash")
                .userId(7L)
                .role(Role.ADMIN)
                .build();

        assertThat(credential.getId()).isEqualTo(42L);
        assertThat(credential.getLogin()).isEqualTo("admin");
        assertThat(credential.getPassword()).isEqualTo("hash");
        assertThat(credential.getUserId()).isEqualTo(7L);
        assertThat(credential.getRole()).isEqualTo(Role.ADMIN);
    }

    @Test
    void noArgsConstructor_ShouldCreateEmptyInstance() {
        UserCredential credential = new UserCredential();
        assertThat(credential.getLogin()).isNull();
        assertThat(credential.getRole()).isNull();
    }
}