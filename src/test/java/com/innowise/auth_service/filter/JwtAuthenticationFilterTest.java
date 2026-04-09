package com.innowise.auth_service.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import com.innowise.auth_service.service.JwtService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {

    @Mock
    private JwtService jwtService;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    @InjectMocks
    private JwtAuthenticationFilter filter;

    @BeforeEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void clearSecurityContextAfter() {
        SecurityContextHolder.clearContext();
    }


    @Test
    void noAuthHeader_ShouldNotAuthenticate_AndContinueChain() throws Exception {
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(null);

        filter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(jwtService);
    }


    @Test
    void basicAuthHeader_ShouldNotAuthenticate_AndContinueChain() throws Exception {
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Basic dXNlcjpwYXNz");

        filter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(jwtService);
    }

    @Test
    void bearerWithNoToken_ShouldNotAuthenticate_AndContinueChain() throws Exception {
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer ");

        when(jwtService.validateToken("")).thenReturn(false);

        filter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }


    @Test
    void validToken_WithPlainRole_ShouldSetAuthenticationWithRolePrefix() throws Exception {
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer valid-token");
        when(jwtService.validateToken("valid-token")).thenReturn(true);
        when(jwtService.extractUserId("valid-token")).thenReturn(5L);
        when(jwtService.extractRole("valid-token")).thenReturn("USER");

        filter.doFilterInternal(request, response, filterChain);

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(auth).isNotNull();
        assertThat(auth.getPrincipal()).isEqualTo(5L);
        assertThat((Iterable<GrantedAuthority>)auth.getAuthorities())
                .containsExactly(new SimpleGrantedAuthority("ROLE_USER"));
        verify(filterChain).doFilter(request, response);
    }


    @Test
    void validToken_WithRolePrefixAlreadyPresent_ShouldNotDoublePrefix() throws Exception {
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer valid-token");
        when(jwtService.validateToken("valid-token")).thenReturn(true);
        when(jwtService.extractUserId("valid-token")).thenReturn(1L);
        when(jwtService.extractRole("valid-token")).thenReturn("ROLE_ADMIN");

        filter.doFilterInternal(request, response, filterChain);

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(auth).isNotNull();
        assertThat((Iterable<GrantedAuthority>)auth.getAuthorities())
                .containsExactly(new SimpleGrantedAuthority("ROLE_ADMIN"));
        assertThat(auth.getAuthorities().iterator().next().getAuthority())
                .doesNotStartWith("ROLE_ROLE_");
    }


    @Test
    void validToken_WithAdminRole_ShouldSetAdminAuthority() throws Exception {
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer admin-token");
        when(jwtService.validateToken("admin-token")).thenReturn(true);
        when(jwtService.extractUserId("admin-token")).thenReturn(1L);
        when(jwtService.extractRole("admin-token")).thenReturn("ADMIN");

        filter.doFilterInternal(request, response, filterChain);

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertThat((Iterable<GrantedAuthority>)auth.getAuthorities())
                .containsExactly(new SimpleGrantedAuthority("ROLE_ADMIN"));
    }


    @Test
    void invalidToken_ShouldNotAuthenticate_AndContinueChain() throws Exception {
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer bad-token");
        when(jwtService.validateToken("bad-token")).thenReturn(false);

        filter.doFilterInternal(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
        verify(jwtService, never()).extractUserId(any());
        verify(jwtService, never()).extractRole(any());
    }


    @Test
    void filterChain_ShouldAlwaysProceed_EvenWhenTokenInvalid() throws Exception {
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer expired");
        when(jwtService.validateToken("expired")).thenReturn(false);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    void filterChain_ShouldAlwaysProceed_EvenWhenNoHeader() throws Exception {
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(null);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain, times(1)).doFilter(request, response);
    }


    @Test
    void validToken_ShouldSetNullCredentials() throws Exception {
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer token");
        when(jwtService.validateToken("token")).thenReturn(true);
        when(jwtService.extractUserId("token")).thenReturn(7L);
        when(jwtService.extractRole("token")).thenReturn("USER");

        filter.doFilterInternal(request, response, filterChain);

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(auth.getCredentials()).isNull();
    }
}