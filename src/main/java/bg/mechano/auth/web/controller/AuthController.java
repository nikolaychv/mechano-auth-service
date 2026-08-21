package bg.mechano.auth.web.controller;

import bg.mechano.auth.service.AuthService;
import bg.mechano.auth.web.dto.AuthTokensResponse;
import bg.mechano.auth.web.dto.LoginRequest;
import bg.mechano.auth.web.dto.RefreshTokenRequest;
import bg.mechano.auth.web.dto.RegisterRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public void register(
            @Valid @RequestBody RegisterRequest request
    ) {
        authService.register(request);
    }

    @PostMapping("/login")
    public AuthTokensResponse login(
            @Valid @RequestBody LoginRequest request
    ) {
        return authService.login(request);
    }

    @PostMapping("/refresh")
    public AuthTokensResponse refresh(
            @Valid @RequestBody RefreshTokenRequest request
    ) {
        return authService.refresh(request);
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(
            @Valid @RequestBody RefreshTokenRequest request
    ) {
        authService.logout(request);
    }
}