package bg.mechano.auth.service;

import bg.mechano.auth.domain.entity.Role;
import bg.mechano.auth.domain.entity.User;
import bg.mechano.auth.domain.repository.UserRepository;
import bg.mechano.auth.web.dto.AuthTokensResponse;
import bg.mechano.auth.web.dto.LoginRequest;
import bg.mechano.auth.web.dto.RefreshTokenRequest;
import bg.mechano.auth.web.dto.RegisterRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final UserProfileProvisioningService
            userProfileProvisioningService;

    @Transactional
    public void register(RegisterRequest request) {
        String email = request.email().trim();
        String username = request.username().trim();

        if (userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException(
                    "Email already exists."
            );
        }

        if (userRepository.existsByUsername(username)) {
            throw new IllegalArgumentException(
                    "Username already exists."
            );
        }

        User user = new User();
        user.setEmail(email);
        user.setUsername(username);
        user.setPasswordHash(
                passwordEncoder.encode(
                        request.password()
                )
        );
        user.setActive(true);
        user.setCreatedAt(LocalDateTime.now());
        user.getRoles().add(Role.ROLE_USER);

        user = userRepository.save(user);

        userProfileProvisioningService
                .createProfileIfMissing(
                        user.getId()
                );
    }

    @Transactional
    public AuthTokensResponse login(
            LoginRequest request
    ) {
        User user = userRepository
                .findByUsername(request.username())
                .orElseThrow(() ->
                        new IllegalArgumentException(
                                "Invalid credentials."
                        )
                );

        if (!user.isActive()) {
            throw new IllegalArgumentException(
                    "User is inactive."
            );
        }

        if (!passwordEncoder.matches(
                request.password(),
                user.getPasswordHash()
        )) {
            throw new IllegalArgumentException(
                    "Invalid credentials."
            );
        }

        String accessToken =
                jwtService.generateAccessToken(user);

        String refreshToken =
                refreshTokenService
                        .createRefreshToken(user);

        return createResponse(
                user,
                accessToken,
                refreshToken
        );
    }

    @Transactional
    public AuthTokensResponse refresh(
            RefreshTokenRequest request
    ) {
        RefreshTokenRotationResult result =
                refreshTokenService
                        .rotateRefreshToken(
                                request.refreshToken()
                        );

        User user = result.user();

        String accessToken =
                jwtService.generateAccessToken(user);

        return createResponse(
                user,
                accessToken,
                result.refreshToken()
        );
    }

    @Transactional
    public void logout(
            RefreshTokenRequest request
    ) {
        refreshTokenService
                .revokeRefreshToken(
                        request.refreshToken()
                );
    }

    private AuthTokensResponse createResponse(
            User user,
            String accessToken,
            String refreshToken
    ) {
        Set<String> roles =
                user.getRoles()
                        .stream()
                        .map(Enum::name)
                        .collect(
                                Collectors.toSet()
                        );

        return new AuthTokensResponse(
                accessToken,
                refreshToken,
                "Bearer",
                jwtService.getAccessExpSeconds(),
                roles
        );
    }
}