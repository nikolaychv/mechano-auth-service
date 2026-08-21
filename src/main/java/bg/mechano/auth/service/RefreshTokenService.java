package bg.mechano.auth.service;

import bg.mechano.auth.domain.entity.RefreshToken;
import bg.mechano.auth.domain.entity.User;
import bg.mechano.auth.domain.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final RefreshTokenRepository refreshTokenRepository;
    private final TokenHashService tokenHashService;

    @Value("${mechano.security.jwt.refresh-exp-days}")
    private long refreshExpDays;

    @Transactional
    public String createRefreshToken(User user) {
        String rawToken = generateToken();

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setTokenHash(tokenHashService.hash(rawToken));
        refreshToken.setCreatedAt(LocalDateTime.now());
        refreshToken.setExpiresAt(
                LocalDateTime.now().plusDays(refreshExpDays)
        );

        refreshTokenRepository.save(refreshToken);

        return rawToken;
    }

    @Transactional
    public RefreshTokenRotationResult rotateRefreshToken(String rawToken) {
        String tokenHash = tokenHashService.hash(rawToken);

        RefreshToken existingToken = refreshTokenRepository
                .findByTokenHashAndRevokedAtIsNull(tokenHash)
                .orElseThrow(() ->
                        new IllegalArgumentException("Invalid refresh token.")
                );

        if (existingToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            existingToken.setRevokedAt(LocalDateTime.now());

            throw new IllegalArgumentException(
                    "Refresh token has expired."
            );
        }

        User user = existingToken.getUser();

        if (!user.isActive()) {
            throw new IllegalArgumentException("User is inactive.");
        }

        existingToken.setRevokedAt(LocalDateTime.now());

        String newRefreshToken = createRefreshToken(user);

        return new RefreshTokenRotationResult(
                user,
                newRefreshToken
        );
    }

    @Transactional
    public void revokeRefreshToken(String rawToken) {
        String tokenHash = tokenHashService.hash(rawToken);

        RefreshToken refreshToken = refreshTokenRepository
                .findByTokenHashAndRevokedAtIsNull(tokenHash)
                .orElseThrow(() ->
                        new IllegalArgumentException("Invalid refresh token.")
                );

        refreshToken.setRevokedAt(LocalDateTime.now());
    }

    private String generateToken() {
        byte[] bytes = new byte[64];
        SECURE_RANDOM.nextBytes(bytes);

        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes);
    }
}