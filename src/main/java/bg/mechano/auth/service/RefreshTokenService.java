package bg.mechano.auth.service;

import bg.mechano.auth.domain.entity.RefreshToken;
import bg.mechano.auth.domain.entity.User;
import bg.mechano.auth.domain.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public String createRefreshToken(User user) {

        byte[] bytes = new byte[64];
        SECURE_RANDOM.nextBytes(bytes);

        String refreshToken = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes);

        RefreshToken token = new RefreshToken();
        token.setUser(user);

        // token.setTokenHash(hash(refreshToken));
        token.setTokenHash(refreshToken);

        token.setCreatedAt(LocalDateTime.now());
        token.setExpiresAt(LocalDateTime.now().plusDays(7));

        refreshTokenRepository.save(token);

        return refreshToken;
    }
}