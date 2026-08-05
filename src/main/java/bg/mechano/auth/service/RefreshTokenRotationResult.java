package bg.mechano.auth.service;

import bg.mechano.auth.domain.entity.User;

public record RefreshTokenRotationResult(
        User user,
        String refreshToken
) {
}