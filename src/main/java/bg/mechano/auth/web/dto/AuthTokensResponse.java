package bg.mechano.auth.web.dto;

import java.util.Set;

public record AuthTokensResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        long expiresIn,
        Set<String> roles
) {
}