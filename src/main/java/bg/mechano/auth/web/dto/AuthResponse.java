package bg.mechano.auth.web.dto;

import java.util.Set;

public record AuthResponse(
        String accessToken,
        String tokenType,
        long expiresIn,
        Set<String> roles
) {
}
