package bg.mechano.auth.service;

import bg.mechano.auth.domain.entity.Role;
import bg.mechano.auth.domain.entity.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Set;

@Service
public class JwtService {

    private final SecretKey secretKey;
    private final String issuer;
    private final long accessExpMinutes;

    public JwtService(
            @Value("${mechano.security.jwt.secret}") String secret,
            @Value("${mechano.security.jwt.issuer}") String issuer,
            @Value("${mechano.security.jwt.access-exp-minutes}") long accessExpMinutes
    ) {
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.issuer = issuer;
        this.accessExpMinutes = accessExpMinutes;
    }

    public String generateAccessToken(User user) {
        Instant now = Instant.now();
        Instant expiry = now.plus(accessExpMinutes, ChronoUnit.MINUTES);

        Set<String> roles = user.getRoles()
                .stream()
                .map(Role::name)
                .collect(java.util.stream.Collectors.toSet());

        return Jwts.builder()
                .subject(String.valueOf(user.getId()))
                .issuer(issuer)
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiry))
                .claim("email", user.getEmail())
                .claim("username", user.getUsername())
                .claim("roles", roles)
                .signWith(secretKey)
                .compact();
    }

    public long getAccessExpSeconds() {
        return accessExpMinutes * 60;
    }
}