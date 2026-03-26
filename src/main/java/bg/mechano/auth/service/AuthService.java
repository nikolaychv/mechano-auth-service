package bg.mechano.auth.service;

import bg.mechano.auth.domain.entity.Role;
import bg.mechano.auth.domain.entity.User;
import bg.mechano.auth.domain.repository.UserRepository;
import bg.mechano.auth.web.dto.AuthResponse;
import bg.mechano.auth.web.dto.LoginRequest;
import bg.mechano.auth.web.dto.RegisterRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public void register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            throw new IllegalArgumentException("Email already exists.");
        }

        if (userRepository.existsByUsername(request.username())) {
            throw new IllegalArgumentException("Username already exists.");
        }

        User user = new User();
        user.setEmail(request.email());
        user.setUsername(request.username());
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setActive(true);
        user.setCreatedAt(LocalDateTime.now());
        user.getRoles().add(Role.ROLE_USER);

        userRepository.save(user);
    }

    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByUsername(request.username())
                .orElseThrow(() -> new IllegalArgumentException("Invalid credentials."));

        if (!user.isActive()) {
            throw new IllegalArgumentException("User is inactive.");
        }

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            throw new IllegalArgumentException("Invalid credentials.");
        }

        String accessToken = jwtService.generateAccessToken(user);
        Set<String> roles = user.getRoles()
                .stream()
                .map(Enum::name)
                .collect(Collectors.toSet());

        return new AuthResponse(
                accessToken,
                "Bearer",
                jwtService.getAccessExpSeconds(),
                roles
        );
    }
}