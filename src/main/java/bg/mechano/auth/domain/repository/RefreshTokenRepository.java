package bg.mechano.auth.domain.repository;

import bg.mechano.auth.domain.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
}
