package bg.mechano.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserProfileProvisioningService {

    private final JdbcTemplate jdbcTemplate;

    public void createProfileIfMissing(
            Long authUserId
    ) {
        jdbcTemplate.update(
                """
                INSERT INTO public.users (
                    auth_user_id,
                    full_name,
                    phone,
                    avatar_image_id,
                    created_at,
                    deleted_at
                )
                VALUES (
                    ?,
                    NULL,
                    NULL,
                    NULL,
                    CURRENT_TIMESTAMP,
                    NULL
                )
                ON CONFLICT (auth_user_id)
                DO NOTHING
                """,
                authUserId
        );
    }
}