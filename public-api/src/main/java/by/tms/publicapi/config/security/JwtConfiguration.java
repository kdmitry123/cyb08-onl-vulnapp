package by.tms.publicapi.config.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;

@Configuration
public class JwtConfiguration {

    // УЯЗВИМОСТЬ: Слабый секретный ключ, известный по умолчанию
    // Длина 32 символа (256 бит) - минимально допустимая для HMAC-SHA256
    private static final String SECRET_KEY = "secretsecretsecretsecretsecret12";

    @Bean
    public JwtTokenGenerator tokenGenerator() {
        return new JwtTokenGenerator(SECRET_KEY);
    }

    public static class JwtTokenGenerator {

        private final SecretKey key;

        public JwtTokenGenerator(String secret) {
            // УЯЗВИМОСТЬ: Использование слабого, предсказуемого ключа
            this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        }

        public String generateToken(String username, String role,
                                    Map<String, Object> claims) {
            Date now = new Date();
            // УЯЗВИМОСТЬ: Длинный срок жизни токена
            Date expiration = new Date(now.getTime() + 86400000); // 24 часа

            JwtBuilder builder = Jwts.builder()
                    .setSubject(username)
                    .setIssuedAt(now)
                    .setExpiration(expiration)
                    .claim("role", role);

            // УЯЗВИМОСТЬ: Принимаем произвольные claims от пользователя
            if (claims != null) {
                claims.forEach((key, value) -> {
                    // УЯЗВИМОСТЬ: Нет фильтрации опасных claims
                    builder.claim(key, value);
                });
            }

            return builder.signWith(key).compact();
        }

        public Claims validateToken(String token) {
            try {
                // УЯЗВИМОСТЬ: Не проверяем алгоритм - уязвимость к "none" алгоритму
                return Jwts.parserBuilder()
                        .setSigningKey(key)
                        .build()
                        .parseClaimsJws(token)
                        .getBody();
            } catch (JwtException e) {
                // УЯЗВИМОСТЬ: Раскрытие деталей ошибки
                throw new RuntimeException("Token validation failed: " + e.getMessage());
            }
        }
    }

}