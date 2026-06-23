package by.tms.publicapi.controller;

import by.tms.publicapi.config.security.JwtConfiguration;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@Tag(name = "Authentication", description = "JWT Authentication with vulnerabilities")
public class JwtAuthController {

    private final JwtConfiguration.JwtTokenGenerator tokenGenerator;

    // УЯЗВИМОСТЬ: Хранение refresh токенов в памяти с известными значениями
    private static final Map<String, String> REFRESH_TOKENS = new HashMap<>();
    private static final Map<String, String> USER_CREDENTIALS = new HashMap<>();

    static {
        REFRESH_TOKENS.put("admin", "rt_admin_super_secret_2024");
        REFRESH_TOKENS.put("john.doe", "rt_john_2024");
        REFRESH_TOKENS.put("jane.smith", "rt_jane_2024");
        REFRESH_TOKENS.put("superadmin", "rt_superadmin_2024");

        // УЯЗВИМОСТЬ: Хранение паролей в открытом виде
        USER_CREDENTIALS.put("admin", "admin123");
        USER_CREDENTIALS.put("john.doe", "password123");
        USER_CREDENTIALS.put("jane.smith", "password123");
        USER_CREDENTIALS.put("superadmin", "SuperAdmin2024!");
    }

    public JwtAuthController(JwtConfiguration.JwtTokenGenerator tokenGenerator) {
        this.tokenGenerator = tokenGenerator;
    }

    @PostMapping("/login")
    @Operation(summary = "Login and get JWT token")
    public ResponseEntity<Map<String, Object>> login(
            @Parameter(description = "Username") @RequestParam String username,
            @Parameter(description = "Password") @RequestParam String password) {

        // УЯЗВИМОСТЬ: Слабая проверка - принимает любой пароль
        Map<String, Object> response = new HashMap<>();
        Map<String, Object> claims = new HashMap<>();

        claims.put("email", username + "@company.com");

        // УЯЗВИМОСТЬ: Роль назначается на основе имени пользователя
        if (username.contains("admin") || username.equals("superadmin")) {
            claims.put("role", "ROLE_ADMIN");
            claims.put("admin", true);
        } else {
            claims.put("role", "ROLE_USER");
        }

        // УЯЗВИМОСТЬ: Сохраняем пароль в claims токена
        claims.put("password", password);

        String token = tokenGenerator.generateToken(
                username, (String) claims.get("role"), claims
        );

        response.put("access_token", token);
        response.put("token_type", "Bearer");
        response.put("expires_in", 86400);

        if (REFRESH_TOKENS.containsKey(username)) {
            response.put("refresh_token", REFRESH_TOKENS.get(username));
        }

        return ResponseEntity.ok(response);
    }

    @PostMapping("/token/custom")
    @Operation(summary = "Generate custom JWT token (DEBUG - vulnerability)")
    public ResponseEntity<String> generateCustomToken(
            @Parameter(description = "Token configuration")
            @RequestBody Map<String, Object> tokenConfig) {

        // УЯЗВИМОСТЬ: Позволяем создавать произвольные токены
        String username = (String) tokenConfig.getOrDefault("username", "user");
        String role = (String) tokenConfig.getOrDefault("role", "ROLE_USER");

        @SuppressWarnings("unchecked")
        Map<String, Object> extraClaims =
                (Map<String, Object>) tokenConfig.get("claims");

        return ResponseEntity.ok(
                tokenGenerator.generateToken(username, role, extraClaims)
        );
    }

    @PostMapping("/refresh")
    @Operation(summary = "Refresh JWT token")
    public ResponseEntity<Map<String, String>> refreshToken(
            @Parameter(description = "Refresh token")
            @RequestParam String refreshToken) {

        // УЯЗВИМОСТЬ: Предсказуемые refresh токены
        for (Map.Entry<String, String> entry : REFRESH_TOKENS.entrySet()) {
            if (entry.getValue().equals(refreshToken)) {
                Map<String, Object> claims = new HashMap<>();
                claims.put("role", entry.getKey().contains("admin") ?
                        "ROLE_ADMIN" : "ROLE_USER");

                String newToken = tokenGenerator.generateToken(
                        entry.getKey(), (String) claims.get("role"), claims
                );

                Map<String, String> response = new HashMap<>();
                response.put("access_token", newToken);
                response.put("token_type", "Bearer");
                return ResponseEntity.ok(response);
            }
        }

        return ResponseEntity.badRequest().body(
                Map.of("error", "Invalid refresh token")
        );
    }

    @GetMapping("/debug/token-info")
    @Operation(summary = "Decode JWT token (Information disclosure)")
    public ResponseEntity<Map<String, Object>> debugToken(
            @Parameter(description = "JWT token to decode")
            @RequestHeader("Authorization") String auth) {

        // УЯЗВИМОСТЬ: Раскрытие информации о токене
        if (auth != null && auth.startsWith("Bearer ")) {
            String token = auth.substring(7);
            String[] parts = token.split("\\.");

            Map<String, Object> response = new HashMap<>();

            if (parts.length >= 2) {
                // Декодируем header
                String header = new String(
                        Base64.getUrlDecoder().decode(parts[0])
                );
                response.put("header", header);

                // Декодируем payload
                String payload = new String(
                        Base64.getUrlDecoder().decode(parts[1])
                );
                response.put("payload", payload);

                if (parts.length == 3) {
                    response.put("signature", parts[2]);
                } else {
                    response.put("warning", "Token has no signature (alg=none)");
                }
            }

            return ResponseEntity.ok(response);
        }

        return ResponseEntity.badRequest().build();
    }

}
