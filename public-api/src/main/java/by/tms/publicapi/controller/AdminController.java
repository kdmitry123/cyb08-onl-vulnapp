package by.tms.publicapi.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import javax.naming.InitialContext;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

@RestController
@RequestMapping("/api/admin")
@Tag(name = "Admin Panel", description = "Administrative operations with privilege escalation")
public class AdminController {

    private final RestTemplate restTemplate;
    private final String internalApiUrl;

    public AdminController(RestTemplate restTemplate,
                           @Value("${internal.api.url}") String internalApiUrl) {
        this.restTemplate = restTemplate;
        this.internalApiUrl = internalApiUrl;
    }

    @PostMapping("/users/create")
    @Operation(summary = "Create new user (Mass Assignment vulnerability)")
    public ResponseEntity<String> createUser(
            @Parameter(description = "User data")
            @RequestBody Map<String, Object> userData,
            @RequestAttribute(required = false) String role) {

        // УЯЗВИМОСТЬ: Проверка роли, которую можно подделать через JWT
        if (!"ROLE_ADMIN".equals(role)) {
            return ResponseEntity.status(403).body(
                    "{\"error\": \"Only admins can create users\"}"
            );
        }

        // УЯЗВИМОСТЬ: Mass Assignment - принимаем все поля
        Map<String, Object> request = new HashMap<>();
        request.put("userData", userData);

        String response = restTemplate.postForObject(
                internalApiUrl + "/api/internal/users/create",
                request,
                String.class
        );

        return ResponseEntity.ok(response);
    }

    @PutMapping("/users/{id}/update")
    @Operation(summary = "Update user (Mass Assignment + IDOR)")
    public ResponseEntity<String> updateUser(
            @Parameter(description = "User ID") @PathVariable Long id,
            @Parameter(description = "Fields to update")
            @RequestBody Map<String, Object> updates) {

        // УЯЗВИМОСТЬ: Нет проверки прав - любой может обновить любого пользователя
        Map<String, Object> request = new HashMap<>();
        request.put("id", id);
        request.put("updates", updates);

        String response = restTemplate.postForObject(
                internalApiUrl + "/api/internal/users/update",
                request,
                String.class
        );

        return ResponseEntity.ok(response);
    }

    @GetMapping("/system/info")
    @Operation(summary = "Get system information (JNDI Injection)")
    public ResponseEntity<String> getSystemInfo(
            @Parameter(description = "System property to lookup")
            @RequestParam(required = false) String property) {

        // УЯЗВИМОСТЬ: JNDI Injection
        if (property != null && property.startsWith("ldap://") ||
                property != null && property.startsWith("rmi://")) {
            try {
                InitialContext ctx = new InitialContext();
                Object result = ctx.lookup(property);
                return ResponseEntity.ok("JNDI Result: " + result);
            } catch (Exception e) {
                return ResponseEntity.ok("JNDI Error: " + e.getMessage());
            }
        }

        if (property != null) {
            return ResponseEntity.ok(
                    "Property '" + property + "': " + System.getProperty(property)
            );
        }

        // УЯЗВИМОСТЬ: Раскрытие всех системных свойств
        Properties props = System.getProperties();
        StringBuilder sb = new StringBuilder();
        props.forEach((key, value) ->
                sb.append(key).append("=").append(value).append("\n")
        );
        return ResponseEntity.ok(sb.toString());
    }

    @GetMapping("/env")
    @Operation(summary = "Get environment variables (Information disclosure)")
    public ResponseEntity<String> getEnvironment() {
        // УЯЗВИМОСТЬ: Раскрытие переменных окружения
        Map<String, String> env = System.getenv();
        StringBuilder sb = new StringBuilder();
        env.forEach((key, value) ->
                sb.append(key).append("=").append(value).append("\n")
        );
        return ResponseEntity.ok(sb.toString());
    }

}
