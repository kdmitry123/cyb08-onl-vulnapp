package by.tms.publicapi.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.yaml.snakeyaml.Yaml;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.io.StringReader;
import java.util.Base64;

@RestController
@RequestMapping("/api/users")
@Tag(name = "User Management", description = "User management endpoints with vulnerabilities")
public class UserController {

    private final RestTemplate restTemplate;
    private final String internalApiUrl;
    private final String internalApiKey;

    public UserController(RestTemplate restTemplate,
                          @Value("${internal.api.url}") String internalApiUrl,
                          @Value("${internal.api.key}") String internalApiKey) {
        this.restTemplate = restTemplate;
        this.internalApiUrl = internalApiUrl;
        this.internalApiKey = internalApiKey;
    }

    @PostMapping("/import-profile")
    @Operation(summary = "Import user profile from external URL (SSRF vulnerability)")
    public ResponseEntity<String> importProfile(
            @Parameter(description = "URL to fetch profile from")
            @RequestParam String url) {
        // УЯЗВИМОСТЬ: SSRF - нет валидации URL
        // Можно указать: file:///etc/passwd, http://internal-api:8081/...
        try {
            String response = restTemplate.getForObject(url, String.class);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(
                    "Failed to import: " + e.getMessage()
            );
        }
    }

    @PostMapping("/import-yaml")
    @Operation(summary = "Import user data from YAML (Deserialization vulnerability)")
    public ResponseEntity<String> importYaml(
            @Parameter(description = "YAML content to parse")
            @RequestBody String yamlContent) {
        // УЯЗВИМОСТЬ: Небезопасная десериализация YAML
        // Можно выполнить произвольный код через SnakeYAML gadgets
        Yaml yaml = new Yaml();
        try {
            Object obj = yaml.load(yamlContent);
            return ResponseEntity.ok("Imported: " + obj.toString());
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Parse error: " + e.getMessage());
        }
    }

    @GetMapping("/search")
    @Operation(summary = "Search users by name (SQL Injection vulnerability)")
    public ResponseEntity<String> searchUsers(
            @Parameter(description = "Name to search for")
            @RequestParam String name) {
        // УЯЗВИМОСТЬ: Передача неочищенных данных в Internal API
        // SQL Injection через параметр name
        String url = internalApiUrl + "/api/internal/users/search?name=" + name;
        String response = restTemplate.getForObject(url, String.class);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/deserialize")
    @Operation(summary = "Deserialize user object (Java Deserialization vulnerability)")
    public ResponseEntity<String> deserializeUser(
            @Parameter(description = "Base64 encoded serialized Java object")
            @RequestBody String base64Data) {
        // УЯЗВИМОСТЬ: Небезопасная Java десериализация
        // Можно выполнить RCE через gadget chains
        try {
            byte[] data = Base64.getDecoder().decode(base64Data);
            ObjectInputStream ois = new ObjectInputStream(
                    new ByteArrayInputStream(data)
            );
            Object obj = ois.readObject();
            return ResponseEntity.ok("Deserialized: " + obj.toString());
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }

    @GetMapping("/profile/{id}")
    @Operation(summary = "Get user profile (IDOR vulnerability)")
    public ResponseEntity<String> getUserProfile(
            @Parameter(description = "User ID")
            @PathVariable String id) {
        // УЯЗВИМОСТЬ: IDOR + SSRF через манипуляцию ID
        String url = internalApiUrl + "/api/internal/users/" + id + "/profile";
        String response = restTemplate.getForObject(url, String.class);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/update-profile")
    @Operation(summary = "Update user profile via XML (XXE vulnerability)")
    public ResponseEntity<String> updateProfileXml(
            @Parameter(description = "XML profile data")
            @RequestBody String xmlData) {
        // УЯЗВИМОСТЬ: XXE через XML processing
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

            // УЯЗВИМОСТЬ: Не отключаем внешние сущности
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(
                    new InputSource(new StringReader(xmlData))
            );

            return ResponseEntity.ok("Profile updated: " +
                    document.getDocumentElement().getTextContent());
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("XML Error: " + e.getMessage());
        }
    }
}
