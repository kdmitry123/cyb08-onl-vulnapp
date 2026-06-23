package by.tms.publicapi.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/search")
@Tag(name = "Advanced Search", description = "Advanced search with filter injection vulnerabilities")
public class SearchController {

    private final RestTemplate restTemplate;
    private final String internalApiUrl;
    private final ObjectMapper objectMapper;

    public SearchController(RestTemplate restTemplate,
                            @Value("${internal.api.url}") String internalApiUrl) {
        this.restTemplate = restTemplate;
        this.internalApiUrl = internalApiUrl;
        this.objectMapper = new ObjectMapper();
    }

    @PostMapping("/advanced")
    @Operation(summary = "Advanced search with JSON filters (Criteria API Injection)")
    public ResponseEntity<String> advancedSearch(
            @Parameter(description = "Search criteria with filters")
            @RequestBody Map<String, Object> searchCriteria) {

        // УЯЗВИМОСТЬ: Передаем сырые пользовательские фильтры в Internal API
        // Злоумышленник может манипулировать Criteria API через JSON
        Map<String, Object> request = new HashMap<>();
        request.put("filters", searchCriteria);

        try {
            String response = restTemplate.postForObject(
                    internalApiUrl + "/api/internal/search/advanced",
                    request,
                    String.class
            );
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(
                    "Search failed: " + e.getMessage()
            );
        }
    }

    @PostMapping("/dynamic-query")
    @Operation(summary = "Dynamic query builder (JPQL Injection)")
    public ResponseEntity<String> dynamicQuery(
            @Parameter(description = "Query configuration with entity and conditions")
            @RequestBody Map<String, Object> queryConfig) {

        // УЯЗВИМОСТЬ: Позволяем клиенту строить произвольные JPQL запросы
        // Можно инжектить условия WHERE, ORDER BY с подзапросами
        try {
            String response = restTemplate.postForObject(
                    internalApiUrl + "/api/internal/search/dynamic",
                    queryConfig,
                    String.class
            );
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(
                    "Query failed: " + e.getMessage()
            );
        }
    }

    @GetMapping("/graphql")
    @Operation(summary = "GraphQL-like query endpoint (GraphQL Injection)")
    public ResponseEntity<String> graphqlQuery(
            @Parameter(description = "GraphQL-like query string")
            @RequestParam String query) {

        // УЯЗВИМОСТЬ: Примитивный парсер GraphQL с инъекциями
        // Можно запрашивать скрытые поля и выполнять SQL инъекции через WHERE
        Map<String, Object> parsedQuery = parseGraphQLQuery(query);

        try {
            String response = restTemplate.postForObject(
                    internalApiUrl + "/api/internal/search/graphql",
                    parsedQuery,
                    String.class
            );
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(
                    "GraphQL query failed: " + e.getMessage()
            );
        }
    }

    @GetMapping("/full-text")
    @Operation(summary = "Full-text search with raw SQL")
    public ResponseEntity<String> fullTextSearch(
            @Parameter(description = "Search query")
            @RequestParam String q,
            @Parameter(description = "Table to search in")
            @RequestParam(defaultValue = "tasks") String table) {

        // УЯЗВИМОСТЬ: Позволяем указывать таблицу для поиска
        // Можно искать в любой таблице, включая системные
        Map<String, Object> queryConfig = new HashMap<>();
        queryConfig.put("entity", table);
        queryConfig.put("where", "title LIKE '%" + q + "%' OR description LIKE '%" + q + "%'");
        queryConfig.put("limit", 100);

        try {
            String response = restTemplate.postForObject(
                    internalApiUrl + "/api/internal/search/dynamic",
                    queryConfig,
                    String.class
            );
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(
                    "Search failed: " + e.getMessage()
            );
        }
    }

    /**
     * УЯЗВИМОСТЬ: Примитивный парсер GraphQL запросов.
     * Позволяет инжектить условия и запрашивать скрытые поля.
     */
    private Map<String, Object> parseGraphQLQuery(String query) {
        Map<String, Object> result = new HashMap<>();

        // Определяем сущность для запроса
        if (query.toLowerCase().contains("users")) {
            result.put("entity", "users");
        } else if (query.toLowerCase().contains("tasks")) {
            result.put("entity", "tasks");
        } else if (query.toLowerCase().contains("apikeys") ||
                query.toLowerCase().contains("api_keys")) {
            result.put("entity", "api_keys");
        } else {
            result.put("entity", "users");
        }

        if (query.contains("password")) {
            result.put("includePassword", true);
        }
        if (query.contains("tasks")) {
            result.put("includeTasks", true);
        }
        if (query.contains("internalNotes") || query.contains("internal_notes")) {
            result.put("includeInternalNotes", true);
        }
        if (query.contains("apikey") || query.contains("api_key")) {
            result.put("includeApiKey", true);
        }
        if (query.contains("secretNotes") || query.contains("secret_notes")) {
            result.put("includeSecretNotes", true);
        }
        if (query.contains("scheduledCommand") || query.contains("scheduled_command")) {
            result.put("includeScheduledCommand", true);
        }

        // Извлекаем условия WHERE
        if (query.contains("where:")) {
            int whereIndex = query.indexOf("where:");
            int endIndex = query.length();

            // Ищем конец WHERE (до следующей директивы или конца строки)
            if (query.contains("orderBy:") && query.indexOf("orderBy:") > whereIndex) {
                endIndex = query.indexOf("orderBy:");
            } else if (query.contains("limit:") && query.indexOf("limit:") > whereIndex) {
                endIndex = query.indexOf("limit:");
            }

            String whereClause = query.substring(whereIndex + 6, endIndex).trim();
            result.put("whereClause", whereClause);
        }

        // Извлекаем сортировку
        if (query.contains("orderBy:")) {
            int orderIndex = query.indexOf("orderBy:");
            int endIndex = query.length();

            if (query.contains("limit:") && query.indexOf("limit:") > orderIndex) {
                endIndex = query.indexOf("limit:");
            }

            String orderBy = query.substring(orderIndex + 8, endIndex).trim();
            result.put("orderBy", orderBy);
        }

        // Извлекаем лимит
        if (query.contains("limit:")) {
            int limitIndex = query.indexOf("limit:");
            String limitStr = query.substring(limitIndex + 6).trim();

            // Извлекаем только число
            StringBuilder limitValue = new StringBuilder();
            for (char c : limitStr.toCharArray()) {
                if (Character.isDigit(c)) {
                    limitValue.append(c);
                } else {
                    break;
                }
            }

            if (!limitValue.isEmpty()) {
                try {
                    result.put("limit", Integer.parseInt(limitValue.toString()));
                } catch (NumberFormatException ignored) {
                }
            }
        }

        return result;
    }
}
