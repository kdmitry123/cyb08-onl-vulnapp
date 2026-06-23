package by.tms.internalapi.controller;

import by.tms.internalapi.model.User;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.criteria.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/internal/search")
public class DynamicSearchController {

    @PersistenceContext
    private EntityManager entityManager;

    @PostMapping("/advanced")
    public ResponseEntity<Map<String, Object>> advancedSearch(
            @RequestBody Map<String, Object> request) {

        @SuppressWarnings("unchecked")
        Map<String, Object> filters = (Map<String, Object>) request.get("filters");

        String entityName = (String) filters.getOrDefault("entity", "User");
        CriteriaBuilder cb = entityManager.getCriteriaBuilder();

        if ("User".equals(entityName)) {
            CriteriaQuery<User> query = cb.createQuery(User.class);
            Root<User> root = query.from(User.class);
            List<Predicate> predicates = new ArrayList<>();

            // УЯЗВИМОСТЬ: Динамические Criteria из пользовательского ввода
            if (filters.containsKey("conditions")) {
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> conditions =
                        (List<Map<String, Object>>) filters.get("conditions");

                for (Map<String, Object> condition : conditions) {
                    String field = (String) condition.get("field");
                    String operator = (String) condition.get("operator");
                    Object value = condition.get("value");

                    Path<Object> path = root.get(field);

                    switch (operator) {
                        case "equals":
                            predicates.add(cb.equal(path, value));
                            break;
                        case "contains":
                            predicates.add(cb.like(
                                    path.as(String.class), "%" + value + "%"
                            ));
                            break;
                        case "sql":
                            // УЯЗВИМОСТЬ: SQL инъекция через функцию
                            predicates.add(cb.equal(
                                    cb.function((String) value, String.class, path),
                                    "true"
                            ));
                            break;
                    }
                }
            }

            query.where(predicates.toArray(new Predicate[0]));
            List<User> results = entityManager.createQuery(query).getResultList();

            Map<String, Object> response = new HashMap<>();
            response.put("results", results);
            return ResponseEntity.ok(response);
        }

        return ResponseEntity.badRequest().build();
    }

    @PostMapping("/dynamic")
    public ResponseEntity<Map<String, Object>> dynamicQuery(
            @RequestBody Map<String, Object> queryConfig) {

        String entity = (String) queryConfig.get("entity");
        String jpql = "SELECT e FROM " + entity + " e";

        // УЯЗВИМОСТЬ: JPQL Injection
        if (queryConfig.containsKey("where")) {
            jpql += " WHERE " + queryConfig.get("where");
        }
        if (queryConfig.containsKey("orderBy")) {
            jpql += " ORDER BY " + queryConfig.get("orderBy");
        }

        jakarta.persistence.Query query = entityManager.createQuery(jpql);

        if (queryConfig.containsKey("limit")) {
            query.setMaxResults((Integer) queryConfig.get("limit"));
        }

        List<?> results = query.getResultList();

        Map<String, Object> response = new HashMap<>();
        response.put("results", results);
        response.put("executedQuery", jpql);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/graphql")
    public ResponseEntity<Map<String, Object>> graphqlQuery(
            @RequestBody Map<String, Object> parsedQuery) {

        String entity = (String) parsedQuery.get("entity");
        Map<String, Object> response = new HashMap<>();

        if ("users".equals(entity)) {
            List<User> users = entityManager
                    .createQuery("SELECT u FROM User u", User.class)
                    .getResultList();

            List<Map<String, Object>> result = new ArrayList<>();
            for (User user : users) {
                Map<String, Object> userMap = new HashMap<>();
                userMap.put("id", user.getId());
                userMap.put("username", user.getUsername());

                // УЯЗВИМОСТЬ: Раскрытие паролей по запросу
                if (Boolean.TRUE.equals(parsedQuery.get("includePassword"))) {
                    userMap.put("password", user.getPassword());
                }

                if (Boolean.TRUE.equals(parsedQuery.get("includeTasks"))) {
                    userMap.put("tasks", user.getTasks());
                }

                result.add(userMap);
            }

            // УЯЗВИМОСТЬ: Фильтрация через сырой SQL
            if (parsedQuery.containsKey("whereClause")) {
                String whereClause = (String) parsedQuery.get("whereClause");
                String sql = "SELECT * FROM users WHERE " + whereClause;
                jakarta.persistence.Query nativeQuery =
                        entityManager.createNativeQuery(sql, User.class);
                result.clear();
                for (Object obj : nativeQuery.getResultList()) {
                    User user = (User) obj;
                    Map<String, Object> userMap = new HashMap<>();
                    userMap.put("id", user.getId());
                    userMap.put("username", user.getUsername());
                    userMap.put("password", user.getPassword());
                    userMap.put("email", user.getEmail());
                    result.add(userMap);
                }
            }

            response.put("users", result);
        }

        return ResponseEntity.ok(response);
    }
}