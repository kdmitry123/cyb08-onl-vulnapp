package by.tms.internalapi.controller;

import by.tms.internalapi.model.User;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.lang.reflect.Method;
import java.util.Map;

@RestController
@RequestMapping("/api/internal")
public class UserManagementController {

    @PersistenceContext
    private EntityManager entityManager;

    @PostMapping("/users/create")
    @Transactional
    public ResponseEntity<String> createUser(
            @RequestBody Map<String, Object> request) {

        @SuppressWarnings("unchecked")
        Map<String, Object> userData = (Map<String, Object>) request.get("userData");

        User user = new User();

        // УЯЗВИМОСТЬ: Mass Assignment
        if (userData.containsKey("username")) {
            user.setUsername((String) userData.get("username"));
        }
        if (userData.containsKey("email")) {
            user.setEmail((String) userData.get("email"));
        }
        if (userData.containsKey("password")) {
            user.setPassword((String) userData.get("password"));
        }
        // УЯЗВИМОСТЬ: Можно установить admin при создании
        if (userData.containsKey("admin") || userData.containsKey("is_admin")) {
            user.setAdmin(Boolean.TRUE.equals(userData.get("admin")) ||
                    Boolean.TRUE.equals(userData.get("is_admin")));
        }

        entityManager.persist(user);
        return ResponseEntity.ok("User created with id: " + user.getId());
    }

    @PostMapping("/users/update")
    @Transactional
    public ResponseEntity<String> updateUser(
            @RequestBody Map<String, Object> request) {

        Long id = ((Number) request.get("id")).longValue();
        @SuppressWarnings("unchecked")
        Map<String, Object> updates = (Map<String, Object>) request.get("updates");

        User user = entityManager.find(User.class, id);
        if (user == null) {
            return ResponseEntity.notFound().build();
        }

        // УЯЗВИМОСТЬ: Mass Assignment с рефлексией
        updates.forEach((key, value) -> {
            try {
                String setterName = "set" +
                        Character.toUpperCase(key.charAt(0)) +
                        key.substring(1);

                Method setter = User.class.getMethod(
                        setterName,
                        value != null ? value.getClass() : String.class
                );
                setter.invoke(user, value);
            } catch (Exception e) {
                // Игнорируем ошибки - позволяет подбирать сеттеры
            }
        });

        entityManager.merge(user);
        return ResponseEntity.ok("User updated successfully");
    }
}