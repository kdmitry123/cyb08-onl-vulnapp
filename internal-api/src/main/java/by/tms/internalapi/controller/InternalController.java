package by.tms.internalapi.controller;

import by.tms.internalapi.model.Task;
import by.tms.internalapi.model.User;
import by.tms.internalapi.repository.TaskRepository;
import by.tms.internalapi.repository.UserRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/internal")
public class InternalController {

    private final UserRepository userRepository;
    private final TaskRepository taskRepository;

    public InternalController(UserRepository userRepository,
                              TaskRepository taskRepository) {
        this.userRepository = userRepository;
        this.taskRepository = taskRepository;
    }

    @GetMapping("/users/search")
    public ResponseEntity<Map<String, Object>> searchUsers(
            @RequestParam String name) {
        // УЯЗВИМОСТЬ: SQL Injection
        List<User> users = userRepository.searchUsersByName(name);
        Map<String, Object> response = new HashMap<>();
        response.put("users", users);
        response.put("count", users.size());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/users/{id}/profile")
    public ResponseEntity<Map<String, Object>> getUserProfile(
            @PathVariable String id) {
        try {
            Long userId = Long.parseLong(id);
            User user = userRepository.findById(userId);
            Map<String, Object> response = new HashMap<>();
            response.put("user", user);
            response.put("tasks", user.getTasks());
            return ResponseEntity.ok(response);
        } catch (NumberFormatException e) {
            // УЯЗВИМОСТЬ: Принимаем строковые ID
            // Можно использовать для SQLi через internal API
            return ResponseEntity.badRequest().build();
        }
    }

    @GetMapping("/users/by-username/{username}")
    public ResponseEntity<User> getUserByUsername(
            @PathVariable String username) {
        // УЯЗВИМОСТЬ: SQL Injection + раскрытие паролей
        User user = userRepository.findByUsername(username);
        if (user != null) {
            return ResponseEntity.ok(user);
        }
        return ResponseEntity.notFound().build();
    }

    @GetMapping("/tasks/by-assignee")
    public ResponseEntity<List<Task>> getTasksByAssignee(
            @RequestParam String assignee) {
        // УЯЗВИМОСТЬ: SQL Injection
        List<Task> tasks = taskRepository.findByAssignee(assignee);
        return ResponseEntity.ok(tasks);
    }

    @GetMapping("/users/all")
    public ResponseEntity<List<User>> getAllUsers() {
        // УЯЗВИМОСТЬ: Раскрытие всех пользователей с паролями
        return ResponseEntity.ok(userRepository.findAll());
    }

    @GetMapping("/tasks/all")
    public ResponseEntity<List<Task>> getAllTasks() {
        // УЯЗВИМОСТЬ: Раскрытие всех задач с заметками
        return ResponseEntity.ok(taskRepository.findAll());
    }
}
