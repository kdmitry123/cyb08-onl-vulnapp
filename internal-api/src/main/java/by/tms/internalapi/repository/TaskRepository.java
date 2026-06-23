package by.tms.internalapi.repository;

import by.tms.internalapi.model.Task;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class TaskRepository {

    @PersistenceContext
    private EntityManager entityManager;

    // УЯЗВИМОСТЬ: SQL Injection через JOIN
    public List<Task> findByAssignee(String assigneeName) {
        String sql = "SELECT t.* FROM tasks t " +
                "JOIN users u ON t.assignee_id = u.id " +
                "WHERE u.username = '" + assigneeName + "'";
        Query query = entityManager.createNativeQuery(sql, Task.class);
        return query.getResultList();
    }

    public List<Task> findAll() {
        return entityManager.createQuery("SELECT t FROM Task t", Task.class)
                .getResultList();
    }

    public Task findById(Long id) {
        return entityManager.find(Task.class, id);
    }

    public void save(Task task) {
        if (task.getId() == null) {
            entityManager.persist(task);
        } else {
            entityManager.merge(task);
        }
    }
}
