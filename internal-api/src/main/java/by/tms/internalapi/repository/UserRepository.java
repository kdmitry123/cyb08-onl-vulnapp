package by.tms.internalapi.repository;

import by.tms.internalapi.model.User;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class UserRepository {

    @PersistenceContext
    private EntityManager entityManager;

    // УЯЗВИМОСТЬ: SQL Injection через конкатенацию строк
    public List<User> searchUsersByName(String name) {
        String sql = "SELECT * FROM users WHERE username LIKE '%" + name + "%'";
        Query query = entityManager.createNativeQuery(sql, User.class);
        return query.getResultList();
    }

    public User findById(Long id) {
        return entityManager.find(User.class, id);
    }

    // УЯЗВИМОСТЬ: SQL Injection в WHERE
    public User findByUsername(String username) {
        String sql = "SELECT * FROM users WHERE username = '" + username + "'";
        Query query = entityManager.createNativeQuery(sql, User.class);
        List<User> users = query.getResultList();
        return users.isEmpty() ? null : users.get(0);
    }

    public List<User> findAll() {
        return entityManager.createQuery("SELECT u FROM User u", User.class)
                .getResultList();
    }

    public void save(User user) {
        if (user.getId() == null) {
            entityManager.persist(user);
        } else {
            entityManager.merge(user);
        }
    }

    public void delete(Long id) {
        User user = findById(id);
        if (user != null) {
            entityManager.remove(user);
        }
    }
}
