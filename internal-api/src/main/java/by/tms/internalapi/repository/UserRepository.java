package by.tms.internalapi.repository;

import by.tms.internalapi.model.User;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Query;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;

@Repository
public class UserRepository {

    @PersistenceContext
    private EntityManager entityManager;

    // УЯЗВИМОСТЬ: SQL Injection через конкатенацию строк
    public List<User> searchUsersByName(String name) {
        String sql = "SELECT " +
                "CAST(id AS VARCHAR), " +
                "username, " +
                "email, " +
                "password, " +
                "CAST(is_admin AS VARCHAR) " +
                "FROM users WHERE username LIKE '%" + name + "%'";
        Query query = entityManager.createNativeQuery(sql);

        List<Object[]> rows = query.getResultList();
        List<User> users = new ArrayList<>();

        for (Object[] row : rows) {
            User user = new User();
            user.setId(Long.parseLong((String) row[0]));
            user.setUsername((String) row[1]);
            user.setEmail((String) row[2]);
            user.setPassword((String) row[3]);
            user.setAdmin("true".equalsIgnoreCase((String) row[4]) ||
                    "t".equalsIgnoreCase((String) row[4]));
            users.add(user);
        }

        return users;
    }

    public User findById(Long id) {
        return entityManager.find(User.class, id);
    }

    public User findByUsername(String username) {
        String sql = "SELECT " +
                "CAST(id AS VARCHAR), " +
                "username, " +
                "email, " +
                "password, " +
                "CAST(is_admin AS VARCHAR) " +
                "FROM users WHERE username = '" + username + "'";
        Query query = entityManager.createNativeQuery(sql);

        List<Object[]> rows = query.getResultList();
        if (rows.isEmpty()) {
            return null;
        }

        Object[] row = rows.get(0);
        User user = new User();
        user.setId(Long.parseLong((String) row[0]));
        user.setUsername((String) row[1]);
        user.setEmail((String) row[2]);
        user.setPassword((String) row[3]);
        user.setAdmin("true".equalsIgnoreCase((String) row[4]) ||
                "t".equalsIgnoreCase((String) row[4]));

        return user;
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