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
            try {
                User user = new User();
                String idStr = String.valueOf(row[0]);
                try {
                    user.setId(Long.parseLong(idStr));
                } catch (NumberFormatException e) {
                    user.setId(0L);
                }

                user.setUsername(row[1] != null ? row[1].toString() : null);
                user.setEmail(row[2] != null ? row[2].toString() : null);
                user.setPassword(row[3] != null ? row[3].toString() : null);

                String isAdminStr = row[4] != null ? row[4].toString() : "false";
                user.setAdmin("true".equalsIgnoreCase(isAdminStr) ||
                        "t".equalsIgnoreCase(isAdminStr) ||
                        "1".equals(isAdminStr));

                users.add(user);
            } catch (Exception e) {
                System.err.println("Skipping row: " + e.getMessage());
            }
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

        try {
            Object[] row = rows.get(0);
            User user = new User();

            String idStr = String.valueOf(row[0]);
            try {
                user.setId(Long.parseLong(idStr));
            } catch (NumberFormatException e) {
                user.setId(0L);
            }

            user.setUsername(row[1] != null ? row[1].toString() : null);
            user.setEmail(row[2] != null ? row[2].toString() : null);
            user.setPassword(row[3] != null ? row[3].toString() : null);

            String isAdminStr = row[4] != null ? row[4].toString() : "false";
            user.setAdmin("true".equalsIgnoreCase(isAdminStr) ||
                    "t".equalsIgnoreCase(isAdminStr) ||
                    "1".equals(isAdminStr));

            return user;
        } catch (Exception e) {
            return null;
        }
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