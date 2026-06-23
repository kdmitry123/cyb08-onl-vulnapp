package by.tms.internalapi.repository;

import by.tms.internalapi.model.ApiKey;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class ApiKeyRepository {

    @PersistenceContext
    private EntityManager entityManager;

    // УЯЗВИМОСТЬ: Раскрытие всех API ключей
    public List<ApiKey> findAll() {
        return entityManager.createQuery(
                "SELECT a FROM ApiKey a", ApiKey.class
        ).getResultList();
    }

    public List<ApiKey> findByService(String serviceName) {
        String sql = "SELECT * FROM api_keys WHERE service_name = '" +
                serviceName + "'";
        return entityManager.createNativeQuery(sql, ApiKey.class)
                .getResultList();
    }
}
