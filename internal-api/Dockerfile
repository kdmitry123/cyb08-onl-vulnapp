FROM maven:3.9.8-eclipse-temurin-21-alpine AS build
WORKDIR /app

# Копируем только pom.xml для кэширования зависимостей
COPY pom.xml .

# Скачиваем зависимости
RUN mvn dependency:go-offline -B || true

# Копируем исходный код
COPY src ./src

# Собираем приложение
RUN mvn clean package -DskipTests -B

FROM eclipse-temurin:21-jre-alpine

# Устанавливаем необходимые утилиты
RUN apk add --no-cache curl bash wget

# Создаем пользователя
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

# Копируем собранный JAR
COPY --from=build /app/target/internal-api.jar app.jar

# Создаем директории
RUN mkdir -p /tmp/uploads /tmp/scripts && \
    chmod 777 /tmp/uploads /tmp/scripts && \
    chown -R appuser:appgroup /tmp/uploads /tmp/scripts /app

USER appuser

EXPOSE 8081

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=5 \
    CMD wget -qO- http://localhost:8081/actuator/health || exit 1

ENTRYPOINT ["sh", "-c", "java ${JAVA_OPTS} -jar app.jar"]