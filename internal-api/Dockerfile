FROM maven:3.9.8-eclipse-temurin-21-alpine AS build
WORKDIR /build
COPY pom.xml .
COPY internal-api/pom.xml internal-api/
COPY internal-api/src internal-api/src/
RUN mkdir -p public-api/src/main/java && \
    echo '<project><modelVersion>4.0.0</modelVersion><groupId>by.tms</groupId><artifactId>public-api</artifactId><version>1.0.0</version></project>' > public-api/pom.xml
RUN mvn clean package -pl internal-api -am -DskipTests -B

FROM eclipse-temurin:21-jre-alpine
RUN apk add --no-cache curl bash
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
WORKDIR /app
COPY --from=build /build/internal-api/target/internal-api.jar app.jar
RUN mkdir -p /tmp/uploads /tmp/scripts && \
    chmod 777 /tmp/uploads /tmp/scripts && \
    chown -R appuser:appgroup /tmp /app
USER appuser
EXPOSE 8082
ENTRYPOINT ["sh", "-c", "java ${JAVA_OPTS} -jar app.jar"]
