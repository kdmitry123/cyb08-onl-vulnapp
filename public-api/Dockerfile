FROM maven:3.9.8-eclipse-temurin-21-alpine AS build
WORKDIR /build
COPY pom.xml .
COPY public-api/pom.xml public-api/
COPY public-api/src public-api/src/
RUN mkdir -p internal-api/src/main/java && \
    echo '<project><modelVersion>4.0.0</modelVersion><groupId>by.tms</groupId><artifactId>internal-api</artifactId><version>1.0.0</version></project>' > internal-api/pom.xml
RUN mvn clean package -pl public-api -am -DskipTests -B

FROM eclipse-temurin:21-jre-alpine
RUN apk add --no-cache curl bash
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
WORKDIR /app
COPY --from=build /build/public-api/target/public-api.jar app.jar
RUN mkdir -p /tmp/uploads && \
    chmod 777 /tmp/uploads && \
    chown -R appuser:appgroup /tmp /app
USER appuser
EXPOSE 8080
ENTRYPOINT ["sh", "-c", "java ${JAVA_OPTS} -jar app.jar"]
