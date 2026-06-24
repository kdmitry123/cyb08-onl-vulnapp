FROM maven:3.9.8-eclipse-temurin-21-alpine AS build
WORKDIR /build
COPY pom.xml .
COPY internal-api/pom.xml internal-api/
COPY internal-api/src internal-api/src/
COPY public-api/pom.xml public-api/
COPY public-api/src public-api/src/
RUN mvn clean package -DskipTests -B