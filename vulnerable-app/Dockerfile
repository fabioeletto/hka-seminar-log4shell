FROM --platform=linux/amd64 maven:3.6.3-openjdk-8 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests

FROM --platform=linux/amd64 openjdk:8-jre
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-Dcom.sun.jndi.ldap.object.trustURLCodebase=true", "-Dcom.sun.jndi.rmi.object.trustURLCodebase=true", "-Dlog4j2.formatMsgNoLookups=false", "-jar", "app.jar"] 