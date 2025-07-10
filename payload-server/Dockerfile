FROM eclipse-temurin:8-jdk

WORKDIR /app

COPY PayloadServer.java .
COPY Exploit.java .
COPY logging.properties .

RUN javac PayloadServer.java Exploit.java

EXPOSE 8000

CMD ["java", "-Djava.util.logging.config.file=logging.properties", "PayloadServer"] 