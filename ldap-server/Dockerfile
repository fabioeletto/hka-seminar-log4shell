FROM openjdk:8-jdk

WORKDIR /app

RUN apt-get update && apt-get install -y git maven
RUN git clone https://github.com/fabioeletto/marshalsec
WORKDIR /app/marshalsec
RUN mvn clean package -DskipTests

COPY start.sh /app/
RUN chmod +x /app/start.sh

WORKDIR /app
CMD ["/app/start.sh"] 