FROM openjdk:8-jdk-alpine
MAINTAINER donghoang
VOLUME /tmp
EXPOSE 8080
ADD authentication-api-0.0.1-SNAPSHOT.jar springbootpostgresqldocker.jar
ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom","-jar","/springbootpostgresqldocker.jar"]