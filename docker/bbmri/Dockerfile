# Custom dockerfile for flexibility, mostly adheres to what web-and-data/Dockerfile does.

FROM node:15.2.1-bullseye AS frontend-build
WORKDIR /frontend

COPY cbioportal-frontend/package.json cbioportal-frontend/yarn.lock ./
RUN yarn set version 1.22.5 || true
RUN yarn install --frozen-lockfile

COPY cbioportal-frontend/ ./
RUN yarn run buildDLL:dev && yarn run buildModules && yarn run build-production

# package the built frontend as a maven artifact
FROM maven:3-eclipse-temurin-21 AS frontend-maven
WORKDIR /frontend-artifact

COPY --from=frontend-build /frontend /frontend-src
WORKDIR /frontend-src

# this assumes the frontend repo contains the maven packaging setup used by cBioPortal releases
RUN mvn install -DskipTests

FROM maven:3-eclipse-temurin-21 AS build
WORKDIR /cbioportal

COPY pom.xml /cbioportal/
COPY version.sh /cbioportal/

RUN mvn dependency:go-offline --fail-never

COPY . /cbioportal

# copy locally installed frontend artifact into this build stage's maven repo
COPY --from=frontend-maven /root/.m2 /root/.m2

RUN mvn clean package -DskipTests \
    -Dfrontend.version=<your-custom-frontend-version> \
    -Dfrontend.groupId=<your-frontend-groupId> -q

RUN mkdir -p target/dependency && (cd target/dependency; jar -xf ../*-exec.jar)

FROM eclipse-temurin:21

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    default-mysql-client \
    default-libmysqlclient-dev \
    python3 \
    python3-setuptools \
    python3-dev \
    python3-pip \
    unzip \
 && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /cbioportal
RUN wget https://github.com/cBioPortal/cbioportal-core/releases/download/v1.0.11/core-1.0.11.jar -P core/ \
 && cd core \
 && jar -xf core-1.0.11.jar scripts/ requirements.txt \
 && chmod -R a+x scripts/ \
 && cd ..

COPY --from=build /cbioportal/src/main/resources/db-scripts /cbioportal/db-scripts

RUN pip3 install --break-system-packages -r /core/requirements.txt
RUN find /core/scripts/ -type f -executable \! -name '*.pl' -print0 | xargs -0 -- ln -st /usr/local/bin

ENV PORTAL_WEB_HOME=/cbioportal-webapp
ENV PORTAL_HOME=/cbioportal
ENV JAVA_OPTS="-Xms2G -Xmx8G"
ENV WEBAPP_OPTS=

ARG DEPENDENCY=/cbioportal/target/dependency
RUN mkdir -p $PORTAL_WEB_HOME
COPY --from=build ${DEPENDENCY}/BOOT-INF/lib $PORTAL_WEB_HOME/lib/
COPY --from=build ${DEPENDENCY}/META-INF $PORTAL_WEB_HOME/META-INF/
COPY --from=build ${DEPENDENCY}/BOOT-INF/classes $PORTAL_WEB_HOME/

COPY --from=build /cbioportal/docker/web-and-data/docker-entrypoint.sh /usr/local/bin/
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["sh", "-c", "java $(echo $JAVA_OPTS) -cp /cbioportal-webapp:/cbioportal-webapp/lib/* org.cbioportal.application.PortalApplication $(echo $WEBAPP_OPTS)"]