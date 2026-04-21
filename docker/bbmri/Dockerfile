FROM node:22.18.0-bullseye AS frontend-build
WORKDIR /frontend

COPY --from=frontend-src . ./

ARG BRANCH_ENV=master
ENV BRANCH_ENV=${BRANCH_ENV}

RUN corepack enable
RUN corepack prepare yarn@1.22.22 --activate

RUN node --version
RUN yarn --version

RUN yarn install
RUN yarn run build

FROM maven:3-eclipse-temurin-21 AS frontend-maven
WORKDIR /frontend-src
COPY --from=frontend-build /frontend /frontend-src

# Only keep this if the frontend repo actually contains a valid Maven packaging setup
RUN FRONTEND_GROUP_ID="$(mvn -q -DforceStdout help:evaluate -Dexpression=project.groupId)" && \
    FRONTEND_VERSION="$(mvn -q -DforceStdout help:evaluate -Dexpression=project.version)" && \
    echo "$FRONTEND_GROUP_ID" > /tmp/frontend.groupId && \
    echo "$FRONTEND_VERSION" > /tmp/frontend.version && \
    mvn install -DskipTests -Dgpg.skip=true


FROM maven:3-eclipse-temurin-21 AS build
WORKDIR /cbioportal

COPY pom.xml /cbioportal/
COPY version.sh /cbioportal/
RUN mvn dependency:go-offline --fail-never

COPY . /cbioportal

COPY --from=frontend-maven /root/.m2 /root/.m2
COPY --from=frontend-maven /tmp/frontend.groupId /tmp/frontend.groupId
COPY --from=frontend-maven /tmp/frontend.version /tmp/frontend.version

ARG FRONTEND_GROUP_ID=io.github.cbioportal
ARG FRONTEND_VERSION=local

RUN FRONTEND_GROUP_ID="$(cat /tmp/frontend.groupId)" && \
    FRONTEND_VERSION="$(cat /tmp/frontend.version)" && \
    echo "FRONTEND_GROUP_ID=$FRONTEND_GROUP_ID" && \
    echo "FRONTEND_VERSION=$FRONTEND_VERSION" && \
    mvn clean package -DskipTests -Dspotless.check.skip=true \
      -Dfrontend.groupId="${FRONTEND_GROUP_ID}" \
      -Dfrontend.version="${FRONTEND_VERSION}" -q

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
RUN wget https://github.com/cBioPortal/cbioportal-core/releases/download/v1.0.16/core-1.0.16.jar -P core/ \
 && cd core \
 && jar -xf core-1.0.16.jar scripts/ requirements.txt \
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