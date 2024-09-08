### 1. stage: create build image
FROM ciceron/alire-bookworm:latest AS ada-keystore

MAINTAINER Stephane Carrez <Stephane.Carrez@gmail.com>

# We have to setup a timezone otherwise installation of tzdata will hang.
ENV TZ=Europe/Paris
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get update \
   && apt-get install -y libfuse-dev

RUN mkdir -p /usr/src \
   && cd /usr/src \
   && git clone https://github.com/stcarrez/ada-keystore.git ada-keystore \
   && cd /usr/src/ada-keystore \
   && make -s \
   && make -s install

WORKDIR /usr/src

### 2. stage: create akt image (without GNAT compiler and Ada Keystore sources)

FROM debian:bookworm AS akt

ENV BUILD_PREFIX /usr/local
ENV INSTALL_PREFIX /usr/local

RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl3 man libfuse2
COPY --from=ada-keystore ${BUILD_PREFIX}/bin/akt ${INSTALL_PREFIX}/bin/
COPY --from=ada-keystore ${BUILD_PREFIX}/share/man/man1/akt.1 ${INSTALL_PREFIX}/share/man/man1/
COPY --from=ada-keystore ${BUILD_PREFIX}/share/akt/ ${INSTALL_PREFIX}/share/akt

WORKDIR /usr/src
