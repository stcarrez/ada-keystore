FROM ciceron/ada-util:latest

MAINTAINER Stephane Carrez <Stephane.Carrez@gmail.com>

RUN apt-get update \
   && apt-get install -y libfuse-dev pkg-config

RUN mkdir -p /usr/src \
   && cd /usr/src \
   && git clone https://github.com/stcarrez/ada-keystore.git ada-keystore \
   && cd /usr/src/ada-keystore \
   && git submodule init \
   && git submodule update --recursive --remote \
   && ./configure --disable-shared --prefix=/usr --enable-fuse \
   && make -s \
   && make -s install

WORKDIR /usr/src
