FROM ciceron/ada-util:latest

MAINTAINER Stephane Carrez <Stephane.Carrez@gmail.com>

RUN mkdir -p /usr/src \
   && cd /usr/src \
   && git clone https://github.com/stcarrez/ada-keystore.git ada-keystore \
   && cd /usr/src/ada-keystore \
   && ./configure --disable-shared --prefix=/usr \
   && make -s \
   && make -s install

WORKDIR /usr/src
