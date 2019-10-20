FROM ciceron/ada-awa:latest

MAINTAINER Stephane Carrez <Stephane.Carrez@gmail.com>

RUN mkdir -p /usr/src \
   && cd /usr/src \
   && git clone https://github.com/stcarrez/ada-util.git ada-util \
   && git clone https://github.com/stcarrez/ada-keystore.git ada-keystore \
   && cd ada-util \
   && ./configure --disable-shared --prefix=/usr \
   && make -s \
   && make -s install \
   && cd /usr/src/ada-keystore \
   && ./configure --disable-shared --prefix=/usr \
   && make -s \
   && make -s install

WORKDIR /usr/src
