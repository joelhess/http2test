FROM microsoft/dotnet:1.1-runtime


RUN ls -lh /
RUN echo "deb-src ftp://ftp.de.debian.org/debian/ stable main contrib" >> /etc/apt/sources.list

RUN apt-get update && apt-get install -y wget git
# Get build requirements
# Some of these are used for the Python bindings
# this package also installs
RUN apt-get install -y g++ make binutils autoconf automake autotools-dev libtool pkg-config \
		zlib1g-dev libcunit1-dev libssl-dev libxml2-dev libev-dev libevent-dev libjansson-dev \
		libjemalloc-dev cython python3-dev python-setuptools && \
	# Build nghttp2 from source
 	git clone https://github.com/nghttp2/nghttp2.git && \
	cd nghttp2 && \
	autoreconf -i && \
	automake &&\
	autoconf &&\
	./configure && \
	make && \
	make install && \
	apt-get -y clean

# Upgrade and configure cURL
RUN cd ~ && \
	apt-get -y build-dep curl && \
	wget http://curl.haxx.se/download/curl-7.46.0.tar.bz2 --no-check-certificate && \
	tar -xvjf curl-7.46.0.tar.bz2 && \
	cd curl-7.46.0 && \
	./configure --with-nghttp2=/usr/local --with-ssl && \
	make && \
	make install && \
	ldconfig

RUN curl --http2 -I nghttp2.org

ARG source
WORKDIR /app
COPY . /app
#ENTRYPOINT ["/bin/bash"]
CMD ["dotnet", "http2test.dll"]
