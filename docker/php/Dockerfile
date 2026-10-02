# PHP >= 8.5 finds provider-only digests (EVP_MD_fetch fallback); PHP 8.4 and older only use EVP_get_digestbyname and cannot.
# Build from the repository root:  docker build -f docker/php/Dockerfile -t php-blake3 .
FROM php:8.5-cli AS build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential cmake ninja-build libssl-dev \
 && rm -rf /var/lib/apt/lists/*
COPY . /src
RUN cmake -S /src -B /build -G Ninja -DOPENSSL_INCLUDE_DIR=/usr/include && cmake --build /build

FROM php:8.5-cli
COPY --from=build /build/blake3.so /usr/local/lib/ossl-modules/blake3.so
COPY conf/openssl-blake3.cnf.example /etc/ssl/openssl-blake3.cnf
ENV OPENSSL_MODULES=/usr/local/lib/ossl-modules \
    OPENSSL_CONF=/etc/ssl/openssl-blake3.cnf
