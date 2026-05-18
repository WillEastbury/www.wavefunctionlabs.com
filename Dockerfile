# Stage 1: Build picoweb from source
FROM tileforgeacr.azurecr.io/alpine:3.19 AS builder
RUN apk add --no-cache gcc musl-dev make linux-headers brotli-dev
WORKDIR /build
COPY picoweb/src/ src/
COPY picoweb/userspace/ userspace/
COPY picoweb/Makefile .
# v32-b2pls-stats: Brotli-primary stats from the cheaper B2pls nodepool
RUN find . -name '*.o' -delete && make CFLAGS="-O3 -Wall -Wextra -std=c11 -D_GNU_SOURCE -fno-strict-aliasing -fstack-protector-strong -fomit-frame-pointer" LDFLAGS="-O3"

# Stage 2: Runtime
FROM tileforgeacr.azurecr.io/alpine:3.19
RUN apk add --no-cache libgcc iproute2 brotli-libs
WORKDIR /app
COPY --from=builder /build/picoweb .
COPY wwwroot/ wwwroot/
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh
# Drop gzip variants from the jumptable.
ENV PICOWEB_NO_GZIP=1
# Store Brotli as the resident representation for compressible files.
# Rare identity clients are decoded through a preallocated worker scratch.
ENV PICOWEB_BROTLI_PRIMARY=1
EXPOSE 443
ENTRYPOINT ["./entrypoint.sh"]
