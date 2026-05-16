# Stage 1: Build picoweb from source
FROM tileforgeacr.azurecr.io/alpine:3.19 AS builder
RUN apk add --no-cache gcc musl-dev make linux-headers
WORKDIR /build
COPY picoweb/src/ src/
COPY picoweb/userspace/ userspace/
COPY picoweb/Makefile .
# v18rsa-selfcheck2: fixed self-check (65537 not 65536)
RUN find . -name '*.o' -delete && make CFLAGS="-O3 -Wall -Wextra -std=c11 -D_GNU_SOURCE -fno-strict-aliasing -fstack-protector-strong -fomit-frame-pointer" LDFLAGS="-O3"

# Stage 2: Runtime
FROM tileforgeacr.azurecr.io/alpine:3.19
RUN apk add --no-cache libgcc iproute2
WORKDIR /app
COPY --from=builder /build/picoweb .
COPY wwwroot/ wwwroot/
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh
# Drop gzip variants from the jumptable (keep brotli + identity).
# Modern browsers all support `br`; saves ~10-15% of arena RAM.
ENV PICOWEB_NO_GZIP=1
EXPOSE 443
ENTRYPOINT ["./entrypoint.sh"]
