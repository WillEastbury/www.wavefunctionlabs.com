# Stage 1: Build picoweb from source
FROM alpine:3.19 AS builder
RUN apk add --no-cache gcc musl-dev make linux-headers
WORKDIR /build
COPY picoweb/src/ src/
COPY picoweb/Makefile .
RUN make

# Stage 2: Runtime
FROM alpine:3.19
RUN apk add --no-cache libgcc
WORKDIR /app
COPY --from=builder /build/picoweb .
COPY wwwroot/ wwwroot/
# Duplicate vhost for www. and _default (picoweb uses lstat, can't follow symlinks)
RUN cp -a wwwroot/wavefunctionlabs.com wwwroot/www.wavefunctionlabs.com \
 && cp -a wwwroot/wavefunctionlabs.com wwwroot/_default
EXPOSE 80
CMD ["./picoweb", "80", "wwwroot", "1"]
