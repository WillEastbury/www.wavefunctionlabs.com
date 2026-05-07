# Stage 1: Build picoweb from source
FROM tileforgeacr.azurecr.io/alpine:3.19 AS builder
RUN apk add --no-cache gcc musl-dev make linux-headers
WORKDIR /build
COPY picoweb/src/ src/
COPY picoweb/userspace/ userspace/
COPY picoweb/Makefile .
RUN make

# Stage 2: Runtime
FROM tileforgeacr.azurecr.io/alpine:3.19
RUN apk add --no-cache libgcc
RUN adduser -D -H picoweb
WORKDIR /app
COPY --from=builder /build/picoweb .
COPY wwwroot/ wwwroot/
USER picoweb
EXPOSE 8080
ENTRYPOINT ["./picoweb", "--io_uring"]
