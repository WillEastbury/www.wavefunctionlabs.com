# Stage 1: Build picoweb from source
FROM alpine:3.19 AS builder
RUN apk add --no-cache gcc musl-dev make linux-headers
WORKDIR /build
COPY picoweb/src/ src/
COPY picoweb/Makefile .
RUN make

# Stage 2: Runtime
FROM alpine:3.19
RUN apk add --no-cache libgcc \
 && adduser -D -u 1000 picoweb
WORKDIR /app
COPY --from=builder /build/picoweb .
COPY wwwroot/ wwwroot/
RUN chown -R picoweb:picoweb /app
USER picoweb
EXPOSE 8080
CMD ["./picoweb", "8080", "wwwroot", "1", "100", "0", "64"]
