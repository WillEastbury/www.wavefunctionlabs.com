FROM tileforgeacr.azurecr.io/nginx:alpine
COPY index.html /usr/share/nginx/html/index.html
COPY phi.html /usr/share/nginx/html/phi.html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
