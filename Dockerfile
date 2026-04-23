FROM node:20-alpine
WORKDIR /app
COPY server.js .
RUN mkdir -p public
COPY index.html public/index.html
COPY phi.html public/phi.html
COPY wavefunction.html public/wavefunction.html
EXPOSE 80
CMD ["node", "server.js"]
