# VULNERABLE: Uso de tag no pinneado
FROM node:alpine
WORKDIR /usr/src/app
COPY package*.json ./
# Instalamos python y herramientas de build antes de npm install
RUN apk add --no-cache python3 make g++ && npm install
COPY server.js .
EXPOSE 3000
CMD [ "node", "server.js" ]