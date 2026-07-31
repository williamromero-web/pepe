# VULNERABLE: Uso de tag no pinneado
FROM node:alpine
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm install
COPY server.js .
EXPOSE 3000
CMD [ "node", "server.js" ]