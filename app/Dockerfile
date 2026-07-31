# VULNERABLE: Uso de tag no pinneado (Hadolint y Trivy lo detectarán)
FROM node:alpine
WORKDIR /usr/src/app
COPY package*.json ./

# Instalamos las herramientas nativas antes de NPM Install para que libxmljs compile
RUN apk add --no-cache python3 make g++ && npm install

COPY server.js .

# VULNERABLE: Falta la instrucción USER (Se ejecutará como root)
EXPOSE 3000
CMD [ "node", "server.js" ]