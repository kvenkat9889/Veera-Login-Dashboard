# Backend/Dockerfile

FROM node:18

WORKDIR /app

COPY package*.json ./
RUN npm install

# Copy only the Backend folder
COPY . .

# Start from inside Backend subfolder
WORKDIR /app/Backend

EXPOSE 3081

CMD ["node", "server.js"]

