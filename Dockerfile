FROM node:18-alpine

WORKDIR /app

# Copy manifest(s) first to leverage Docker layer caching
COPY package.json package-lock.json* ./

# Install ALL deps (including dev) so tsc is available in build stage
RUN npm install

# Copy sources & tsconfig
COPY tsconfig.json ./
COPY src ./src

# Build TypeScript to dist/
RUN npm run build

ENV PORT=8080
CMD ["node", "dist/server.js"]
