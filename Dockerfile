# Multi-stage production build
FROM node:20-alpine AS builder
WORKDIR /app

# Copy dependency definitions and TypeScript config
COPY package*.json tsconfig.json ./
RUN npm ci

# Copy source code and compile
COPY src/ ./src/
RUN npm run build

# Production runtime stage
FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production

COPY package*.json ./
RUN npm ci --only=production
COPY --from=builder /app/dist ./dist

EXPOSE 8080
CMD ["node", "dist/server.js"]
