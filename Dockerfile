# Stage 1: Build the Native Rust Extension
FROM node:20-bookworm AS builder

# Install Rust toolchain
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /app

# Copy dependency files
COPY package*.json ./
# Install all dependencies (including devDependencies required for NAPI-RS build)
RUN npm install

# Copy source and build the Linux .node binary
COPY . .
RUN npm run build

# Stage 2: Lean Production Runtime
FROM node:20-bookworm-slim

WORKDIR /app

# Copy package files and install production dependencies only
COPY package*.json ./
RUN npm install --omit=dev

# Copy the compiled Rust binary and Node.js source from the builder stage
COPY --from=builder /app/ ./

# Cloud Run dynamically assigns the PORT, but 8080 is the default expectation
ENV PORT=8080
EXPOSE 8080

CMD ["npm", "start"]
