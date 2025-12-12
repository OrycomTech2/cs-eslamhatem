# ---- Base image ----
FROM node:20.18.0-slim

# ---- System deps (needed for bcrypt, sharp, etc.) ----
RUN apt-get update -qq && \
    apt-get install --no-install-recommends -y \
      build-essential \
      node-gyp \
      pkg-config \
      python-is-python3 && \
    rm -rf /var/lib/apt/lists/*

# ---- App directory ----
WORKDIR /app

# ---- Copy package files first (better cache) ----
COPY package.json package-lock.json ./

# ---- Install dependencies (FIX HERE) ----
# npm ci FAILS because lock file is out of sync
# npm install safely resolves AWS SDK version drift
RUN npm install --omit=dev --no-audit --no-fund

# ---- Copy rest of app ----
COPY . .

# ---- Environment ----
ENV NODE_ENV=production
ENV PORT=8080

# ---- Expose port ----
EXPOSE 8080

# ---- Start app ----
CMD ["npm", "run", "start"]
