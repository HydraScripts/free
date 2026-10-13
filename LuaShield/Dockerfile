# LuaShield authentication server
FROM node:20-alpine

WORKDIR /app
ENV NODE_ENV=production

# Install dependencies first for layer caching. The Prisma CLI (a devDependency) is needed to
# generate the client, so install everything, generate, then drop dev deps.
COPY package.json package-lock.json ./
RUN npm ci
COPY prisma ./prisma
RUN npx prisma generate
RUN npm prune --omit=dev

COPY . .

# Run as the built-in unprivileged user.
RUN mkdir -p files && chown -R node:node /app
USER node

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "server/index.js"]
