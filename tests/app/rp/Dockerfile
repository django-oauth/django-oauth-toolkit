FROM node:22-alpine AS builder
WORKDIR /app
COPY package*.json .
RUN npm ci
COPY . .
RUN npm run build
RUN npm prune --production

FROM node:22-alpine
WORKDIR /app
COPY --from=builder /app/build build/
COPY --from=builder /app/node_modules node_modules/
COPY package.json server.js ./
EXPOSE 3000
ENV NODE_ENV=production
# server.js wraps the built app so the OP's back-channel logout POST is not refused.
CMD [ "node", "server.js" ]