FROM node:22-alpine AS base
WORKDIR /app
COPY package*.json .


FROM base AS builder
RUN npm ci
COPY . .
RUN npm run build
RUN npm prune --production

FROM node:22-alpine
WORKDIR /app
COPY --from=builder /app/build build/
COPY --from=builder /app/node_modules node_modules/
COPY package.json .
EXPOSE 3000
ENV NODE_ENV=production
CMD [ "node", "build" ]

FROM base AS dev
RUN npm install -g pnpm
RUN pnpm install
