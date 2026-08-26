# syntax=docker/dockerfile:1
# Multi-stage build: one ARG-tagged base and one digest-pinned base.
ARG NODE_VERSION=20.11.1

FROM node:${NODE_VERSION}-bookworm-slim AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci

# Distroless base pinned by digest (the only truly immutable form).
FROM gcr.io/distroless/nodejs20-debian12@sha256:3d1d2c8e3f5b9a7c6e4d2b1a0f9e8d7c6b5a4938271605f4e3d2c1b0a9f8e7d6 AS runtime
WORKDIR /app
COPY --from=builder /app /app
CMD ["server.js"]

# 'builder' / 'runtime' stage aliases are NOT packages; 'scratch' is skipped.
FROM scratch
