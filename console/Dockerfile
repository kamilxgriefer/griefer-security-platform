# GRIEFER Console — Next.js standalone build on a non-root Node image.

FROM node:22-alpine AS deps
WORKDIR /app
RUN corepack enable
# pnpm-workspace.yaml carries the build-script allowlist. Without it pnpm
# refuses to install rather than silently running an unapproved postinstall,
# which is the correct behaviour and the reason it must be copied here.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

FROM node:22-alpine AS build
WORKDIR /app
RUN corepack enable
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
RUN pnpm build

FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0

# Strip the package managers out of the runtime image.
#
# The standalone server runs `node server.js` and never invokes one. Their
# bundled dependencies — npm vendors tar, brace-expansion and a few dozen
# others — are otherwise scanned as part of this image and carry CVEs that have
# nothing to do with GRIEFER. Removing them is a real reduction in attack
# surface rather than a suppressed finding: a package manager is also the most
# useful thing an attacker could find after reaching code execution here.
RUN rm -rf \
        /usr/local/lib/node_modules/npm \
        /usr/local/lib/node_modules/corepack \
        /usr/local/bin/npm \
        /usr/local/bin/npx \
        /usr/local/bin/corepack \
        /opt/yarn-* \
        /usr/local/bin/yarn \
        /usr/local/bin/yarnpkg

# Next.js "standalone" output ships only the server and the files it actually
# imports, which keeps the runtime image free of the build toolchain.
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
COPY --from=build /app/public ./public

USER node
EXPOSE 3000

CMD ["node", "server.js"]
