# DissQus relay server.
#
# glibc base (bookworm), NOT Alpine/musl: lib/hqc.ts dlopen's the native
# post-quantum lib (lib/libhqc_x86.so) which links libc.so.6 — it will not
# load under musl. The image is therefore linux/amd64 (the .so is x86_64);
# build on the VM or with `--platform=linux/amd64`.
FROM node:22-bookworm-slim

ENV NODE_ENV=production
WORKDIR /app

# Install deps first for layer caching. tsx is a real *dependency* (not dev), so
# it's installed even with NODE_ENV=production — the server runs the TypeScript
# directly via `node --import tsx`. typescript/@types stay dev-only and are
# correctly omitted from the production image.
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

# App source (the native .so under lib/ is copied with it; see .dockerignore).
COPY . .

# The deploy bundle: everything a VM needs to RUN this image, carried inside the
# image itself. The VMs hold no git checkout — the agent (infra/deploy/agent)
# resolves a channel tag to a digest, pulls, and extracts /deploy-bundle out of
# it. Shipping the manifests with the code they describe means the compose file,
# emqx.conf and nginx.conf can never drift from the running binary, and it keeps
# the property hqcat-apply-nginx depended on when it read from a git ref: the
# config comes from an immutable, reviewed artifact the deploy host cannot edit.
#
# Comes from a named build context, so the main context stays just the server:
#   docker buildx build --build-context deploy=infra/deploy services/server
# Files are listed explicitly rather than copied wholesale: a stray secrets/ or
# server.env in a local working tree can never be baked in, and only what a VM
# actually executes ships to it. Of infra/deploy/scripts/ that is exactly two —
# gen-runtime-secrets.sh (bind-mounted by secrets-init) and hqcat-apply-nginx
# (run by the agent). The rest (harden-vm.sh, collect-apple-env.sh,
# set-ci-secrets.sh, emqx-dashboard.sh, compute-spki-pins.sh, apply-nginx.sh)
# are operator tools that belong on a laptop; harden-vm.sh is piped in over ssh
# when needed rather than left lying on the box.
# release.env carries the NON-SECRET config GitHub is the source of truth for
# (the Apple bundle ids and key ids, today). The release workflow writes it
# from repository variables just before this build, so the values reach a host
# by being PULLED inside an immutable digest — GitHub still never touches a
# server. It is listed in compose ahead of server.env, so the host overrides it.
# It is explicitly not a place for secrets: anyone who can pull the image can
# read it.
COPY --from=deploy docker-compose.yml docker-compose.preprod.yml nginx.conf release.env /deploy-bundle/
COPY --from=deploy emqx/ /deploy-bundle/emqx/
COPY --from=deploy scripts/gen-runtime-secrets.sh scripts/hqcat-apply-nginx /deploy-bundle/scripts/
COPY --from=deploy agent/ /deploy-bundle/agent/

# Drop privileges. The bundled `node` user owns the workdir for any runtime
# writes (e.g. the bot's .bot-seed / .bot-state.json when no volume is mounted).
RUN chown -R node:node /app
USER node

EXPOSE 8080

# Liveness: the slim image has no curl/wget, so probe with node itself.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "require('http').get('http://127.0.0.1:'+(process.env.PORT||8080)+'/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

# Run via `node --import tsx` rather than `npx tsx` or the `.bin/tsx` shebang:
#   - `npx` can touch an npm cache (breaks a read-only rootfs) / fetch on miss.
#   - execing `.bin/tsx` makes Node load the symlink path as the main module,
#     which fails to resolve.
# `--import tsx` resolves the tsx PACKAGE and registers its in-memory loader, so
# it works under read-only root + cap_drop: ALL + no-new-privileges (writes
# nothing outside the mounted volumes / tmpfs).
CMD ["node", "--import", "tsx", "server.ts"]
