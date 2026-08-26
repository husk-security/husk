+++
id = "dockerignore-coverage"
category = "Local environment"
kind = "baseline"
severity = "high"
control = "dockerignore-coverage"
estimate = "5 min per repo"
solution_name = ".dockerignore + RUN --mount=type=secret"
solution_url = "https://docs.docker.com/build/building/secrets/"
solution_husk = false
related_rules = ["dockerfile-secret"]
+++

# Keep secrets and .git out of the build context

> COPY . . bakes dotenv files and the whole .git history into layers anyone who pulls the image can read.

`COPY . .` bakes dotenv files and the whole `.git` history into a layer anyone who pulls the image can read. `ARG` and `ENV` literals persist in the final image too.

## Steps

1. Add the four entries to `.dockerignore` in the build-context directory.
   ```command
.env*
.git
*.pem
*.key
   ```
2. Pass build-time secrets with `RUN --mount=type=secret,id=npmrc npm ci`, not `ARG NPM_TOKEN=...`; the mount never enters a layer.
3. Rotate any secret in an image that was ever pushed; deleting the tag does not delete the layer.

## Sources

- [Docker build secrets](https://docs.docker.com/build/building/secrets/)
