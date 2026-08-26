+++
id = "docker-socket-exposure"
category = "Local environment"
kind = "baseline"
severity = "high"
control = "docker-socket-exposure"
estimate = "10 min"
solution_name = "docker-socket-proxy (filtering proxy)"
solution_url = "https://github.com/Tecnativa/docker-socket-proxy"
solution_husk = false
related_rules = ["docker-socket-mount", "compose-privileged"]
+++

# Never hand a container the Docker socket

> A process that can write to /var/run/docker.sock can start a privileged container, which is root on the host.

A process that can write to `/var/run/docker.sock` can start a privileged container, which is root on the host. `privileged: true`, or `cap_add` with `SYS_ADMIN` or `ALL`, erases the same boundary without the socket, and `DOCKER_HOST=tcp://` without TLS hands the daemon to anyone who can reach the port.

## Steps

1. Delete the `/var/run/docker.sock` line from `volumes:`; a tool needing the daemon API goes behind docker-socket-proxy, only its endpoints enabled.
2. Remove `privileged: true`; replace `SYS_ADMIN` with `cap_drop: [ALL]` plus the one capability the service needs.
3. For a remote daemon, `DOCKER_HOST=ssh://user@host`, or tcp with `DOCKER_TLS_VERIFY=1` and `DOCKER_CERT_PATH`.

## Sources

- [Docker: protect the daemon socket](https://docs.docker.com/engine/security/protect-access/)
