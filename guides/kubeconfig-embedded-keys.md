+++
id = "kubeconfig-embedded-keys"
category = "Secrets & credentials"
kind = "baseline"
severity = "high"
control = "kubeconfig-embedded-keys"
estimate = "15 min"
solution_name = "exec credential plugin (cloud CLI)"
solution_url = "https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/"
solution_husk = false
related_rules = []
+++

# Keep private keys and tokens out of kubeconfig

> client-key-data is a cluster private key inside a YAML file people paste into chat.

`client-key-data:` embeds a base64 PEM private key, and a static `token:` never expires. An `exec:` plugin fetches short-lived credentials per call, but it runs an arbitrary command, so read any kubeconfig you are sent before using it. When `$KUBECONFIG` is set, kubectl merges that list and skips `~/.kube/config`.

## Steps

1. See what is embedded.
   ```command
grep -E "client-key-data|client-certificate-data|token:" ~/.kube/config
   ```
2. Regenerate with your provider's exec plugin (`gcloud container clusters get-credentials`, `az aks get-credentials`), then revoke the embedded ServiceAccount token or client certificate.
   ```command
aws eks update-kubeconfig --name <cluster>
   ```
3. Keep the file private.
   ```command
chmod 600 ~/.kube/config
   ```

## Sources

- [Kubernetes: client authentication (exec plugins)](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins)
