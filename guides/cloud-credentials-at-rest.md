+++
id = "cloud-credentials-at-rest"
category = "Secrets & credentials"
kind = "baseline"
severity = "critical"
control = "cloud-credentials-at-rest"
estimate = "20 min"
solution_name = "AWS IAM Identity Center (SSO) sessions"
solution_url = "https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html"
solution_husk = false
related_rules = []
+++

# Replace static cloud keys with SSO sessions

> ~/.aws/credentials is a non-expiring cloud key in a plaintext file every stealer greps for.

`aws configure` writes `aws_access_key_id` and `aws_secret_access_key` to `~/.aws/credentials`, a plaintext path credential stealers sweep by name. An SSO session token expires within hours, so the same theft yields nothing.

## Steps

1. Switch the CLI to short-lived SSO sessions (`sso_session` in `~/.aws/config`).
   ```command
aws configure sso
   ```
2. Delete the static key file (`rm ~/.aws/credentials`) and deactivate the keys in the IAM console. For tools without SSO support, set `credential_process` so keys come from a manager at call time.
3. For GCP, revoke stored application-default credentials and log in per session with `gcloud auth login` instead.
   ```command
gcloud auth application-default revoke
   ```

## Sources

- [AWS CLI: configuration and credential files](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)
- [GCP: application default credentials](https://docs.cloud.google.com/docs/authentication/application-default-credentials)
