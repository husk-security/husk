+++
id = "send-feedback"
category = "Using Husk"
kind = "recommendation"
severity = "info"
verification = "manual"
estimate = "2 min"
solution_name = "husk feedback"
solution_url = ""
solution_husk = true
related_rules = []
+++

# Tell the husk developers what you found

> A rough edge nobody reports stays rough for everyone.

Husk is built on what users report. Anything counts: something confusing, something broken, something missing, or something you liked. No account is needed; only your message, an optional reply email, and the husk version are sent.

## Steps

1. Send it from the terminal (or use the Send feedback item in the web UI's Help menu):
   ```command
husk feedback "What you want the developers to know"
   ```
2. Want a reply? Add a contact address:
   ```command
husk feedback --contact you@example.com "Your message"
   ```

## Sources

- [Husk on GitHub (bug reports and issues)](https://github.com/husk-security/husk/issues)
