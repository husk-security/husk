+++
id = "full-disk-encryption"
category = "Machine & identity"
kind = "baseline"
severity = "high"
control = "full-disk-encryption"
estimate = "30 min"
solution_name = "Platform disk encryption (LUKS, FileVault, BitLocker)"
solution_url = ""
solution_husk = false
related_rules = []
+++

# Encrypt the disk

> Every plaintext credential on this machine is a theft finding only if the disk is readable.

`~/.aws/credentials`, `~/.npmrc`, `~/.kube/config`, and SSH keys are files; pulling an unencrypted drive reads them without a password.

## Steps

1. Linux: check for a dm-crypt mapping.
   ```command
lsblk -o NAME,FSTYPE,MOUNTPOINT
   ```
2. If root is unencrypted, `cryptsetup reencrypt --encrypt` (cryptsetup 2.2+, LUKS2) encrypts in place, no reinstall; back up first, the machine is unusable while it runs.
3. macOS: FileVault.
   Platform: macOS
   ```command
fdesetup status
   ```
4. Windows: BitLocker; store the recovery key off this machine.
   Platform: Windows
   ```command
manage-bde -status
   ```

## Sources

- [cryptsetup-reencrypt(8)](https://man7.org/linux/man-pages/man8/cryptsetup-reencrypt.8.html)
- [Apple Platform Security: FileVault](https://support.apple.com/guide/security/volume-encryption-with-filevault-sec4c6dc1b6e/web)
