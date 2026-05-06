# Folder Crypto

Local Obsidian plugin with two folder-protection modes.

## Folder lock

`Folder lock` is the master switch for locking the configured folder in Obsidian.

This mode locks a folder inside Obsidian. A locked folder shows a lock badge in the file explorer. When a file inside that folder is opened, the plugin asks for the password. After successful unlock, every file in that folder is readable until Obsidian is closed or `Lock all Folder Crypto folders` is run.

`Sync Finder folder lock` is the small switch under it. When enabled, folder locking also hides the underlying folder in Finder with `chflags hidden`. Unlocking shows it again with `chflags nohidden`. It does not change read permissions, so Obsidian can still open and scan the vault.

Commands:

- `Lock configured folder in Obsidian`
- `Unlock configured folder in Obsidian`
- `Lock all Folder Crypto folders`
- `Remove configured folder lock`

Folder right-click menu:

- `Lock folder in Obsidian`
- `Unlock folder in Obsidian`
- `Remove Obsidian folder lock`

This is still not encryption. Finder hiding is only a convenience layer and can be bypassed by other apps, Terminal, backups, sync history, admin access, or already-open cached content.

## Content lock

`Content lock` is the master switch for content encryption. Turning it on encrypts the configured folder after confirmation and password entry. Turning it off blocks new encryption operations; encrypted files are not automatically decrypted.

This mode rewrites file contents into an encrypted envelope. Use it when the file contents should be unreadable outside Obsidian too.

Commands:

- `Encrypt configured folder`
- `Decrypt configured folder`

Folder right-click menu:

- `Encrypt folder with password`
- `Decrypt folder with password`

Passwords for content encryption are never saved. Files are encrypted with AES-256-GCM and a PBKDF2-derived key.

If `Create plaintext backup` is enabled, `.ofc-backup` files are written next to encrypted files. This is safer during testing but leaves readable plaintext in the vault.
