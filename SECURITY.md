# Security

Explorer Advance — Cipher is a **local Windows desktop helper**. It is not a
network service and it does not send files anywhere.

## What the app can change

- **Encrypt** (`cipher /E`) rewrites chosen files so only this Windows user
  (and any recovery agent) can open them.
- **Decrypt** (`cipher /D`) rewrites chosen files as plaintext on disk.

Both actions show the exact `cipher` command and require confirmation.
`cipher /W` (wipe free space) is documented in the Command map and is
**not wired** in the UI.

EFS is per user. Encrypting without a certificate backup (`cipher /x`) can
make files unreadable after a new Windows profile, a rebuilt PC, or a deleted
account. There is no cloud recovery.

## Localhost only

The UI listens on `127.0.0.1` so other machines on the LAN cannot open it.
Do not change the host to `0.0.0.0` unless you understand that anyone who
can reach that port can encrypt or decrypt as the logged-in Windows user.

## Reporting a problem

Open a GitHub issue. Do not attach encrypted personal files or `.pfx`
certificate backups.
