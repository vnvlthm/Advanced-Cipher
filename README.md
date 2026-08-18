# Explorer Advance — Cipher / EFS

A **NiceGUI** desktop UI for Windows **Encrypting File System (EFS)**.

`cipher.exe` is the built-in command that lists and changes EFS encryption on
**NTFS** volumes. This app helps you find encrypted items, encrypt folders, and
learn every `cipher` switch — without parsing localized `E` / `U` text.

The scanner reads the NTFS **Encrypted** attribute (the same padlock Explorer
shows). Details still come from `cipher /c` and `cipher /y`.

## Features

| Tab | What it does |
|---|---|
| **Find encrypted** | Scan a folder or every local NTFS drive. List encrypted files and folders. Switch to **Folders with files** to list every parent folder that contains encrypted files (even if the folder itself is not marked encrypted), then decrypt that folder with `cipher /D /S`. Reveal in Explorer, copy the path, show `cipher /c`, or decrypt a selection. Sort **Folders first**. |
| **Encrypt** | Add folders, preview `cipher /E` (`/S` tree, `/H` hidden, `/B` stop on error), confirm, and encrypt as the current Windows user. |
| **Cipher manual** | What EFS is, quick start, safety, how it differs from BitLocker. |
| **Command map** | Every `cipher` switch with syntax, examples, and whether this app wraps it. |

`cipher /W` (wipe unused disk space) is documented and **not wired**.

## Requirements

- Windows, NTFS volumes (EFS does not exist on FAT / exFAT)
- Python 3.10+
- NiceGUI

## Install

```powershell
py -3 -m pip install -r requirements.txt
```

## Run

From this folder:

```powershell
py -3 main.py
```

The UI listens on **http://127.0.0.1:8766** only (not on the LAN). Settings are
saved locally to `user_config.json`, which is gitignored.

## Usage — Find encrypted

1. Type a path or click the folder button.
2. Leave **Recursive** and **Skip Windows / system folders** on unless you have a reason not to.
3. Or tick **All local NTFS drives** to walk every fixed NTFS volume.
4. Click **Find encrypted items**.
5. Double-click a row, or use **Reveal in Explorer**, to open that position in Explorer.
6. **cipher /c details** shows who can decrypt the file.
7. Check rows and click **Decrypt** to run `cipher /D` after a confirmation. Folders default to `/D /S`.
8. Use **Folders with files** to list unique parent folders of those files, then decrypt a folder in one step.
9. Use **Folders first** (or the Type column) to group folders above files.

## Usage — Encrypt

1. Open the **Encrypt** tab.
2. Type a folder path or click the folder button, then **Add folder**. You can add several.
3. Leave **Also encrypt everything inside** on unless you only want the folder mark (and files sitting directly in it).
4. Review the `cipher /E` command preview.
5. Click **Encrypt folders**, tick the certificate warning, and confirm.

The folder is marked so new files dropped in it stay encrypted. Do not “Run as
administrator” unless you want that admin account to own the encryption.

## Safety

- **`cipher /E`** encrypts for **this Windows user**. Without a certificate backup (`cipher /x`) or a recovery agent, a new profile cannot open the files.
- **`cipher /D`** rewrites the selected files as plaintext. Confirm the command list first. You must already be able to open the files.
- **`cipher /W`** is documented on the Command map but **not wired**. It overwrites *all free space on a volume*. There is no undo.
- Always encrypt the **parent folder** as well as the files.
- `cipher` cannot encrypt **read-only** files — clear that attribute first.
- See [SECURITY.md](SECURITY.md) for localhost binding and reporting.

## Project layout

```
main.py                   # NiceGUI app
cipher_ops.py             # NTFS scan, Explorer, cipher.exe wrappers
cipher_docs.py            # Manual text + command catalog
requirements.txt
user_config.example.json  # shape of the local settings file
```

## License

[MIT](LICENSE)
