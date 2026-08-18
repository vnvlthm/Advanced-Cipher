"""
Reference text for the Cipher manual and command-map tabs.

Switches match the `cipher /?` shipped with current Windows (including
`/P`, `/FLUSHCACHE`, `/USER`, and `/ECC`), plus the official Microsoft docs.
"""

from __future__ import annotations

from typing import TypedDict


class CipherCommand(TypedDict):
    id: str
    switch: str
    title: str
    syntax: str
    group: str
    status: str  # ready | inspect | planned
    danger: bool
    summary: str
    details: str
    examples: list[str]


GROUPS = [
    "Inspect",
    "Encrypt & decrypt",
    "Find & update keys",
    "Certificates & backup",
    "Recovery",
    "Share with other users",
    "Maintenance",
]


OVERVIEW_MD = """
### What `cipher` is

**`cipher.exe`** is the built-in Windows command that **displays or changes
Encrypting File System (EFS)** encryption on **NTFS** volumes. It is not
BitLocker. BitLocker encrypts a whole drive; EFS encrypts **individual files
and folders** so that only the user (and any recovery agent) can open them.

- Works **only on NTFS**. FAT32, exFAT, and most network shares cannot hold EFS.
- In Explorer, an EFS item shows a **padlock** overlay on its icon.
- `cipher` with **no switches** lists the current folder: **`E`** = encrypted,
  **`U`** = unencrypted.
- Help is localized. On a French Windows the banners are in French, but the
  **switches stay the same** (`/E`, `/D`, `/U`, …).

### EFS in one paragraph

When you encrypt a file, Windows generates a random file encryption key (FEK),
encrypts the file with it, then protects that FEK with **your EFS certificate**.
Without that certificate (or a recovery-agent certificate), the file is
unreadable — even to an administrator who takes ownership of the disk. **Back
up your EFS certificate** (`/X`) before you rely on encryption.

### Golden rules

1. Encrypt the **file and its parent folder**. If only the file is encrypted,
   a save/rename can write a new unencrypted copy.
2. EFS follows **your Windows user profile**. A new PC, a rebuilt profile, or
   a deleted user account cannot open the files unless a backup `.pfx` or a
   recovery agent exists.
3. Copying an EFS file to ZIP, FAT, exFAT, or some USB sticks **decrypts it
   in transit** (the copy is plaintext).
4. `cipher` **cannot encrypt read-only** files — clear the read-only attribute
   first.
"""


QUICKSTART_MD = """
### 1. See what is encrypted in a folder

```bat
cd /d C:\\Users\\You\\Documents
cipher
```

Lines starting with **`E`** are encrypted. Lines starting with **`U`** are not.
The banner also says whether *new* files dropped in that folder will be
encrypted automatically.

### 2. Inspect one file (who can open it)

```bat
cipher /c "C:\\Users\\You\\Documents\\secret.xlsx"
```

This prints the users / certificates that can decrypt the file.

### 3. Encrypt a folder (and mark it so new files stay encrypted)

```bat
cipher /e /s:"C:\\Users\\You\\Private"
```

`/E` encrypts. `/S:` walks every subdirectory.

### 4. Decrypt

```bat
cipher /d /s:"C:\\Users\\You\\Private"
```

### 5. Find every encrypted file on local NTFS drives

```bat
cipher /u /n
```

`/N` means *list only* — do not rotate keys. This is the official whole-disk
search. The **Find encrypted** tab in this app does the same job by reading
the Encrypted NTFS attribute (faster, and independent of the UI language).

### 6. Back up the certificate that unlocks your files

```bat
cipher /x C:\\Backup\\my-efs-keys
```

Windows writes a `.pfx`. Store it **off the same disk**, with a password you
will still know in two years.

### 7. Open a Command Prompt as yourself

EFS is per-user. A command run as another account encrypts for *that*
account, not yours. You rarely need “Run as administrator” for your own files.
"""


SAFETY_MD = """
### Safe to run anytime

| Command | Why it is safe |
|---|---|
| `cipher` | Read-only listing |
| `cipher /c` | Read-only details |
| `cipher /y` | Shows your current certificate thumbprint |
| `cipher /u /n` | Lists encrypted files, does not change them |

### Needs a clear intent

| Command | What it changes |
|---|---|
| `/E` | Encrypts files / marks folders |
| `/D` | Decrypts files (plaintext on disk) |
| `/K` | Creates a **new** EFS certificate (old files stay on the old one until `/REKEY`) |
| `/REKEY` / `/U` | Rewraps files with the current key |
| `/ADDUSER` `/REMOVEUSER` | Who can open a given file |
| `/X` | Exports private key material |

### Dangerous if you do not mean it

**`cipher /w:C:\\somefolder`** does **not** encrypt. It **overwrites all free
space on that volume** (three passes) so deleted files cannot be undeleted.
It can take hours. Close other programs. All other switches are ignored.

There is **no undo**.
"""


ROADMAP_MD = """
This version ships four working surfaces:

1. **Find encrypted** — locate EFS files/folders, reveal them in Explorer,
   and decrypt a selection with `cipher /D` after a confirmation.
2. **Encrypt** — pick folders, preview `cipher /E` (with `/S`, `/H`, `/B`),
   confirm, and encrypt as the current Windows user.
3. **Cipher manual** + **Command map** — the full switch list, with examples.

Later tabs can wrap the remaining write commands (keys, recovery, wipe)
as guided actions. The map below is the backlog.
"""


COMMANDS: list[CipherCommand] = [
    {
        "id": "status",
        "switch": "(none)",
        "title": "Show encryption status",
        "syntax": "cipher [pathname [...]]",
        "group": "Inspect",
        "status": "ready",
        "danger": False,
        "summary": "List E (encrypted) vs U (unencrypted) for a folder and its files.",
        "details": (
            "With no switches, cipher prints the encryption state of the current "
            "directory (or of each pathname you pass) and whether new files added "
            "there will be encrypted. This app’s scanner does not parse that text: "
            "it reads the Encrypted NTFS attribute directly, then can still call "
            "`cipher` on a selected path if you want the raw listing."
        ),
        "examples": [
            "cipher",
            r"cipher C:\Users\You\Documents",
            r"cipher C:\Users\You\Documents\*",
        ],
    },
    {
        "id": "details",
        "switch": "/C",
        "title": "File encryption details",
        "syntax": "cipher /c [/s:directory] [/b] [/h] [pathname [...]]",
        "group": "Inspect",
        "status": "ready",
        "danger": False,
        "summary": "Show who can decrypt a file and which certificate protects it.",
        "details": (
            "Prints EFS metadata for an encrypted file: algorithm, users, and "
            "certificate thumbprints. Use this when a file will not open — it "
            "tells you which account or recovery agent is on the file. Wired "
            "to the Info button on the Find encrypted tab."
        ),
        "examples": [
            r'cipher /c "C:\Users\You\Private\budget.xlsx"',
        ],
    },
    {
        "id": "thumbprint",
        "switch": "/Y",
        "title": "Current EFS certificate thumbprint",
        "syntax": "cipher /y",
        "group": "Inspect",
        "status": "ready",
        "danger": False,
        "summary": "Display the thumbprint of the EFS certificate this account uses now.",
        "details": (
            "Useful to compare with `/C` output: if a file was encrypted with an "
            "older certificate, `/Y` will not match until you `/REKEY` that file. "
            "Shown in the Find encrypted header."
        ),
        "examples": ["cipher /y"],
    },
    {
        "id": "encrypt",
        "switch": "/E",
        "title": "Encrypt files or folders",
        "syntax": "cipher /e [/s:directory] [/b] [/h] [pathname [...]]",
        "group": "Encrypt & decrypt",
        "status": "ready",
        "danger": False,
        "summary": "Turn EFS on. Folders are marked so files added later are encrypted too.",
        "details": (
            "Always encrypt the parent folder as well as the files. Combine with "
            "`/S:` to walk a tree. Hidden/system files are skipped unless you add `/H`. "
            "`/B` stops at the first error instead of continuing. Cannot encrypt "
            "read-only files. Wired to the **Encrypt** tab: add folders, review "
            "the `cipher /E` commands, confirm the certificate warning, then run."
        ),
        "examples": [
            r"cipher /e Private",
            r"cipher /e /s:C:\Users\You\Private",
            r"cipher /e /h /s:C:\Users\You\Private",
        ],
    },
    {
        "id": "decrypt",
        "switch": "/D",
        "title": "Decrypt files or folders",
        "syntax": "cipher /d [/s:directory] [/b] [/h] [pathname [...]]",
        "group": "Encrypt & decrypt",
        "status": "ready",
        "danger": False,
        "summary": "Turn EFS off. The file is rewritten as plaintext on disk.",
        "details": (
            "Decrypting a folder also clears the “encrypt new files” mark. You must "
            "be a user listed on the file (or a recovery agent). Wired to **Decrypt** "
            "on the Find encrypted tab: check rows, confirm the `cipher /D` commands, "
            "then the app drops any items that no longer have the Encrypted attribute. "
            "Selected folders default to `/D /S` so their contents are decrypted too."
        ),
        "examples": [
            r"cipher /d secret.txt",
            r"cipher /d /s:C:\Users\You\Private",
        ],
    },
    {
        "id": "recursive",
        "switch": "/S",
        "title": "Operate on a whole tree",
        "syntax": "cipher /s:directory  (with /E, /D, /C, /ADDUSER, …)",
        "group": "Encrypt & decrypt",
        "status": "ready",
        "danger": False,
        "summary": "Apply the chosen operation to a directory and every subdirectory.",
        "details": (
            "A modifier, not a stand-alone command. The scanner already walks trees "
            "itself when you tick Recursive. Decrypt on the Find encrypted tab uses "
            "`/S:` when you leave “Also decrypt everything inside selected folders” on. "
            "The Encrypt tab does the same with `cipher /E /S`."
        ),
        "examples": [
            r"cipher /e /s:D:\Vault",
            r"cipher /c /s:D:\Vault",
        ],
    },
    {
        "id": "hidden",
        "switch": "/H",
        "title": "Include hidden and system files",
        "syntax": "cipher /h  (with /E, /D, /C, …)",
        "group": "Encrypt & decrypt",
        "status": "ready",
        "danger": False,
        "summary": "By default cipher ignores hidden and system attributes.",
        "details": (
            "The Find encrypted tab has its own “Include hidden / system” option "
            "for the attribute scan. Decrypt also passes `/H` so hidden files "
            "inside a selected folder are not left encrypted. The Encrypt tab "
            "offers the same `/H` checkbox (on by default)."
        ),
        "examples": [r"cipher /e /h /s:C:\Users\You\Private"],
    },
    {
        "id": "abort",
        "switch": "/B",
        "title": "Stop on first error",
        "syntax": "cipher /b  (with /E, /D, /C, …)",
        "group": "Encrypt & decrypt",
        "status": "ready",
        "danger": False,
        "summary": "Abort the whole run if any file fails. Default is to continue.",
        "details": (
            "Useful on unattended scripts so a permission error does not silently "
            "skip files. Offered as **Stop on the first error** on the Encrypt tab."
        ),
        "examples": [r"cipher /e /b /s:D:\Vault"],
    },
    {
        "id": "find_all",
        "switch": "/U /N",
        "title": "Find every encrypted file on local drives",
        "syntax": "cipher /u /n",
        "group": "Find & update keys",
        "status": "ready",
        "danger": False,
        "summary": "Official whole-disk listing. `/N` prevents key updates.",
        "details": (
            "`/U` walks every local drive looking for EFS files. Without `/N` it "
            "also rewraps each file if your certificate or the recovery-agent key "
            "has changed. With `/N` it is a search only. This app’s default scan "
            "is the attribute walk (same result, scoped to the folder you pick)."
        ),
        "examples": [
            "cipher /u /n",
            "cipher /u",
        ],
    },
    {
        "id": "rekey",
        "switch": "/REKEY",
        "title": "Rewrap files with the current EFS key",
        "syntax": "cipher /rekey [pathname [...]]",
        "group": "Find & update keys",
        "status": "planned",
        "danger": False,
        "summary": "Update chosen encrypted files to the certificate you use now.",
        "details": (
            "After `cipher /k` (new certificate) old files still open with the old "
            "cert until you rekey them. `/U` without `/N` does this for every "
            "encrypted file on local drives; `/REKEY` does it for the paths you name."
        ),
        "examples": [r"cipher /rekey /s:C:\Users\You\Private"],
    },
    {
        "id": "new_cert",
        "switch": "/K",
        "title": "Create a new EFS certificate and key",
        "syntax": "cipher /k [/ecc:256|384|521]",
        "group": "Certificates & backup",
        "status": "planned",
        "danger": False,
        "summary": "Mint a new personal EFS cert. All other switches are ignored.",
        "details": (
            "By default `/K` follows Group Policy (usually a 2048-bit RSA cert). "
            "`/ECC:256|384|521` forces a self-signed elliptic-curve certificate. "
            "Existing files stay on the previous cert until `/REKEY` or `/U`. "
            "Back up the new cert with `/X` immediately."
        ),
        "examples": [
            "cipher /k",
            "cipher /k /ecc:384",
        ],
    },
    {
        "id": "backup",
        "switch": "/X",
        "title": "Back up EFS certificate and keys",
        "syntax": "cipher /x[:efsfile] [filename]",
        "group": "Certificates & backup",
        "status": "planned",
        "danger": False,
        "summary": "Export the current (or a file’s) EFS keys to a .pfx.",
        "details": (
            "Without `:efsfile`, backs up the certificate this account uses now. "
            "With `/x:C:\\path\\encrypted.dat BackupName`, backs up the cert(s) "
            "that actually protect that file — the one you need if the file was "
            "encrypted with an older key. Guard the .pfx; it is the unlock key."
        ),
        "examples": [
            r"cipher /x C:\Backup\my-efs-keys",
            r"cipher /x:C:\Users\You\Private\old.dat C:\Backup\old-file-keys",
        ],
    },
    {
        "id": "recovery_agent",
        "switch": "/R",
        "title": "Generate a recovery-agent key",
        "syntax": "cipher /r:filename [/smartcard] [/ecc:256|384|521]",
        "group": "Recovery",
        "status": "planned",
        "danger": False,
        "summary": "Create a .pfx + .cer pair used to recover other users’ EFS files.",
        "details": (
            "Writes `filename.pfx` (cert + private key) and `filename.cer` (cert "
            "only). An administrator publishes the .cer in the EFS recovery policy "
            "(DRA) and keeps the .pfx offline. `/SMARTCARD` puts the key on a "
            "smart card and skips the .pfx. Default key is RSA 2048; `/ECC:` "
            "selects 256, 384, or 521."
        ),
        "examples": [
            r"cipher /r:C:\Backup\efs-recovery",
            r"cipher /r:C:\Backup\efs-recovery /ecc:384",
        ],
    },
    {
        "id": "policy_blob",
        "switch": "/P",
        "title": "Build a recovery-policy blob from a .cer",
        "syntax": "cipher /p:filename.cer",
        "group": "Recovery",
        "status": "planned",
        "danger": False,
        "summary": "Create a base64 DRA policy blob for MDM / GPM deployments.",
        "details": (
            "Modern Windows addition. Takes a recovery-agent certificate and "
            "emits the blob used to set a Data Recovery Agent policy without "
            "hand-editing Group Policy. Specialist / IT-admin command."
        ),
        "examples": [r"cipher /p:C:\Backup\efs-recovery.cer"],
    },
    {
        "id": "adduser",
        "switch": "/ADDUSER",
        "title": "Give another user access to a file",
        "syntax": (
            "cipher /adduser [/certhash:hash | /certfile:filename | /user:name] "
            "[/s:directory] [/b] [/h] [pathname [...]]"
        ),
        "group": "Share with other users",
        "status": "planned",
        "danger": False,
        "summary": "Add a second certificate so another account can decrypt the file.",
        "details": (
            "EFS is not a shared-folder ACL. Other users need their EFS cert "
            "wrapped into the file. Identify them by SHA1 thumbprint (`/CERTHASH`), "
            "a `.cer` file (`/CERTFILE`), or an Active Directory user (`/USER`). "
            "They still also need NTFS permission to read the file."
        ),
        "examples": [
            r'cipher /adduser /user:alice@contoso.com "D:\Vault\shared.xlsx"',
            r"cipher /adduser /certfile:C:\certs\alice.cer /s:D:\Vault",
        ],
    },
    {
        "id": "removeuser",
        "switch": "/REMOVEUSER",
        "title": "Remove a user from a file",
        "syntax": "cipher /removeuser /certhash:hash [/s:directory] [/b] [/h] [pathname [...]]",
        "group": "Share with other users",
        "status": "planned",
        "danger": False,
        "summary": "Drop a certificate from the file’s EFS user list.",
        "details": (
            "`/CERTHASH` must be the SHA1 thumbprint shown by `cipher /c`. "
            "Do not remove the last remaining key or the file becomes unrecoverable."
        ),
        "examples": [
            r"cipher /removeuser /certhash:0123456789ABCDEF0123456789ABCDEF01234567 secret.xlsx",
        ],
    },
    {
        "id": "flushcache",
        "switch": "/FLUSHCACHE",
        "title": "Flush the EFS key cache",
        "syntax": "cipher /flushcache [/server:name]",
        "group": "Maintenance",
        "status": "planned",
        "danger": False,
        "summary": "Clear cached EFS keys on this PC or on a remote server.",
        "details": (
            "EFS caches unwrapped keys for performance. Flush after a key rotation "
            "or when troubleshooting “access denied” on a file you should be able "
            "to open. Without `/SERVER:` it flushes the local cache for the caller."
        ),
        "examples": [
            "cipher /flushcache",
            r"cipher /flushcache /server:FILESERVER01",
        ],
    },
    {
        "id": "wipe",
        "switch": "/W",
        "title": "Wipe unused disk space (not encryption)",
        "syntax": "cipher /w:directory",
        "group": "Maintenance",
        "status": "planned",
        "danger": True,
        "summary": "Overwrite free space on the whole volume. Irreversible. Slow.",
        "details": (
            "When EFS encrypts a plaintext file it first makes a backup copy, then "
            "deletes the original. The leftover slack can still be recovered unless "
            "free space is overwritten. `/W` does that for the **entire volume** "
            "that contains `directory` (three-pass wipe of deallocated clusters). "
            "All other switches are ignored. Close apps. Expect a long run. "
            "A future UI must require an explicit typed confirmation."
        ),
        "examples": [
            "cipher /w:C:\\",
            r"cipher /w:D:\temp",
        ],
    },
]


STATUS_LABEL = {
    "ready": "In this app",
    "inspect": "In this app",
    "planned": "UI later",
}

STATUS_COLOR = {
    "ready": "positive",
    "inspect": "positive",
    "planned": "grey",
}


def commands_by_group() -> list[tuple[str, list[CipherCommand]]]:
    grouped: dict[str, list[CipherCommand]] = {g: [] for g in GROUPS}
    for cmd in COMMANDS:
        grouped.setdefault(cmd["group"], []).append(cmd)
    return [(g, grouped[g]) for g in GROUPS if grouped.get(g)]
