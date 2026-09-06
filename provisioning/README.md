# Cryptotherm Onboarding USB

A USB kit that preps a **new computer** to join the Cryptotherm ecosystem in one run:

1. Installs and enables an **SSH server**
2. Installs **Tailscale** and joins your tailnet (`tailscale up`)
3. Authorizes your **admin public key(s)** so you can SSH in afterward
4. (Optional) sets the hostname and installs an outbound key

Works on **Windows, macOS, and Linux**.

## Why not literal "autorun"?

Windows disabled USB `autorun.inf` in Windows 7, and macOS/Linux never
auto-executed removable media — all to stop USB malware. So a stick that
"just runs on insert" isn't possible without disabling security you don't
want disabled. This kit gets as close as safely possible: **one double-click
on Windows, one paste-and-run on Mac/Linux.**

## Layout

```
provisioning/
├── START-HERE.txt              # quickstart for whoever holds the stick
├── config/
│   ├── provision.conf.example  # copy to provision.conf, add your Tailscale key
│   └── authorized_keys.example # copy to authorized_keys, paste admin PUBLIC keys
├── windows/
│   ├── RUN-provision-windows.bat   # double-click this (self-elevates)
│   └── provision-windows.ps1
├── mac/
│   └── provision-mac.sh
└── linux/
    └── provision-linux.sh
```

## One-time prep (before onboarding)

1. `cd provisioning/config`
2. `cp provision.conf.example provision.conf` and set **`TS_AUTHKEY`**
   — generate one at <https://login.tailscale.com/admin/settings/keys>.
   Recommended: *Reusable*, a short expiry, and a tag; **revoke it when the
   batch is done**.
3. `cp authorized_keys.example authorized_keys` and paste your admin
   **public** key(s) (`cat ~/.ssh/id_ed25519.pub`), one per line.
4. Copy the whole `provisioning/` folder onto the USB stick.

`provision.conf`, `authorized_keys`, and any `id_ct` are **git-ignored** so
real secrets never get committed to the repo.

## Run it on a new machine

| OS | Command |
|----|---------|
| **Windows** | double-click `windows\RUN-provision-windows.bat`, approve the UAC prompt |
| **macOS** | `bash /Volumes/<USB>/mac/provision-mac.sh` (prompts for your password) |
| **Linux** | `sudo bash /media/<you>/<USB>/linux/provision-linux.sh` |

Each script reads `config/provision.conf` and `config/authorized_keys`
automatically. At the end it prints the machine's Tailscale IP so you can
add it to your inventory and SSH in.

## Security model (important)

- **Public keys, not private ones.** The stick installs your *public* key
  into each new machine's `authorized_keys`. If the stick is lost, nothing
  usable leaks — the opposite of shipping a private `foxai_deploy` key on
  removable media.
- **Revocable Tailscale auth key.** `TS_AUTHKEY` can be revoked in the admin
  console the instant onboarding is finished. Prefer a *reusable + tagged +
  short-expiry* key, and delete it after the batch.
- **Optional outbound key** (`INSTALL_OUTBOUND_KEY=1` + a `config/id_ct`
  file) is only for machines that must SSH *out* to cthome/inference-3, like
  the booth. Most onboarded machines don't need it — leave it off.
- Treat the prepared stick like a key to your network anyway: don't leave it
  in a machine, and wipe `config/` before repurposing it.

## Notes per OS

- **Windows** needs Administrator (the `.bat` self-elevates). It uses
  `winget` for Tailscale if present, otherwise downloads the stable MSI. A
  hostname change applies after reboot.
- **macOS** may show GUI prompts for Remote Login and the Tailscale VPN
  profile — approve them. Uses Homebrew for the Tailscale CLI daemon if
  available; otherwise install the Tailscale app and re-run.
- **Linux** supports apt / dnf / yum / pacman / zypper. Uses the official
  `tailscale.com/install.sh`. Enables `--ssh` so Tailscale SSH also works.
