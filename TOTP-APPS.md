<div align="center">

# Recommended TOTP Authenticator Apps

[![RFC 6238](https://img.shields.io/badge/standard-RFC%206238-blue?style=flat)](https://datatracker.ietf.org/doc/html/rfc6238)
![Open source only](https://img.shields.io/badge/apps-open%20source%20only-brightgreen?style=flat)

</div>

This app's two-factor authentication is standard [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238) TOTP — it works with **any** compatible authenticator, not just the ones listed here. If you don't already have one, these are open-source, actively maintained picks per platform, chosen using three criteria:

- **Open source** under an OSI-approved license — the code that holds your 2FA secrets is auditable.
- **Actively maintained** — no apps that have been abandoned or archived.
- **No forced cloud/account** — local-only by default, or end-to-end encrypted if it offers sync.

This is an independent recommendation, not an endorsement or partnership with any of these projects.

> [!NOTE]
> DeadDropMGMT uses the RFC 6238 defaults every app assumes: **SHA-1, 6 digits, 30-second period** (see
> [ADR-005](docs/ADR.md)). Enroll by scanning the QR code on the **2FA** page, or type the shown secret in manually.

| Platform | App | License | Link |
|---|---|---|---|
| Android | [Aegis Authenticator](https://getaegis.app/) | GPL-3.0 | [GitHub](https://github.com/beemdevelopment/Aegis) |
| Android / iOS | [2FAS Auth](https://2fas.com/) | Open source | [GitHub](https://github.com/twofas/2fas-android) |
| Android / iOS / Windows / Linux / macOS | [Ente Auth](https://ente.io/auth) | AGPL-3.0 | [GitHub](https://github.com/ente-io/ente) |
| Windows / Linux / macOS | [KeePassXC](https://keepassxc.org/) | GPL-2.0 or GPL-3.0 | [GitHub](https://github.com/keepassxreboot/keepassxc) |
| Linux | [Authenticator (GNOME)](https://apps.gnome.org/Authenticator/) | GPL-3.0 | [GitHub](https://github.com/bilelmoussaoui/Authenticator) |

## Which one should I pick?

- **Want one app for every device?** [Ente Auth](https://ente.io/auth) is the only option above with native apps on all five platforms, with optional end-to-end-encrypted sync between them.
- **Want zero cloud dependency on Android?** [Aegis](https://getaegis.app/) is fully offline — no account, no telemetry, encrypted local vault, manual encrypted export for backups.
- **Already use a password manager?** [KeePassXC](https://keepassxc.org/) stores a TOTP secret as a field on any entry, so you don't need a separate app at all.

## Good to know

- **Back up your authenticator.** If the phone is lost, an owner can reset a courier's 2FA from **Users**; a locked-out owner needs another way back in, so keep an encrypted export of your codes.
- **Raivo OTP** was deliberately left off this list — its source is publicly viewable but not released under an OSI-approved open-source license, so it doesn't meet the bar above.
