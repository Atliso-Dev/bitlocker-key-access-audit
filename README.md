# BitLocker Key Access Audit for Entra ID

[![Tests](https://github.com/Atliso-Dev/bitlocker-key-access-audit/actions/workflows/test.yml/badge.svg)](https://github.com/Atliso-Dev/bitlocker-key-access-audit/actions/workflows/test.yml)

Read-only PowerShell script that lists every BitLocker recovery key viewed in Entra ID: who read it, when, for which device, and whether the key has been rotated since.

Entra logs every key view, but keeps the log for 7 days on Entra ID Free and 30 days on P1 or P2. Viewing a key never rotates it, so a key read over the phone last week still unlocks the drive. This script lists the reads and puts the keys that still work first.

## What it does

- Reads every `Read BitLocker key` event in the Entra audit log for the last 1 to 30 days, through Microsoft Graph, with your own account
- Matches each read to the device name, and says whether the reader was the device's owner, an admin or helpdesk account, or an app
- Checks whether the device backed up a newer key after the read: `Still valid` keys come first
- Lists failed attempts by accounts without the right role
- Flags anyone who read keys for three or more devices in the period
- Exports a CSV with a next step per read and exits 1 when a viewed key is still valid
- Never reads a key itself. It lists key IDs and dates only, which doesn't create an audit event
- Changes nothing in your tenant
- Logs to `%LOCALAPPDATA%\Atliso\BitLockerKeyAccessAudit.log`

## Quick start

1. Install the Graph authentication module once:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

2. Download [`Atliso-BitLockerKeyAccessAudit.ps1`](Atliso-BitLockerKeyAccessAudit.ps1) and check the config at the top:

```powershell
# ===== CONFIG =====
$OutputPath    = Join-Path $env:USERPROFILE 'Desktop\Atliso-BitLockerKeyReads.csv'
$BulkThreshold = 3       # flag anyone who read keys for this many devices or more in the period
$LogPath       = Join-Path $env:LOCALAPPDATA 'Atliso\BitLockerKeyAccessAudit.log'
# ==================
```

3. Run it and sign in when prompted:

```powershell
.\Atliso-BitLockerKeyAccessAudit.ps1
# Entra ID Free keeps 7 days
.\Atliso-BitLockerKeyAccessAudit.ps1 -Days 7
```

MSPs can point it at a customer tenant:

```powershell
.\Atliso-BitLockerKeyAccessAudit.ps1 -TenantId contoso.onmicrosoft.com
```

## Output

One CSV row per key read:

`Status, ReadAt, Reader, ReaderType, IP, DeviceName, DeviceId, KeyId, KeyCreated, NextStep, Note`

| Status | Meaning |
|---|---|
| `Still valid` | The key that was read is still the device's current key. Rotate it: Intune > Devices > the device > BitLocker key rotation |
| `Failed attempt` | Someone without the right role tried to read a key |
| `Rotated` | The device backed up a newer key after the read |
| `Key gone` | The key is no longer in Entra, usually because the device was deleted |

Exit code 0 when no viewed key is still valid, 1 when one is.

The key ID and device ID come from the event's detail text, `Successfully retrieved BitLocker recovery key associated with key ID: '...'. Backed up from device: '...'`, with the event's target resource as a fallback for the key ID.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7
- The `Microsoft.Graph.Authentication` module
- Delegated, read-only Graph permissions:
  - `AuditLog.Read.All` (the Entra audit log)
  - `BitlockerKey.ReadBasic.All` (key IDs, devices and dates, never the key itself)
  - `Device.Read.All` (device names and owners)
- A role that can read audit logs and BitLocker key metadata, such as Security Reader or Global Reader

## What it doesn't do

It doesn't rotate keys or change who can read them. It can only see as far back as Entra keeps audit logs. It signs in as you; for an unattended daily run, register an app with the same read-only permissions and keep the CSVs.

## Tests

Pester tests mock Microsoft Graph, so they run without a tenant:

```powershell
Install-Module Pester -MinimumVersion 5.5 -Scope CurrentUser -SkipPublisherCheck
Invoke-Pester ./tests
```

CI runs them on Windows PowerShell 5.1 and PowerShell 7.

## Guide

Where key reads are logged, who can read keys, and why viewing one doesn't rotate it: [Who viewed a BitLocker recovery key? Check the Entra log](https://atliso.com/blog/who-viewed-bitlocker-recovery-key-entra)

Want BitLocker checked every night across your client tenants? [Atliso](https://atliso.com/pro?ref=bitlocker-key-access-audit) opens a helpdesk ticket for anything new. 30-day free trial.

## License

MIT. See [LICENSE](LICENSE).
