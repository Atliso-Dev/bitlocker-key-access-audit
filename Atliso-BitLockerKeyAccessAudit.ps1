<#PSScriptInfo
.VERSION 1.0.0
.GUID 70fab440-2211-4a48-b025-39663dc60b54
.AUTHOR Atliso
.COMPANYNAME Atliso
.COPYRIGHT (c) 2026 Atliso. MIT License.
.TAGS BitLocker RecoveryKey Entra Intune AuditLog Graph Audit ReadOnly
.LICENSEURI https://github.com/Atliso-Dev/bitlocker-key-access-audit/blob/main/LICENSE
.PROJECTURI https://atliso.com/blog/who-viewed-bitlocker-recovery-key-entra
.REQUIREDMODULES Microsoft.Graph.Authentication
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES First release.
#>

<#
.SYNOPSIS
  Atliso BitLocker Key Access Audit. Read-only.
.DESCRIPTION
  Lists every BitLocker recovery key that was viewed in Entra ID: who read it, when, from which
  IP, for which device, and whether the key has been rotated since. A key that was read and never
  rotated still unlocks the drive, so those come first.
  Also flags anyone who read keys for several devices in the period.
  Never reads a key itself: it only lists key IDs and dates, which doesn't create an audit event.
  Exports a CSV and exits 1 when a viewed key is still valid. Changes nothing in your tenant.
  https://atliso.com/blog/who-viewed-bitlocker-recovery-key-entra
.PARAMETER TenantId
  Optional. A tenant ID or domain to sign in to, for MSPs running it against customer tenants.
.PARAMETER Days
  How far back to look. Entra keeps audit logs for 7 days on Entra ID Free and 30 days on P1 or P2.
.NOTES
  Requires Microsoft.Graph.Authentication.
  Scopes: AuditLog.Read.All, BitlockerKey.ReadBasic.All, Device.Read.All
  Exit 0 = every viewed key has been rotated, or none were viewed. Exit 1 = a viewed key still works.
#>
[CmdletBinding()]
param(
  [string]$TenantId,
  [ValidateRange(1, 30)]
  [int]$Days = 30
)

# ===== CONFIG =====
$OutputPath    = Join-Path $env:USERPROFILE 'Desktop\Atliso-BitLockerKeyReads.csv'
$BulkThreshold = 3       # flag anyone who read keys for this many devices or more in the period
$LogPath       = Join-Path $env:LOCALAPPDATA 'Atliso\BitLockerKeyAccessAudit.log'
# ==================

$ErrorActionPreference = 'Stop'

function Write-Log([string]$Message) {
  try {
    $dir = Split-Path -Path $LogPath -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Add-Content -Path $LogPath -Value ("{0}  {1}" -f (Get-Date -Format s), $Message)
  } catch { }
}

# HTTP status from a Graph error. PowerShell 7 and Windows PowerShell 5.1 throw different exception shapes.
function Get-HttpStatus($ErrorRecord) {
  $ex = $ErrorRecord.Exception
  try { if ($ex.Response -and $ex.Response.StatusCode) { return [int]$ex.Response.StatusCode } } catch { }
  if ([string]$ex.Message -match '\b(403|404|429)\b') { return [int]$Matches[1] }
  return $null
}

function Invoke-Graph([string]$Uri) {
  for ($try = 1; $try -le 5; $try++) {
    try {
      return Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject
    } catch {
      $status = Get-HttpStatus $_
      if ($status -eq 429 -and $try -lt 5) {
        $wait = 10
        try { $ra = $_.Exception.Response.Headers.RetryAfter.Delta; if ($ra) { $wait = [int][math]::Ceiling($ra.TotalSeconds) } } catch { }
        Write-Log "429 on $Uri, waiting $wait s"
        Start-Sleep -Seconds $wait
        continue
      }
      throw
    }
  }
}

function Get-GraphList([string]$Uri) {
  $items = New-Object System.Collections.Generic.List[object]
  while ($Uri) {
    $page = Invoke-Graph $Uri
    if (-not $page) { break }
    foreach ($v in @($page.value)) { if ($null -ne $v) { $items.Add($v) } }
    $Uri = $page.'@odata.nextLink'
  }
  return ,$items
}

function ConvertTo-UtcDate($Value) {
  if (-not $Value) { return $null }
  if ($Value -is [datetime]) { $d = $Value.ToUniversalTime() }
  else { $d = ([datetimeoffset]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture)).UtcDateTime }
  if ($d.Year -lt 2000 -or $d.Year -gt 9000) { return $null }
  return $d
}

$now = (Get-Date).ToUniversalTime()
function Format-Date($Date) { if ($Date) { $Date.ToString('yyyy-MM-dd HH:mm') + ' UTC' } else { '' } }

# The key ID and device ID of a "Read BitLocker key" event. Entra writes both into the detail text:
#   Successfully retrieved BitLocker recovery key associated with key ID: '<key id>'. Backed up from device: '<device id>'
# The key ID is also the first target resource's display name, so that's the fallback.
$GuidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
function Get-KeyRead($Event) {
  $text = (@($Event.additionalDetails) | ForEach-Object { [string]$_.value }) -join ' '
  $keyId = $null; $deviceId = $null
  if ($text -match "key ID:\s*'($GuidPattern)'") { $keyId = $Matches[1] }
  if ($text -match "device:\s*'($GuidPattern)'") { $deviceId = $Matches[1] }
  if (-not $keyId) {
    foreach ($t in @($Event.targetResources)) {
      foreach ($v in @($t.displayName, $t.id)) { if ([string]$v -match "^$GuidPattern$") { $keyId = [string]$v; break } }
      if ($keyId) { break }
    }
  }
  $user = $Event.initiatedBy.user
  $app = $Event.initiatedBy.app
  $userId = $null
  if ($user -and $user.userPrincipalName) { $who = [string]$user.userPrincipalName; $kind = 'User'; $ip = [string]$user.ipAddress; $userId = ([string]$user.id).ToLower() }
  elseif ($app -and $app.displayName) { $who = [string]$app.displayName; $kind = 'App'; $ip = '' }
  else { $who = 'Unknown'; $kind = 'Unknown'; $ip = '' }
  [pscustomobject]@{
    Time     = ConvertTo-UtcDate $Event.activityDateTime
    Result   = [string]$Event.result
    Reader   = $who
    Kind     = $kind
    UserId   = $userId
    IP       = $ip
    KeyId    = if ($keyId) { $keyId.ToLower() } else { $null }
    DeviceId = if ($deviceId) { $deviceId.ToLower() } else { $null }
  }
}

Write-Log 'Run started'
$connect = @{ Scopes = @('AuditLog.Read.All', 'BitlockerKey.ReadBasic.All', 'Device.Read.All'); NoWelcome = $true }
if ($TenantId) { $connect.TenantId = $TenantId }
Connect-MgGraph @connect

# 1. Every key read in the period, including failed attempts.
$since = $now.AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
$filter = "activityDisplayName eq 'Read BitLocker key' and activityDateTime ge $since"
$events = Get-GraphList ("https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter={0}" -f [uri]::EscapeDataString($filter))
$reads = @($events | ForEach-Object { Get-KeyRead $_ })
Write-Log ("Read {0} key read events since {1}" -f $reads.Count, $since)

# 2. The keys Entra holds now. ReadBasic lists IDs and dates only, never the key itself, so this creates no audit event.
$keysById = @{}; $keysByDevice = @{}
foreach ($k in (Get-GraphList 'https://graph.microsoft.com/v1.0/informationProtection/bitlocker/recoveryKeys?$select=id,deviceId,createdDateTime,volumeType')) {
  $entry = [pscustomobject]@{ Id = ([string]$k.id).ToLower(); DeviceId = ([string]$k.deviceId).ToLower(); Created = ConvertTo-UtcDate $k.createdDateTime }
  $keysById[$entry.Id] = $entry
  if (-not $keysByDevice.ContainsKey($entry.DeviceId)) { $keysByDevice[$entry.DeviceId] = New-Object System.Collections.Generic.List[object] }
  $keysByDevice[$entry.DeviceId].Add($entry)
}

# 3. Device names and registered owners, so a user reading their own device's key reads as self-service.
# Owners are matched by object ID: Device.Read.All doesn't return the owner's UPN.
$devices = @{}
foreach ($d in (Get-GraphList 'https://graph.microsoft.com/v1.0/devices?$select=deviceId,displayName&$expand=registeredOwners($select=id)')) {
  $devices[([string]$d.deviceId).ToLower()] = [pscustomobject]@{
    Name   = [string]$d.displayName
    Owners = @($d.registeredOwners | ForEach-Object { ([string]$_.id).ToLower() } | Where-Object { $_ })
  }
}

# How many different devices each reader opened keys for.
$devicesPerReader = @{}
foreach ($r in $reads | Where-Object { $_.Result -eq 'success' }) {
  $device = if ($r.DeviceId) { $r.DeviceId } elseif ($r.KeyId -and $keysById.ContainsKey($r.KeyId)) { $keysById[$r.KeyId].DeviceId } else { $r.KeyId }
  if (-not $devicesPerReader.ContainsKey($r.Reader)) { $devicesPerReader[$r.Reader] = @{} }
  if ($device) { $devicesPerReader[$r.Reader][$device] = $true }
}

$rows = New-Object System.Collections.Generic.List[object]
foreach ($r in $reads) {
  $key = if ($r.KeyId -and $keysById.ContainsKey($r.KeyId)) { $keysById[$r.KeyId] } else { $null }
  $deviceId = if ($r.DeviceId) { $r.DeviceId } elseif ($key) { $key.DeviceId } else { $null }
  $device = if ($deviceId -and $devices.ContainsKey($deviceId)) { $devices[$deviceId] } else { $null }
  $notes = @()

  if ($r.Result -ne 'success') {
    $status = 'Failed attempt'
    $next = "Someone tried to read a key and was refused. Check that $($r.Reader) should be asking."
  } elseif (-not $key) {
    $status = 'Key gone'
    $next = 'The key is no longer in Entra. The device was deleted or its keys were replaced. Nothing to rotate.'
  } else {
    # Rotated when the device backed up a newer key after the read.
    $newer = @($keysByDevice[$key.DeviceId] | Where-Object { $_.Created -and $r.Time -and $_.Created -gt $r.Time })
    if ($newer.Count) {
      $status = 'Rotated'
      $next = 'A new key was backed up after the read. The one that was viewed is no longer the current key.'
    } else {
      $status = 'Still valid'
      $next = 'Rotate it: Intune > Devices > this device > BitLocker key rotation. Until then, whoever saw it can unlock the drive.'
    }
  }

  $role = $r.Kind
  if ($r.Kind -eq 'User' -and $device -and $r.UserId -and $device.Owners -contains $r.UserId) { $role = 'Device owner' }
  elseif ($r.Kind -eq 'User') { $role = 'Admin or helpdesk' }
  if ($r.Kind -eq 'App') { $notes += 'Read by an app, not a person. Check it is a tool you expect to read keys.' }
  if ($devicesPerReader.ContainsKey($r.Reader) -and $devicesPerReader[$r.Reader].Count -ge $BulkThreshold) {
    $notes += "$($r.Reader) read keys for $($devicesPerReader[$r.Reader].Count) devices in this period."
  }

  $rows.Add([pscustomobject]@{
    Status     = $status
    ReadAt     = Format-Date $r.Time
    Reader     = $r.Reader
    ReaderType = $role
    IP         = $r.IP
    DeviceName = if ($device) { $device.Name } else { '' }
    DeviceId   = $deviceId
    KeyId      = $r.KeyId
    KeyCreated = if ($key) { Format-Date $key.Created } else { '' }
    NextStep   = $next
    Note       = ($notes -join ' ')
  })
}

# Output: keys that still work first, newest read at the top.
$order = @{ 'Still valid' = 0; 'Failed attempt' = 1; 'Rotated' = 2; 'Key gone' = 3 }
$sorted = @($rows | Sort-Object @{ Expression = { $order[$_.Status] } }, @{ Expression = { $_.ReadAt }; Descending = $true })

if ($sorted.Count -gt 0) {
  $outDir = Split-Path -Path $OutputPath -Parent
  if ($outDir -and -not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
  $sorted | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
  $sorted | Format-Table Status, ReadAt, Reader, ReaderType, DeviceName, KeyCreated -AutoSize | Out-String -Width 250 | Write-Host
}

$bulk = @($devicesPerReader.Keys | Where-Object { $devicesPerReader[$_].Count -ge $BulkThreshold } | Sort-Object)
foreach ($b in $bulk) {
  Write-Host ("{0} read keys for {1} devices in the last {2} days." -f $b, $devicesPerReader[$b].Count, $Days) -ForegroundColor Yellow
}

$valid = @($sorted | Where-Object Status -eq 'Still valid')
if ($sorted.Count -gt 0) {
  $counts = $sorted | Group-Object Status | ForEach-Object { "{0} {1}" -f $_.Count, $_.Name.ToLower() }
  Write-Host ("Key reads in the last {0} days: {1}. CSV: {2}" -f $Days, ($counts -join ', '), $OutputPath)
} else {
  Write-Host "Nobody read a BitLocker recovery key in the last $Days days."
}
Write-Host 'Entra keeps audit logs for 7 days on Entra ID Free and 30 days on P1 or P2. Run this on a schedule and keep the CSVs if you need a longer record.'
Write-Host 'Have a check like this run every night across every client tenant: https://atliso.com/pro?ref=bitlocker-key-access-audit' -ForegroundColor Cyan
Write-Log ("Run finished: {0} reads, {1} still valid" -f $sorted.Count, $valid.Count)

if ($valid.Count -gt 0) { exit 1 } else { exit 0 }
