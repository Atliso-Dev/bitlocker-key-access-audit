# Pester 5+. Graph is mocked, so these run anywhere without a tenant or the Graph module:
#   Invoke-Pester ./tests

BeforeAll {
  $script:Script = Join-Path (Join-Path $PSScriptRoot '..') 'Atliso-BitLockerKeyAccessAudit.ps1'

  # Stand-ins so the mocks have something to replace when Microsoft.Graph.Authentication isn't installed.
  if (-not (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue)) { function global:Connect-MgGraph { param($Scopes, $TenantId, [switch]$NoWelcome) } }
  if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) { function global:Invoke-MgGraphRequest { param($Method, $Uri, $Headers, $OutputType) } }

  $script:Iso = { param([double]$Hours) (Get-Date).ToUniversalTime().AddHours($Hours).ToString('o') }

  # Runs the script against a fake tenant. $Graph maps a URI fragment to a response, a scriptblock, or 403.
  function script:Invoke-Audit([System.Collections.IDictionary]$Graph, [hashtable]$Params = @{}) {
    $env:USERPROFILE  = Join-Path $TestDrive 'home'
    $env:LOCALAPPDATA = Join-Path $TestDrive 'appdata'
    $csvPath = Join-Path $env:USERPROFILE 'Desktop\Atliso-BitLockerKeyReads.csv'
    if (Test-Path $csvPath) { Remove-Item $csvPath }
    $global:AtlisoTestGraph = $Graph
    $global:AtlisoTestUris = New-Object System.Collections.Generic.List[string]
    Mock Connect-MgGraph { }
    Mock Invoke-MgGraphRequest {
      $global:AtlisoTestUris.Add($Uri)
      foreach ($key in $global:AtlisoTestGraph.Keys) {
        if ($Uri -like "*$key*") {
          $v = $global:AtlisoTestGraph[$key]
          if ($v -eq 403) { throw 'Response status code does not indicate success: 403 (Forbidden).' }
          if ($v -is [scriptblock]) { return & $v $Uri }
          return $v
        }
      }
      return [pscustomobject]@{ value = @() }
    }
    $out = & $script:Script @Params 6>&1 | Out-String
    $rows = @()
    if (Test-Path $csvPath) { $rows = @(Import-Csv $csvPath) }
    [pscustomobject]@{ Exit = $LASTEXITCODE; Output = $out; Rows = $rows; Uris = @($global:AtlisoTestUris) }
  }

  function script:List([object[]]$Items) { [pscustomobject]@{ value = $Items } }

  # A "Read BitLocker key" audit event, shaped like Entra writes it. $Hours is when, relative to now.
  function script:KeyRead($KeyId, $DeviceId, $Hours = -24, $Upn = 'tech@msp.com', $App = $null, $Result = 'success') {
    $user = if ($App) { $null } else { [pscustomobject]@{ id = "id-$($Upn.ToLower())"; userPrincipalName = $Upn; ipAddress = '203.0.113.10' } }
    $app = if ($App) { [pscustomobject]@{ displayName = $App } } else { $null }
    $detail = "Successfully retrieved BitLocker recovery key associated with key ID: '$KeyId'. Backed up from device: '$DeviceId'"
    [pscustomobject]@{
      activityDisplayName = 'Read BitLocker key'; category = 'KeyManagement'; result = $Result
      activityDateTime = (& $script:Iso $Hours)
      initiatedBy = [pscustomobject]@{ user = $user; app = $app }
      targetResources = @([pscustomobject]@{ id = $null; displayName = $KeyId; type = 'Other' })
      additionalDetails = @([pscustomobject]@{ key = 'AdditionalInfo'; value = $detail })
    }
  }
  function script:Key($Id, $DeviceId, $Hours = -24 * 90) { [pscustomobject]@{ id = $Id; deviceId = $DeviceId; createdDateTime = (& $script:Iso $Hours); volumeType = 1 } }
  function script:Device($DeviceId, $Name, $Owner = 'user@contoso.com') {
    [pscustomobject]@{ deviceId = $DeviceId; displayName = $Name; registeredOwners = @([pscustomobject]@{ id = "id-$Owner" }) }
  }

  $script:K1 = '11111111-1111-1111-1111-111111111111'; $script:D1 = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
  $script:K2 = '22222222-2222-2222-2222-222222222222'; $script:D2 = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
  $script:K3 = '33333333-3333-3333-3333-333333333333'; $script:D3 = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
  $script:K1New = '44444444-4444-4444-4444-444444444444'
}

Describe 'BitLocker Key Access Audit' {
  It 'exits 0 and writes no CSV when nobody read a key' {
    $r = Invoke-Audit ([ordered]@{ 'directoryAudits' = (List @()); 'recoveryKeys' = (List @((Key $K1 $D1))); 'devices' = (List @((Device $D1 'PC-01'))) })
    $r.Exit | Should -Be 0
    $r.Rows.Count | Should -Be 0
    $r.Output | Should -Match 'Nobody read a BitLocker recovery key'
  }

  It 'flags a read key with no newer key as still valid and exits 1' {
    $r = Invoke-Audit ([ordered]@{
      'directoryAudits' = (List @((KeyRead $K1 $D1)))
      'recoveryKeys'    = (List @((Key $K1 $D1)))
      'devices'         = (List @((Device $D1 'PC-01')))
    })
    $r.Exit | Should -Be 1
    $r.Rows[0].Status | Should -Be 'Still valid'
    $r.Rows[0].DeviceName | Should -Be 'PC-01'
    $r.Rows[0].Reader | Should -Be 'tech@msp.com'
    $r.Rows[0].ReaderType | Should -Be 'Admin or helpdesk'
    $r.Rows[0].IP | Should -Be '203.0.113.10'
    $r.Rows[0].NextStep | Should -Match 'BitLocker key rotation'
  }

  It 'marks a read as rotated when the device backed up a newer key afterwards' {
    $r = Invoke-Audit ([ordered]@{
      'directoryAudits' = (List @((KeyRead $K1 $D1 -Hours -48)))
      'recoveryKeys'    = (List @((Key $K1 $D1), (Key $K1New $D1 -Hours -2)))
      'devices'         = (List @((Device $D1 'PC-01')))
    })
    $r.Exit | Should -Be 0
    $r.Rows[0].Status | Should -Be 'Rotated'
  }

  It 'does not count a key created before the read as a rotation' {
    $r = Invoke-Audit ([ordered]@{
      'directoryAudits' = (List @((KeyRead $K1 $D1 -Hours -2)))
      'recoveryKeys'    = (List @((Key $K1 $D1), (Key $K1New $D1 -Hours -48)))
      'devices'         = (List @((Device $D1 'PC-01')))
    })
    $r.Rows[0].Status | Should -Be 'Still valid'
  }

  It 'reports a key that is no longer in Entra as gone' {
    $r = Invoke-Audit ([ordered]@{ 'directoryAudits' = (List @((KeyRead $K1 $D1))); 'recoveryKeys' = (List @()); 'devices' = (List @()) })
    $r.Exit | Should -Be 0
    $r.Rows[0].Status | Should -Be 'Key gone'
    $r.Rows[0].DeviceId | Should -Be $D1
  }

  It 'labels a user reading their own device key as the device owner' {
    $r = Invoke-Audit ([ordered]@{
      'directoryAudits' = (List @((KeyRead $K1 $D1 -Upn 'User@Contoso.com')))
      'recoveryKeys'    = (List @((Key $K1 $D1)))
      'devices'         = (List @((Device $D1 'PC-01' 'user@contoso.com')))
    })
    $r.Rows[0].ReaderType | Should -Be 'Device owner'
  }

  It 'labels a read by an app and says so' {
    $r = Invoke-Audit ([ordered]@{
      'directoryAudits' = (List @((KeyRead $K1 $D1 -App 'Backup Tool')))
      'recoveryKeys'    = (List @((Key $K1 $D1)))
      'devices'         = (List @((Device $D1 'PC-01')))
    })
    $r.Rows[0].Reader | Should -Be 'Backup Tool'
    $r.Rows[0].ReaderType | Should -Be 'App'
    $r.Rows[0].Note | Should -Match 'Read by an app'
  }

  It 'lists failed attempts without treating them as exposed keys' {
    $r = Invoke-Audit ([ordered]@{
      'directoryAudits' = (List @((KeyRead $K1 $D1 -Result 'failure')))
      'recoveryKeys'    = (List @((Key $K1 $D1)))
      'devices'         = (List @((Device $D1 'PC-01')))
    })
    $r.Exit | Should -Be 0
    $r.Rows[0].Status | Should -Be 'Failed attempt'
  }

  It 'flags a reader who opened keys for three devices' {
    $r = Invoke-Audit ([ordered]@{
      'directoryAudits' = (List @((KeyRead $K1 $D1), (KeyRead $K2 $D2), (KeyRead $K3 $D3)))
      'recoveryKeys'    = (List @((Key $K1 $D1), (Key $K2 $D2), (Key $K3 $D3)))
      'devices'         = (List @((Device $D1 'PC-01'), (Device $D2 'PC-02'), (Device $D3 'PC-03')))
    })
    $r.Rows.Count | Should -Be 3
    $r.Rows[0].Note | Should -Match 'read keys for 3 devices'
    $r.Output | Should -Match 'tech@msp.com read keys for 3 devices'
  }

  It 'counts devices, not reads, towards the bulk flag' {
    $r = Invoke-Audit ([ordered]@{
      'directoryAudits' = (List @((KeyRead $K1 $D1 -Hours -3), (KeyRead $K1 $D1 -Hours -2), (KeyRead $K1 $D1 -Hours -1)))
      'recoveryKeys'    = (List @((Key $K1 $D1)))
      'devices'         = (List @((Device $D1 'PC-01')))
    })
    $r.Rows.Count | Should -Be 3
    $r.Output | Should -Not -Match 'read keys for'
  }

  It 'falls back to the target resource when the detail text has no key ID' {
    $e = KeyRead $K1 $D1
    $e.additionalDetails = @()
    $r = Invoke-Audit ([ordered]@{ 'directoryAudits' = (List @($e)); 'recoveryKeys' = (List @((Key $K1 $D1))); 'devices' = (List @((Device $D1 'PC-01'))) })
    $r.Rows[0].KeyId | Should -Be $K1
    $r.Rows[0].DeviceName | Should -Be 'PC-01'
    $r.Rows[0].Status | Should -Be 'Still valid'
  }

  It 'sorts still-valid keys above rotated ones' {
    $r = Invoke-Audit ([ordered]@{
      'directoryAudits' = (List @((KeyRead $K1 $D1 -Hours -48), (KeyRead $K2 $D2 -Hours -1 -Upn 'other@msp.com')))
      'recoveryKeys'    = (List @((Key $K1 $D1), (Key $K1New $D1 -Hours -2), (Key $K2 $D2)))
      'devices'         = (List @((Device $D1 'PC-01'), (Device $D2 'PC-02')))
    })
    $r.Rows[0].Status | Should -Be 'Still valid'
    $r.Rows[0].DeviceName | Should -Be 'PC-02'
    $r.Rows[1].Status | Should -Be 'Rotated'
  }

  It 'asks Entra only for key reads in the period and never selects the key itself' {
    $r = Invoke-Audit ([ordered]@{ 'directoryAudits' = (List @()); 'recoveryKeys' = (List @()); 'devices' = (List @()) }) @{ Days = 7 }
    $audit = $r.Uris | Where-Object { $_ -like '*directoryAudits*' }
    [uri]::UnescapeDataString($audit) | Should -Match "activityDisplayName eq 'Read BitLocker key' and activityDateTime ge "
    ($r.Uris | Where-Object { $_ -like '*recoveryKeys*' }) | Should -Not -Match 'select=key\b|select=key&|,key\b'
  }

  It 'follows nextLink paging on the audit log' {
    $page1 = [pscustomobject]@{ value = @((KeyRead $K1 $D1)); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?page=2' }
    $r = Invoke-Audit ([ordered]@{
      'page=2'          = (List @((KeyRead $K2 $D2)))
      'directoryAudits' = $page1
      'recoveryKeys'    = (List @((Key $K1 $D1), (Key $K2 $D2)))
      'devices'         = (List @((Device $D1 'PC-01'), (Device $D2 'PC-02')))
    })
    $r.Rows.Count | Should -Be 2
  }
}
