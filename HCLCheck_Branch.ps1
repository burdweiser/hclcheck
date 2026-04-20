# ============================================================
# HCL Compliance Check - Branch Hosts (esxi-* prefix)
# vCenter : your-vcenter.domain.com
# Scope   : FC HBA driver (lpfc) + PERC driver/firmware
# Output  : CSV detail report + TXT summary + HTML report
# OME     : https://your-ome-server/
# ============================================================
# WHAT THIS SCRIPT CHECKS
#   FC HBA  - lpfc driver version via esxcli (ESXi software layer)
#             Validates against VMware HCL for Dell LPe35002-M2-D (SSID f410)
#             Valid: lpfc 14.4.0.39/40/42-35vmw   Invalid: any -1OEM variant
#
#   PERC    - lsi_mr3 / bcm_mpi3 driver version via esxcli
#             Validates driver/firmware as a PAIR per VMware HCL for ESXi 8.0 U3
#             H755 valid pairs:
#               lsi_mr3 7.730.01.00-1OEM  +  firmware 52.30.0-6115    (preferred)
#               lsi_mr3 7.728.02.00-1vmw  +  firmware 52.21.0-4606    (acceptable)
#             H965 valid pairs:
#               bcm_mpi3 8.14.2.0.0.0-1OEM  +  firmware 8.14.0.0.18-14
#               bcm_mpi3 8.11.0.0.0-1OEM    +  firmware 8.11.0.0.18-22
#               bcm_mpi3 8.8.1.0.0-1vmw     +  firmware 8.8.0.0.18-26
#             FIRMWARE NOTE: 52.26.x is NOT in the HCL - update required
#
#   FIRMWARE - Emulex and PERC firmware via OME API
#              Endpoint: /api/DeviceService/Devices(id)/InventoryDetails('deviceSoftware')
#              Returns InventoryInfo[] where SoftwareType=FRMW are firmware components
#              DeviceDescription = component name, Version = installed version
#              Cross-checks OME reported firmware against HCL validated versions
#
# BRANCH HOST FILTER
#   Only processes hosts whose name starts with "esxi-"
#   All other hosts on the vCenter are skipped
# ============================================================

$omeServer    = "your-ome-server"  # Replace with your OME hostname or IP
$vCenter      = "your-vcenter.domain.com"  # Replace with your vCenter FQDN
$branchPrefix = "esxi-"

# ── TARGET HOST LIST ─────────────────────────────────────────────────────────
# Leave empty for full scan of all esxi-* hosts.
# Populate with short hostnames to scan a specific subset only.
# Useful for re-running against FW-UNVERIFIED or NON-COMPLIANT hosts after
# remediation, without waiting for a full 83-host scan.
$targetHosts = @(
    # "esxi-branch-host01"
    # "esxi-branch-host02"
    # "esxi-branch-host03"
    # Add hostnames here, one per line, uncommented
)
# ─────────────────────────────────────────────────────────────────────────────

$timestamp   = Get-Date -Format 'yyyyMMdd-HHmm'
$outputPath  = "C:\HCLReports\Branch_HCL_$timestamp.csv"
$summaryPath = "C:\HCLReports\Branch_HCL_SUMMARY_$timestamp.txt"
$htmlPath    = "C:\HCLReports\Branch_HCL_REPORT_$timestamp.html"

New-Item -Path "C:\HCLReports" -ItemType Directory -Force | Out-Null

# ============================================================
# SSL + TLS - PowerShell 5.1 compatible (no -SkipCertificateCheck)
# ============================================================
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# Increase connection timeout and keep-alive for slow OME endpoints
# InventoryDetails('deviceSoftware') can take 10-15s to respond per device
# Default ServicePoint timeout is 100s but connection idle timeout is much shorter
[System.Net.ServicePointManager]::MaxServicePointIdleTime  = 300000  # 5 min idle
[System.Net.ServicePointManager]::MaxServicePoints         = 50
[System.Net.ServicePointManager]::SetTcpKeepAlive($true, 30000, 5000)

if (-not ([System.Management.Automation.PSTypeName]'TrustAllCerts').Type) {
    Add-Type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCerts : ICertificatePolicy {
            public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem) {
                return true;
            }
        }
"@
}
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCerts

# ============================================================
# CREDENTIALS
# ============================================================
$omeCred = Get-Credential -Message "Enter OME local admin credentials (username only, no domain prefix)"
$vcCred  = Get-Credential -Message "Enter vCenter credentials for $vCenter"

# Auth body reused for token refresh
$authBody = @{
    UserName = $omeCred.UserName
    Password = $omeCred.GetNetworkCredential().Password
} | ConvertTo-Json

# ============================================================
# HELPER - OME REST call
# ============================================================
function Invoke-OMERequest {
    param(
        [string]$Uri,
        [string]$Method = "Get",
        [hashtable]$Headers,
        [string]$Body
    )
    $params = @{
        Uri             = $Uri
        Method          = $Method
        Headers         = $Headers
        UseBasicParsing = $true
        ErrorAction     = "Stop"
    }
    if ($Body) { $params.Body = $Body; $params.ContentType = "application/json" }
    $response = Invoke-WebRequest @params
    return ($response.Content | ConvertFrom-Json)
}

# ============================================================
# HELPER - Validate existing OME token; only re-authenticate
# if the current token has actually expired or been rejected.
#
# IMPORTANT: OME enforces a maximum concurrent session limit
# per user. Creating a new session on every host exhausts
# this limit (~30-40 hosts in) and triggers CUSR1340 errors.
# This function reuses the existing session token and only
# creates a new session when a lightweight probe confirms the
# current token is dead. The old session is deleted first to
# free up the slot before creating the replacement.
# ============================================================
function Refresh-OMEToken {
    param([hashtable]$Headers)

    # Probe the current token with a lightweight call
    # GET /api/SessionService/Sessions is low-cost and returns 401 on expired token
    try {
        $probe = Invoke-WebRequest `
            -Uri "https://$omeServer/api/SessionService/Sessions" `
            -Method Get `
            -Headers $Headers `
            -UseBasicParsing `
            -ErrorAction Stop
        # 200 response = token still valid, nothing to do
        return $true
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        if ($statusCode -ne 401 -and $statusCode -ne 403) {
            # Non-auth error (network issue etc.) - keep existing token and try anyway
            return $true
        }
        # 401/403 = token expired - fall through to re-authenticate below
    }

    Write-Host "        [INFO] OME token expired - re-authenticating..." -ForegroundColor DarkGray

    # Try to delete the expired session to free up the session slot
    # Failure here is non-fatal - the slot will time out eventually on its own
    try {
        Invoke-WebRequest `
            -Uri "https://$omeServer/api/SessionService/Sessions" `
            -Method Delete `
            -Headers $Headers `
            -UseBasicParsing `
            -ErrorAction SilentlyContinue | Out-Null
    } catch { }

    # Create a single fresh session
    $maxAttempts = 3
    for ($i = 1; $i -le $maxAttempts; $i++) {
        try {
            $r = Invoke-WebRequest `
                -Uri "https://$omeServer/api/SessionService/Sessions" `
                -Method Post `
                -Body $authBody `
                -ContentType "application/json" `
                -UseBasicParsing `
                -ErrorAction Stop
            $t = $r.Headers["X-Auth-Token"]
            if ($t) {
                $Headers["X-Auth-Token"] = $t
                Write-Host "        [INFO] OME re-authenticated successfully" -ForegroundColor DarkGray
                return $true
            }
        } catch {
            if ($i -lt $maxAttempts) {
                Start-Sleep -Seconds 5
            } else {
                Write-Host "        [WARN] OME re-authentication failed after $maxAttempts attempts" -ForegroundColor DarkYellow
            }
        }
    }
    return $false
}

# ============================================================
# HCL REFERENCE - Driver validation rules
# ============================================================

# FC HBA - Dell branded LPe35002-M2-D (SSID f410)
# ONLY VMware inbox -35vmw drivers validated on ESXi 8.0 U3
# OEM -1OEM drivers are NOT validated regardless of version
$fcValidDrivers  = @("14.4.0.39-35vmw", "14.4.0.40-35vmw", "14.4.0.42-35vmw")
$fcPreferredDriver = "lpfc 14.4.0.42-35vmw"

# PERC H755 - validated driver/firmware PAIRS
# The pair must match - updating firmware without updating driver creates a non-validated state
# 52.26.x is NOT in the HCL at all
$percH755ValidPairs = @(
    @{ Driver = "7.730.01.00-1OEM"; Firmware = "52.30.0"; Label = "lsi_mr3 7.730.01.00-1OEM + 52.30.0-6115 (preferred)" },
    @{ Driver = "7.728.02.00-1vmw"; Firmware = "52.21.0"; Label = "lsi_mr3 7.728.02.00-1vmw + 52.21.0-4606 (acceptable)" }
)
$percH755InvalidFirmware = @("52.26.")   # explicitly not in HCL

# PERC H965 - validated driver/firmware PAIRS
$percH965ValidPairs = @(
    @{ Driver = "8.14.2.0.0.0-1OEM"; Firmware = "8.14.0"; Label = "bcm_mpi3 8.14.2.0.0.0-1OEM + 8.14.0.0.18-14 (preferred)" },
    @{ Driver = "8.11.0.0.0-1OEM";   Firmware = "8.11.";  Label = "bcm_mpi3 8.11.0.0.0-1OEM + 8.11.0.0.18-22" },
    @{ Driver = "8.8.1.0.0-1vmw";    Firmware = "8.8.";   Label = "bcm_mpi3 8.8.1.0.0-1vmw + 8.8.0.0.18-26" }
)

# ============================================================
# HELPER - FC HBA driver compliance
# ============================================================
function Get-FCDriverCompliance {
    param([string]$Driver)

    if ($Driver -notlike "lpfc*") {
        return [PSCustomObject]@{
            Status   = "MANUAL-CHECK-REQUIRED"
            Required = $fcPreferredDriver
            Notes    = "Non-lpfc driver on FC adapter - check HCL manually"
        }
    }

    # Check for validated -35vmw inbox drivers
    $isValid = $fcValidDrivers | Where-Object { $Driver -like "*$_*" }
    if ($isValid) {
        return [PSCustomObject]@{
            Status   = "COMPLIANT"
            Required = $fcPreferredDriver
            Notes    = "VMware inbox driver validated for Dell LPe35002-M2-D SSID f410 on ESXi 8.0 U3"
        }
    }

    # Detect ESXi 7.x era driver - special callout
    if ($Driver -like "*14.2.*") {
        return [PSCustomObject]@{
            Status   = "NON-COMPLIANT"
            Required = $fcPreferredDriver
            Notes    = "ESXi 7.x era OEM driver - two major versions behind. Highest priority for remediation - SQL/production data integrity risk"
        }
    }

    # Any other -1OEM variant
    return [PSCustomObject]@{
        Status   = "NON-COMPLIANT"
        Required = $fcPreferredDriver
        Notes    = "OEM lpfc driver not validated for Dell branded LPe35002-M2-D SSID f410 on ESXi 8.0 U3. Remove OEM VIB to revert to inbox driver"
    }
}

# ============================================================
# HELPER - PERC driver/firmware pair compliance
# Returns object with Status, Required, Notes, and PairIssue flag
# ============================================================
function Get-PERCCompliance {
    param(
        [string]$Driver,    # full driver string e.g. "lsi_mr3 7.730.01.00-1OEM"
        [string]$Firmware   # firmware version from OME e.g. "52.30.0-6115"
    )

    # ---- PERC H755 (lsi_mr3) ----
    if ($Driver -like "*lsi_mr3*") {

        # Check for explicitly invalid firmware first
        $badFW = $percH755InvalidFirmware | Where-Object { $Firmware -like "*$_*" }
        if ($badFW) {
            # Determine which driver they have to give targeted advice
            if ($Driver -like "*7.728*") {
                $note = "Firmware 52.26.x is NOT in the VMware HCL. Driver 7.728 requires firmware 52.21.0-4606. Upgrade both driver to 7.730.01.00-1OEM and firmware to 52.30.0-6115 for preferred validated pair"
            } elseif ($Driver -like "*7.730*") {
                $note = "Firmware 52.26.x is NOT in the VMware HCL. Driver 7.730 requires firmware 52.30.0-6115. Firmware update required"
            } else {
                $note = "Firmware 52.26.x is NOT in the VMware HCL for any driver version. Update firmware to 52.30.0-6115"
            }
            return [PSCustomObject]@{
                Status    = "NON-COMPLIANT"
                Required  = "lsi_mr3 7.730.01.00-1OEM + firmware 52.30.0-6115"
                Notes     = $note
                PairIssue = $true
            }
        }

        # Check validated pairs
        foreach ($pair in $percH755ValidPairs) {
            $driverMatch   = $Driver   -like "*$($pair.Driver)*"
            $firmwareMatch = $Firmware -like "*$($pair.Firmware)*"

            if ($driverMatch -and $firmwareMatch) {
                # Both match - fully validated pair
                $preferred = if ($pair.Driver -like "*7.730*") { "" } else { " - consider upgrading to preferred pair 7.730.01.00-1OEM + 52.30.0-6115" }
                return [PSCustomObject]@{
                    Status    = "COMPLIANT"
                    Required  = $pair.Label
                    Notes     = "Validated HCL pair$preferred"
                    PairIssue = $false
                }
            } elseif ($driverMatch -and -not $firmwareMatch) {
                # Driver matches but firmware does not
                return [PSCustomObject]@{
                    Status    = "NON-COMPLIANT"
                    Required  = $pair.Label
                    Notes     = "Driver version is valid but firmware $Firmware does not match the validated pair for this driver. Update firmware to match validated pair or upgrade both to preferred pair (7.730-1OEM + 52.30.0-6115)"
                    PairIssue = $true
                }
            } elseif (-not $driverMatch -and $firmwareMatch) {
                # Firmware matches a pair but driver does not - classic OME baseline mismatch
                return [PSCustomObject]@{
                    Status    = "NON-COMPLIANT"
                    Required  = "lsi_mr3 7.730.01.00-1OEM + firmware 52.30.0-6115"
                    Notes     = "Firmware $Firmware was updated without matching driver update - mismatched unvalidated combination. This is the OME patching baseline gap. Update driver to 7.730.01.00-1OEM to complete the validated pair"
                    PairIssue = $true
                }
            }
        }

        # Driver version not in reference table at all
        return [PSCustomObject]@{
            Status    = "MANUAL-CHECK-REQUIRED"
            Required  = "lsi_mr3 7.730.01.00-1OEM + firmware 52.30.0-6115"
            Notes     = "PERC H755 driver version $Driver not in local HCL reference - verify at compatibilityguide.broadcom.com"
            PairIssue = $false
        }
    }

    # ---- PERC H965 (bcm_mpi3) ----
    if ($Driver -like "*bcm_mpi3*") {
        foreach ($pair in $percH965ValidPairs) {
            $driverMatch   = $Driver   -like "*$($pair.Driver)*"
            $firmwareMatch = $Firmware -like "*$($pair.Firmware)*"

            if ($driverMatch -and $firmwareMatch) {
                $preferred = if ($pair.Driver -like "*8.14*") { "" } else { " - consider upgrading to preferred pair 8.14.2.0.0.0-1OEM + 8.14.0.0.18-14" }
                return [PSCustomObject]@{
                    Status    = "COMPLIANT"
                    Required  = $pair.Label
                    Notes     = "Validated HCL pair$preferred"
                    PairIssue = $false
                }
            } elseif ($driverMatch -and -not $firmwareMatch) {
                return [PSCustomObject]@{
                    Status    = "NON-COMPLIANT"
                    Required  = $pair.Label
                    Notes     = "Driver version valid but firmware $Firmware does not match validated pair. Update firmware or upgrade both to preferred pair (8.14.2.0.0.0-1OEM + 8.14.0.0.18-14)"
                    PairIssue = $true
                }
            } elseif (-not $driverMatch -and $firmwareMatch) {
                return [PSCustomObject]@{
                    Status    = "NON-COMPLIANT"
                    Required  = "bcm_mpi3 8.14.2.0.0.0-1OEM + firmware 8.14.0.0.18-14"
                    Notes     = "Firmware updated without matching driver update. Update driver to complete validated pair"
                    PairIssue = $true
                }
            }
        }

        return [PSCustomObject]@{
            Status    = "MANUAL-CHECK-REQUIRED"
            Required  = "bcm_mpi3 8.14.2.0.0.0-1OEM + firmware 8.14.0.0.18-14"
            Notes     = "PERC H965 driver version $Driver not in local HCL reference - verify at compatibilityguide.broadcom.com"
            PairIssue = $false
        }
    }

    # Unknown PERC driver
    return [PSCustomObject]@{
        Status    = "MANUAL-CHECK-REQUIRED"
        Required  = "Check compatibilityguide.broadcom.com"
        Notes     = "Unknown PERC driver type - verify manually"
        PairIssue = $false
    }
}

# ============================================================
# STEP 1 - Authenticate to OME
# ============================================================
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " Connecting to OME: https://$omeServer"     -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

try {
    $authResponse = Invoke-WebRequest `
        -Uri "https://$omeServer/api/SessionService/Sessions" `
        -Method Post `
        -Body $authBody `
        -ContentType "application/json" `
        -UseBasicParsing

    $omeToken = $authResponse.Headers["X-Auth-Token"]

    if (-not $omeToken) {
        Write-Host "[ERROR] Auth succeeded but no token returned" -ForegroundColor Red
        exit
    }

    $omeHeaders = @{
        "X-Auth-Token" = $omeToken
        "Content-Type" = "application/json"
    }

    Write-Host "[OK] OME authenticated - token acquired" -ForegroundColor Green

} catch {
    Write-Host "[ERROR] OME authentication failed: $($_.Exception.Message)" -ForegroundColor Red
    exit
}

# ============================================================
# STEP 2 - Pull OME device inventory + bulk firmware data
# Firmware is fetched once in bulk via FirmwareInventory report
# rather than per-device InventoryDetails calls. This avoids
# the "connection was closed" errors caused by OME dropping
# slow per-device TCP connections under sequential load.
# ============================================================
Write-Host ""
Write-Host "Retrieving OME device inventory..." -ForegroundColor Cyan

try {
    $allOMEDevices = Invoke-OMERequest `
        -Uri "https://$omeServer/api/DeviceService/Devices?`$top=5000" `
        -Headers $omeHeaders
    Write-Host "[OK] Retrieved $($allOMEDevices.'@odata.count') devices from OME" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to retrieve OME devices: $($_.Exception.Message)" -ForegroundColor Red
    exit
}

# Firmware lookup table - populated in STEP 2b after vCenter connect
# Keys: OME DeviceId (string) -> array of FRMW inventory items
$omeFirmwareByDevice = @{}

# ============================================================
# STEP 3 - Connect to vCenter, filter to branch hosts only
# ============================================================
Write-Host ""
Write-Host "============================================" -ForegroundColor Magenta
Write-Host " vCenter: $vCenter"                          -ForegroundColor Magenta
Write-Host " Scope  : Hosts with prefix '$branchPrefix'" -ForegroundColor Magenta
Write-Host "============================================" -ForegroundColor Magenta

try {
    Connect-VIServer -Server $vCenter -Credential $vcCred -ErrorAction Stop | Out-Null
    Write-Host "[OK] Connected to $vCenter" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Could not connect to $vCenter : $($_.Exception.Message)" -ForegroundColor Red
    exit
}

# Get all hosts from vCenter (all containers including subfolders)
$allHosts    = Get-VMHost | Sort-Object Name
$branchHosts = $allHosts | Where-Object { $_.Name -like "$branchPrefix*" }

# Apply target host filter if $targetHosts is populated
$scanMode = "FULL"
if ($targetHosts -and $targetHosts.Count -gt 0) {
    $scanMode    = "TARGETED"
    $branchHosts = $branchHosts | Where-Object {
        $shortN = $_.Name.Split('.')[0]
        $targetHosts -contains $shortN
    }
}

Write-Host ""
Write-Host "  Total hosts in vCenter : $($allHosts.Count)"     -ForegroundColor Gray
Write-Host "  Branch hosts (esxi-*)  : $($($allHosts | Where-Object { $_.Name -like "$branchPrefix*" }).Count)"  -ForegroundColor Gray
if ($scanMode -eq "TARGETED") {
    Write-Host "  Scan mode              : TARGETED ($($branchHosts.Count) hosts specified)" -ForegroundColor Cyan
} else {
    Write-Host "  Scan mode              : FULL ($($branchHosts.Count) hosts)" -ForegroundColor Cyan
}
Write-Host ""

if ($branchHosts.Count -eq 0) {
    Write-Host "[WARN] No matching hosts found. Check `$targetHosts list or prefix '$branchPrefix'." -ForegroundColor Yellow
    exit
}

# ============================================================
# STEP 2b - Fetch firmware for all branch hosts in parallel
# Uses PowerShell background jobs so each InventoryDetails call
# is independent - one slow/dropped connection cannot block others.
# All jobs run simultaneously then we collect results before
# the host loop begins. No per-host HTTP calls during the loop.
# ============================================================
Write-Host ""
Write-Host "Fetching firmware inventory from OME (parallel jobs)..." -ForegroundColor Cyan

# Build list of deviceId -> hostname for branch hosts we care about
$fwJobList = @()
foreach ($vmhost in $branchHosts) {
    if ($vmhost.Version -like "7.*") { continue }
    try {
        $svcTagTmp = (Get-VMHostHardware -VMHost $vmhost -ErrorAction SilentlyContinue).SerialNumber
    } catch { $svcTagTmp = $null }

    $domainTmp  = ($vmhost.Name -split '\.', 2)[1]
    $shortTmp   = $vmhost.Name.Split('.')[0]
    $idracTmp   = "$shortTmp-drac.$domainTmp"

    $omeDevTmp  = $null
    if ($svcTagTmp) {
        $omeDevTmp = $allOMEDevices.value | Where-Object { $_.DeviceServiceTag -eq $svcTagTmp }
    }
    if (-not $omeDevTmp) {
        $omeDevTmp = $allOMEDevices.value | Where-Object {
            $_.DeviceName -eq $idracTmp -or $_.DeviceName -eq "$shortTmp-drac"
        }
    }
    if ($omeDevTmp) {
        $fwJobList += [PSCustomObject]@{ DeviceId = $omeDevTmp.Id; Hostname = $vmhost.Name }
    }
}

Write-Host "  Queuing $($fwJobList.Count) firmware jobs..." -ForegroundColor Gray

# Script block executed by each background job
$fwJobScript = {
    param($omeServer, $omeToken, $deviceId, $hostname)

    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    [System.Net.ServicePointManager]::MaxServicePointIdleTime = 300000
    [System.Net.ServicePointManager]::SetTcpKeepAlive($true, 30000, 5000)

    if (-not ([System.Management.Automation.PSTypeName]'TrustAllCerts').Type) {
        Add-Type @"
            using System.Net;
            using System.Security.Cryptography.X509Certificates;
            public class TrustAllCerts : ICertificatePolicy {
                public bool CheckValidationResult(
                    ServicePoint srvPoint, X509Certificate certificate,
                    WebRequest request, int certificateProblem) { return true; }
            }
"@
    }
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCerts

    $headers = @{ "X-Auth-Token" = $omeToken; "Content-Type" = "application/json" }
    $maxTry = 3
    for ($t = 1; $t -le $maxTry; $t++) {
        try {
            $resp = Invoke-WebRequest `
                -Uri "https://$omeServer/api/DeviceService/Devices($deviceId)/InventoryDetails('deviceSoftware')" `
                -Method Get -Headers $headers -UseBasicParsing -TimeoutSec 90 -ErrorAction Stop
            $data = $resp.Content | ConvertFrom-Json
            return [PSCustomObject]@{
                DeviceId = $deviceId
                Hostname = $hostname
                Items    = $data.InventoryInfo | Where-Object { $_.SoftwareType -eq "FRMW" }
                Error    = $null
            }
        } catch {
            if ($t -lt $maxTry) { Start-Sleep -Seconds 5 }
            else {
                return [PSCustomObject]@{
                    DeviceId = $deviceId; Hostname = $hostname
                    Items = $null; Error = $_.Exception.Message
                }
            }
        }
    }
}

# Start all jobs simultaneously (max 10 concurrent to avoid overwhelming OME)
$maxConcurrent = 10
$jobs          = @()
$jobQueue      = [System.Collections.Queue]::new()
foreach ($entry in $fwJobList) { $jobQueue.Enqueue($entry) }

while ($jobQueue.Count -gt 0 -or $jobs.Count -gt 0) {
    # Start new jobs up to concurrency limit
    while ($jobs.Count -lt $maxConcurrent -and $jobQueue.Count -gt 0) {
        $entry = $jobQueue.Dequeue()
        $job   = Start-Job -ScriptBlock $fwJobScript `
                     -ArgumentList $omeServer, $omeHeaders["X-Auth-Token"], $entry.DeviceId, $entry.Hostname
        $jobs += $job
    }

    # Collect any completed jobs
    $stillRunning = @()
    foreach ($job in $jobs) {
        if ($job.State -in @("Completed","Failed","Stopped")) {
            $result = Receive-Job -Job $job -ErrorAction SilentlyContinue
            Remove-Job -Job $job -Force

            if ($result -and $result.Items) {
                $omeFirmwareByDevice[[string]$result.DeviceId] = $result.Items
            } elseif ($result -and $result.Error) {
                Write-Host "  [WARN] FW query failed for $($result.Hostname): $($result.Error)" -ForegroundColor DarkYellow
            }
        } else {
            $stillRunning += $job
        }
    }
    $jobs = $stillRunning

    if ($jobQueue.Count -gt 0 -or $jobs.Count -gt 0) { Start-Sleep -Milliseconds 500 }
}

$devicesWithFW = $omeFirmwareByDevice.Count
Write-Host "[OK] Firmware data collected for $devicesWithFW of $($fwJobList.Count) hosts" -ForegroundColor $(
    if ($devicesWithFW -eq $fwJobList.Count) {"Green"} else {"Yellow"})

# ============================================================
# STEP 4 - Process each branch host
# Per-host data collection:
#   a) OME lookup for firmware (FC HBA + PERC)
#   b) esxcli for driver versions
#   c) Pair-validate PERC driver vs firmware
# ============================================================

$report         = [System.Collections.Generic.List[PSObject]]::new()
$hostSummary    = [System.Collections.Generic.List[PSObject]]::new()
$totalHosts     = 0
$processedOK    = 0
$notInOME       = 0
$queryErrors    = 0

$skippedESXi7 = 0

foreach ($vmhost in $branchHosts) {

    # ---- Skip ESXi 7.x hosts ------------------------------------------------
    # HCL validation in this script is scoped to ESXi 8.0 U3 only.
    # ESXi 7.x hosts have a different HCL baseline and must be assessed separately.
    if ($vmhost.Version -like "7.*") {
        Write-Host "  [SKIP] $($vmhost.Name) - ESXi $($vmhost.Version) (7.x not in scope)" -ForegroundColor DarkGray
        $skippedESXi7++
        continue
    }

    $totalHosts++
    $shortName = $vmhost.Name.Split('.')[0]

    # Branch hosts are all standalone - no cluster
    $hostType    = "Standalone"
    $clusterName = "N/A"

    # Get folder path so we know which branch/subfolder this host is in
    $folderPath = ""
    try {
        $parent = $vmhost.Parent
        $pathParts = @()
        while ($parent -and $parent.GetType().Name -ne "Datacenter") {
            if ($parent.GetType().Name -eq "Folder") {
                $pathParts = @($parent.Name) + $pathParts
            }
            $parent = $parent.Parent
        }
        $folderPath = if ($pathParts.Count -gt 0) { $pathParts -join "/" } else { "Root" }
    } catch {
        $folderPath = "Unknown"
    }

    Write-Host "  [$($totalHosts.ToString().PadLeft(3))] $($vmhost.Name)" -ForegroundColor Yellow
    Write-Host "        Folder: $folderPath" -ForegroundColor Gray

    # Service tag lookup
    try {
        $svcTag = (Get-VMHostHardware -VMHost $vmhost -ErrorAction Stop).SerialNumber
    } catch {
        $svcTag = "Unknown"
    }
    Write-Host "        Tag   : $svcTag" -ForegroundColor Gray

    # --- Per-host tracking vars ---
    $hostFCStatus   = "NO-FC-HBA"
    $hostPERCStatus = "NO-PERC"
    $hostOverall    = "COMPLIANT"
    $hostIssues     = @()

    # OME firmware storage for PERC pair validation
    $omePercFirmware = @{}   # key: component type, value: version string

    # esxcli driver storage
    $esxcliDrivers   = @{}   # key: driver type (lpfc/lsi_mr3/bcm_mpi3), value: full version string

    # --------------------------------------------------------
    # 4a - OME Firmware query
    # --------------------------------------------------------
    $omeDevice = $allOMEDevices.value | Where-Object { $_.DeviceServiceTag -eq $svcTag }

    if (-not $omeDevice) {
        Write-Host "        [WARN] Not found in OME inventory" -ForegroundColor DarkYellow
        $notInOME++

        $report.Add([PSCustomObject]@{
            vCenter        = $vCenter
            Hostname       = $vmhost.Name
            Folder         = $folderPath
            HostType       = $hostType
            ServiceTag     = $svcTag
            Model          = $vmhost.Model
            ESXiVersion    = $vmhost.Version
            Build          = $vmhost.Build
            ComponentName  = "HOST NOT IN OME"
            ComponentType  = "WARNING"
            CurrentVersion = "N/A"
            HCLRequired    = "N/A"
            HCLCompliant   = "NOT-IN-OME"
            InstallDate    = "N/A"
            Notes          = "Host not found in OME by service tag. May not be inventoried yet."
        })

        $hostSummary.Add([PSCustomObject]@{
            Hostname    = $vmhost.Name
            ShortName   = $shortName
            Folder      = $folderPath
            Model       = $vmhost.Model
            ServiceTag  = $svcTag
            ESXiVersion = $vmhost.Version
            FCStatus    = "NOT-IN-OME"
            PERCStatus  = "NOT-IN-OME"
            Overall     = "NOT-IN-OME"
            Issues      = "Host not found in OME"
        })
        continue
    }

    $deviceId    = $omeDevice.Id
    $processedOK++

    # Look up firmware from the bulk inventory table fetched at startup
    # No per-device HTTP calls needed - avoids OME connection-closed errors
    $omeFWAvailable = $omeFirmwareByDevice.ContainsKey([string]$deviceId)

    if ($omeFWAvailable) {
        # FirmwareInventory items have: DeviceDescription (=ComponentDescription),
        # Version, InstanceId, Type (FRMW). All items are already FRMW-filtered.
        # Map to the same field names used by the parsing block below.
        $allFRMW = $omeFirmwareByDevice[[string]$deviceId] | ForEach-Object {
            # InventoryDetails('deviceSoftware') .InventoryInfo items use:
            #   .Name        = component description (e.g. "PERC H755 Front", "BOSS-N1 Monolithic")
            #   .Version     = firmware version string
            #   .InstanceId  = DCIM path (e.g. "DCIM:INSTALLED#301_C_RAID.SL.3-1")
            # Normalise to consistent field names used by the parsing block below.
            $nameVal = if ($_.Name)                { $_.Name }
                       elseif ($_.DeviceDescription) { $_.DeviceDescription }
                       elseif ($_.ComponentDescription) { $_.ComponentDescription }
                       else { "" }
            [PSCustomObject]@{
                DeviceDescription = $nameVal
                Version           = $_.Version
                InstanceId        = if ($_.InstanceId) { $_.InstanceId } else { "" }
                InstallationDate  = $null
            }
        }

        foreach ($fw in $allFRMW) {
            $fwDesc   = $fw.DeviceDescription
            $instId   = $fw.InstanceId
            $rawVer   = if ($fw.Version) { $fw.Version } else { "" }

            # ---- PERC controller firmware ----
            # Match ONLY the PERC controller entry. Two conditions BOTH required:
            #   1. InstanceId must contain '_C_RAID' (rules out BOSS, disks, backplane)
            #   2. InstanceId must NOT contain '_C_BOSS' (extra guard for T640/R750)
            #
            # InstanceId patterns on Dell servers:
            #   DCIM:INSTALLED#301_C_RAID.SL.3-1     = PERC H755/H750/H730  ✅ match
            #   DCIM:INSTALLED#401_C_RAID.SL.x-1     = PERC H965             ✅ match
            #   DCIM:INSTALLED#304_C_Disk.Bay.x:...  = Individual disk        ❌ no _C_RAID
            #   DCIM:INSTALLED#314_C_RAID.Backplane.1 = Backplane             ❌ excluded below
            #   DCIM:INSTALLED#301_C_BOSS.SL.12-1    = BOSS SSD (T640/R750)  ❌ _C_BOSS
            #
            # Backplane has _C_RAID in InstanceId but description is "Backplane x"
            # so the fwDesc guard catches it.
            $isBOSS       = ($instId -like "*_C_BOSS*") -or ($fwDesc -like "*BOSS*")
            $isRAIDInstId = ($instId -like "*_C_RAID*") -and (-not $isBOSS)
            $isPERCByDesc = ($fwDesc -like "PERC H*") -and (-not $isBOSS)
            $isBackplane  = ($fwDesc -like "Backplane*") -or ($fwDesc -like "*Backplane*")
            $isPERCController = ($isRAIDInstId -or $isPERCByDesc) -and (-not $isBackplane)

            if ($isPERCController -and $rawVer -match '\.') {
                if ($fwDesc -like "*H965*" -or $instId -like "*401_C_RAID*") {
                    if (-not $omePercFirmware.ContainsKey("H965")) {
                        $omePercFirmware["H965"] = $rawVer
                        Write-Host "        FW  PERC H965: $rawVer" -ForegroundColor Cyan
                    }
                } else {
                    # H755 / H750 / H730 - all use lsi_mr3, stored under H755 key
                    if (-not $omePercFirmware.ContainsKey("H755")) {
                        $omePercFirmware["H755"] = $rawVer
                        Write-Host "        FW  PERC H755: $rawVer" -ForegroundColor Cyan
                    }
                }
            }

            # ---- Emulex FC HBA firmware ----
            # InstanceId pattern for FC HBA: #701_FC or description contains Emulex/LPe
            $isFC = $fwDesc -like "*Emulex*" -or
                    $fwDesc -like "*LPe*"    -or
                    $fwDesc -like "*Fibre Channel*"

            if ($isFC -and $rawVer -match '\.') {
                $validFFV = @("03.08.", "03.09.", "03.10.", "14.4.322", "14.4.730", "14.4.436")
                $fwValid  = $validFFV | Where-Object { $rawVer -like "*$_*" }

                $fwStatus = if ($fwValid) { "COMPLIANT" } else { "NON-COMPLIANT" }
                $fwNotes  = if ($fwValid) {
                    "FC HBA firmware is a validated Additional Firmware Version (FFV) for ESXi 8.0 U3"
                } else {
                    "FC HBA firmware $rawVer not in validated FFV list. Valid: FFV 03.08.x / 03.09.x / 03.10.x / 14.4.322.17"
                }

                if ($fwStatus -eq "NON-COMPLIANT") {
                    $hostOverall = "NON-COMPLIANT"
                    $hostIssues += "FC HBA firmware $rawVer not validated"
                }

                $report.Add([PSCustomObject]@{
                    vCenter        = $vCenter
                    Hostname       = $vmhost.Name
                    Folder         = $folderPath
                    HostType       = $hostType
                    ServiceTag     = $svcTag
                    Model          = $vmhost.Model
                    ESXiVersion    = $vmhost.Version
                    Build          = $vmhost.Build
                    ComponentName  = $fwDesc
                    ComponentType  = "FIRMWARE"
                    CurrentVersion = $rawVer
                    HCLRequired    = "FFV 03.09.x or 03.10.x (recommended)"
                    HCLCompliant   = $fwStatus
                    InstallDate    = $fw.InstallationDate
                    Notes          = $fwNotes
                })

                Write-Host "        FW  $($fwDesc): $rawVer [$fwStatus]" -ForegroundColor $(if ($fwStatus -eq "COMPLIANT") {"Green"} else {"Red"})
            }
        }

        # Warn if no PERC firmware was resolved - shows raw controller-like entries for diagnosis
        if ($omePercFirmware.Count -eq 0) {
            $percRaw = ($allFRMW | Where-Object {
                $_.DeviceDescription -like "*PERC*" -or $_.InstanceId -like "*RAID*"
            } | ForEach-Object {
                "[$($_.DeviceDescription) | Ver=$($_.Version) | InstId=$($_.InstanceId)]"
            }) -join "`n          "
            Write-Host "        [DEBUG] No PERC controller firmware resolved. PERC/RAID entries:`n          $percRaw" -ForegroundColor DarkCyan
        }

    } # end if ($omeFWAvailable)

    # --------------------------------------------------------
    # 4b - esxcli driver version query
    # --------------------------------------------------------
    try {
        $esxcli = Get-EsxCli -VMHost $vmhost -V2

        # Get all storage adapters - filter for lpfc (FC HBA) and PERC drivers
        $adapters = $esxcli.storage.core.adapter.list.Invoke() | Where-Object {
            $_.Driver -like "lpfc*"    -or
            $_.Driver -like "lsi_mr3*" -or
            $_.Driver -like "bcm_mpi3*"
        }

        # Deduplicate - one version lookup per unique driver module name
        $processedModules = @{}

        foreach ($adapter in $adapters) {
            $driverName = $adapter.Driver

            if (-not $processedModules.ContainsKey($driverName)) {
                try {
                    $modInfo = $esxcli.system.module.get.Invoke(@{ module = $driverName })
                    # Guard against null/empty version (can occur on brief esxcli timeout)
                    if ($modInfo.Version -and $modInfo.Version.Trim() -ne "") {
                        $fullVersion = "$driverName $($modInfo.Version)"
                    } else {
                        # Retry once with a short pause
                        Start-Sleep -Seconds 2
                        $modInfo2 = $esxcli.system.module.get.Invoke(@{ module = $driverName })
                        if ($modInfo2.Version -and $modInfo2.Version.Trim() -ne "") {
                            $fullVersion = "$driverName $($modInfo2.Version)"
                        } else {
                            Write-Host "        [WARN] Empty version for $driverName - re-run targeted scan to resolve" -ForegroundColor DarkYellow
                            $fullVersion = $driverName   # name only - triggers FW-UNVERIFIED path
                        }
                    }
                } catch {
                    $fullVersion = $driverName
                }
                $processedModules[$driverName] = $fullVersion

                # Store by type for PERC pair validation
                if ($driverName -like "lpfc*")    { $esxcliDrivers["lpfc"]    = $fullVersion }
                if ($driverName -like "lsi_mr3*") { $esxcliDrivers["lsi_mr3"] = $fullVersion }
                if ($driverName -like "bcm_mpi3*"){ $esxcliDrivers["bcm_mpi3"]= $fullVersion }
            } else {
                $fullVersion = $processedModules[$driverName]
            }

            # ---- FC HBA driver compliance ----
            if ($driverName -like "lpfc*") {
                $comp = Get-FCDriverCompliance -Driver $fullVersion

                if ($comp.Status -ne "COMPLIANT") {
                    $hostOverall = "NON-COMPLIANT"
                    $hostIssues += "FC HBA driver: $fullVersion"
                    $hostFCStatus = "NON-COMPLIANT"
                } else {
                    if ($hostFCStatus -ne "NON-COMPLIANT") { $hostFCStatus = "COMPLIANT" }
                }

                $report.Add([PSCustomObject]@{
                    vCenter        = $vCenter
                    Hostname       = $vmhost.Name
                    Folder         = $folderPath
                    HostType       = $hostType
                    ServiceTag     = $svcTag
                    Model          = $vmhost.Model
                    ESXiVersion    = $vmhost.Version
                    Build          = $vmhost.Build
                    ComponentName  = "Driver (FC HBA): $($adapter.HBAName)"
                    ComponentType  = "DRIVER-FC"
                    CurrentVersion = $fullVersion
                    HCLRequired    = $comp.Required
                    HCLCompliant   = $comp.Status
                    InstallDate    = "N/A"
                    Notes          = "$($comp.Notes) | LinkState: $($adapter.LinkState)"
                })

                $col = if ($comp.Status -eq "COMPLIANT") {"Green"} elseif ($comp.Status -eq "NON-COMPLIANT") {"Red"} else {"Yellow"}
                Write-Host "        FC  $($adapter.HBAName): $fullVersion [$($comp.Status)]" -ForegroundColor $col
            }

            # ---- PERC driver - deferred to pair validation below ----
            if ($driverName -like "lsi_mr3*" -or $driverName -like "bcm_mpi3*") {
                Write-Host "        PERC driver: $fullVersion [pair validation pending]" -ForegroundColor Gray
            }
        }

    } catch {
        Write-Host "        [WARN] esxcli driver query failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
        $queryErrors++
    }

    # --------------------------------------------------------
    # 4c - PERC pair validation
    # Cross-validate esxcli driver against OME firmware
    # This is the key check - the pair must match the HCL
    # --------------------------------------------------------
    $percDriverTypes = @("lsi_mr3", "bcm_mpi3")
    $percFound = $false

    foreach ($percType in $percDriverTypes) {
        if (-not $esxcliDrivers.ContainsKey($percType)) { continue }

        $percFound     = $true
        $percDriver    = $esxcliDrivers[$percType]
        $controllerKey = if ($percType -eq "lsi_mr3") { "H755" } else { "H965" }

        # Try to get firmware from OME - first try specific key, then generic PERC key
        $percFirmware  = if ($omePercFirmware.ContainsKey($controllerKey)) {
            $omePercFirmware[$controllerKey]
        } elseif ($omePercFirmware.ContainsKey("PERC")) {
            $omePercFirmware["PERC"]
        } else {
            "UNKNOWN"
        }

        # When OME firmware is unavailable, validate driver version only.
        # A known-valid driver paired with unknown firmware is flagged FW-UNVERIFIED
        # rather than NON-COMPLIANT - it is not a confirmed failure, just unconfirmed.
        # Hosts flagged FW-UNVERIFIED need a manual OME check to confirm firmware.
        if ($percFirmware -eq "UNKNOWN") {

            # Determine if driver version itself is a known-valid driver
            $knownValidDrivers = @(
                "7.730.01.00-1OEM",   # H755 preferred
                "7.728.02.00-1vmw",   # H755 acceptable
                "8.14.2.0.0.0-1OEM",  # H965 preferred
                "8.11.0.0.0-1OEM",    # H965
                "8.8.1.0.0-1vmw"      # H965 inbox
            )
            $driverKnown = $knownValidDrivers | Where-Object { $percDriver -like "*$_*" }

            if ($driverKnown) {
                $pairStatus  = "FW-UNVERIFIED"
                $pairNote    = "Driver $percDriver is a valid HCL driver. Firmware could not be retrieved from OME - run OME firmware check manually to confirm pair"
                $pairRequired = if ($percType -eq "lsi_mr3") { "lsi_mr3 7.730.01.00-1OEM + firmware 52.30.0-6115" } else { "bcm_mpi3 8.14.2.0.0.0-1OEM + firmware 8.14.0.0.18-14" }
                if ($hostPERCStatus -ne "NON-COMPLIANT") { $hostPERCStatus = "FW-UNVERIFIED" }
                if ($hostOverall -ne "NON-COMPLIANT") { $hostOverall = "FW-UNVERIFIED" }
            } else {
                $pairStatus  = "NON-COMPLIANT"
                $pairNote    = "Driver $percDriver is NOT a valid HCL driver for ESXi 8.0 U3. Firmware also unavailable from OME."
                $pairRequired = if ($percType -eq "lsi_mr3") { "lsi_mr3 7.730.01.00-1OEM + firmware 52.30.0-6115" } else { "bcm_mpi3 8.14.2.0.0.0-1OEM + firmware 8.14.0.0.18-14" }
                $hostOverall    = "NON-COMPLIANT"
                $hostPERCStatus = "NON-COMPLIANT"
                $hostIssues    += "PERC driver NOT valid: $percDriver"
            }

            $report.Add([PSCustomObject]@{
                vCenter        = $vCenter
                Hostname       = $vmhost.Name
                Folder         = $folderPath
                HostType       = $hostType
                ServiceTag     = $svcTag
                Model          = $vmhost.Model
                ESXiVersion    = $vmhost.Version
                Build          = $vmhost.Build
                ComponentName  = "PERC $controllerKey Driver+Firmware Pair"
                ComponentType  = "DRIVER-PERC-PAIR"
                CurrentVersion = "$percDriver + FW UNKNOWN (OME unavailable)"
                HCLRequired    = $pairRequired
                HCLCompliant   = $pairStatus
                InstallDate    = "N/A"
                Notes          = $pairNote
            })

            $col = if ($pairStatus -eq "FW-UNVERIFIED") {"Yellow"} elseif ($pairStatus -eq "NON-COMPLIANT") {"Red"} else {"Green"}
            Write-Host "        PERC $($controllerKey): $($percDriver) [FW UNKNOWN - $($pairStatus)]" -ForegroundColor $col

        } else {

            # Firmware is available - do full pair validation
            $percComp = Get-PERCCompliance -Driver $percDriver -Firmware $percFirmware

            if ($percComp.Status -ne "COMPLIANT") {
                $hostOverall    = "NON-COMPLIANT"
                $hostPERCStatus = "NON-COMPLIANT"
                $hostIssues    += "PERC driver/firmware pair mismatch: $percDriver + $percFirmware"
            } else {
                if ($hostPERCStatus -ne "NON-COMPLIANT") { $hostPERCStatus = "COMPLIANT" }
            }

            $report.Add([PSCustomObject]@{
                vCenter        = $vCenter
                Hostname       = $vmhost.Name
                Folder         = $folderPath
                HostType       = $hostType
                ServiceTag     = $svcTag
                Model          = $vmhost.Model
                ESXiVersion    = $vmhost.Version
                Build          = $vmhost.Build
                ComponentName  = "PERC $controllerKey Driver+Firmware Pair"
                ComponentType  = "DRIVER-PERC-PAIR"
                CurrentVersion = "$percDriver + FW $percFirmware"
                HCLRequired    = $percComp.Required
                HCLCompliant   = $percComp.Status
                InstallDate    = "N/A"
                Notes          = "$($percComp.Notes)$(if ($percComp.PairIssue) {' [PAIR MISMATCH]'} else {''})"
            })

            $col = if ($percComp.Status -eq "COMPLIANT") {"Green"} elseif ($percComp.Status -eq "NON-COMPLIANT") {"Red"} else {"Yellow"}
            Write-Host "        PERC $($controllerKey) pair: $($percDriver) + $($percFirmware) [$($percComp.Status)]" -ForegroundColor $col

        } # end firmware available check
    }

    if (-not $percFound) { $hostPERCStatus = "NO-PERC-DETECTED" }
    if ($hostFCStatus -eq "NO-FC-HBA" -and -not $percFound) {
        Write-Host "        [INFO] No FC HBA or PERC drivers found via esxcli" -ForegroundColor Gray
    }

    # ---- Determine final overall for this host ----
    if ($hostOverall -eq "COMPLIANT" -and $hostFCStatus -eq "NO-FC-HBA" -and $hostPERCStatus -in @("COMPLIANT","NO-PERC-DETECTED")) {
        $hostOverall = "COMPLIANT"
    }

    # ---- Add to host summary table ----
    $hostSummary.Add([PSCustomObject]@{
        Hostname    = $vmhost.Name
        ShortName   = $shortName
        Folder      = $folderPath
        Model       = $vmhost.Model
        ServiceTag  = $svcTag
        ESXiVersion = $vmhost.Version
        FCStatus    = $hostFCStatus
        PERCStatus  = $hostPERCStatus
        Overall     = $hostOverall
        Issues      = if ($hostIssues.Count -gt 0) { $hostIssues -join "; " } else { "None" }
    })

    $overallColor = if ($hostOverall -eq "COMPLIANT") {"Green"} elseif ($hostOverall -eq "NON-COMPLIANT") {"Red"} else {"Yellow"}
    Write-Host "        Overall: [$hostOverall]" -ForegroundColor $overallColor
    Write-Host ""
}

Disconnect-VIServer -Server $vCenter -Confirm:$false
Write-Host "Disconnected from $vCenter" -ForegroundColor Gray

# Clean up OME session to free the session slot for other users
Write-Host "Closing OME session..." -ForegroundColor Gray
try {
    Invoke-WebRequest `
        -Uri "https://$omeServer/api/SessionService/Sessions" `
        -Method Delete `
        -Headers $omeHeaders `
        -UseBasicParsing `
        -ErrorAction SilentlyContinue | Out-Null
    Write-Host "[OK] OME session closed" -ForegroundColor Green
} catch {
    Write-Host "[INFO] OME session cleanup skipped (session may have already expired)" -ForegroundColor Gray
}

# ============================================================
# STEP 5 - Export CSV (detailed)
# ============================================================
$report | Export-Csv -Path $outputPath -NoTypeInformation
Write-Host ""
Write-Host "[OK] Detail report: $outputPath" -ForegroundColor Green

# ============================================================
# STEP 6 - Text Summary
# ============================================================
$compliantItems    = $report | Where-Object { $_.HCLCompliant -eq "COMPLIANT" }
$nonCompliantItems = $report | Where-Object { $_.HCLCompliant -eq "NON-COMPLIANT" }
$manualItems       = $report | Where-Object { $_.HCLCompliant -eq "MANUAL-CHECK-REQUIRED" }
$notInOMEItems     = $report | Where-Object { $_.HCLCompliant -eq "NOT-IN-OME" }

$compliantHosts    = $hostSummary | Where-Object { $_.Overall -eq "COMPLIANT" }
$nonCompliantHosts = $hostSummary | Where-Object { $_.Overall -eq "NON-COMPLIANT" }
$fwUnverifiedHosts = $hostSummary | Where-Object { $_.Overall -eq "FW-UNVERIFIED" }
$unknownHosts      = $hostSummary | Where-Object { $_.Overall -notin @("COMPLIANT","NON-COMPLIANT","FW-UNVERIFIED") }

$percIssues       = $report | Where-Object { $_.ComponentType -eq "DRIVER-PERC-PAIR" -and $_.HCLCompliant -eq "NON-COMPLIANT" }
$percUnverified   = $report | Where-Object { $_.ComponentType -eq "DRIVER-PERC-PAIR" -and $_.HCLCompliant -eq "FW-UNVERIFIED" }
$fcIssues         = $report | Where-Object { $_.ComponentType -eq "DRIVER-FC"        -and $_.HCLCompliant -eq "NON-COMPLIANT" }

$summary = @"
============================================================
 BRANCH HOST HCL COMPLIANCE REPORT
 vCenter : $vCenter
 Scope   : Hosts with prefix '$branchPrefix'
 Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm')
============================================================
 SCOPE
   Scan mode                 : $scanMode
   ESXi 8.x hosts processed  : $totalHosts
   ESXi 7.x hosts skipped    : $skippedESXi7
   Matched in OME            : $processedOK
   Firmware data available   : $($omeFirmwareByDevice.Count) of $($fwJobList.Count) hosts (parallel fetch)
   Not in OME                : $notInOME
   ESXi driver query errors  : $queryErrors

 OVERALL HOST STATUS
   COMPLIANT                 : $($compliantHosts.Count)
   NON-COMPLIANT             : $($nonCompliantHosts.Count)
   FW-UNVERIFIED             : $($fwUnverifiedHosts.Count)  (driver OK - firmware not confirmed via OME)
   Unknown / Not in OME      : $($unknownHosts.Count)

 COMPONENT ITEMS
   Compliant items           : $($compliantItems.Count)
   Non-compliant items       : $($nonCompliantItems.Count)
   Manual check needed       : $($manualItems.Count)

============================================================
 HOST SUMMARY TABLE
============================================================
$($hostSummary | Select-Object ShortName, Model, FCStatus, PERCStatus, Overall | Format-Table -AutoSize | Out-String)

============================================================
 NON-COMPLIANT HOSTS - DETAIL
============================================================
$($nonCompliantHosts | Select-Object Hostname, Folder, Model, FCStatus, PERCStatus, Issues | Format-Table -AutoSize | Out-String)

============================================================
 FC HBA NON-COMPLIANT ITEMS
============================================================
$($fcIssues | Select-Object Hostname, ComponentName, CurrentVersion, HCLRequired, Notes | Format-Table -AutoSize | Out-String)

============================================================
 PERC NON-COMPLIANT PAIRS
============================================================
$($percIssues | Select-Object Hostname, ComponentName, CurrentVersion, HCLRequired, Notes | Format-Table -AutoSize | Out-String)

============================================================
 PERC FW-UNVERIFIED - DRIVER OK, FIRMWARE NOT CONFIRMED
 These hosts have valid PERC drivers but OME firmware data
 was unavailable. Manually verify firmware in OME or iDRAC.
============================================================
$($percUnverified | Select-Object Hostname, ComponentName, CurrentVersion, HCLRequired, Notes | Format-Table -AutoSize | Out-String)

============================================================
 HOSTS NOT FOUND IN OME
============================================================
$($notInOMEItems | Select-Object -ExpandProperty Hostname -Unique | Sort-Object | ForEach-Object { "  $_" } | Out-String)
"@

Write-Host $summary -ForegroundColor Cyan
$summary | Out-File -FilePath $summaryPath -Encoding UTF8
Write-Host "[OK] Summary: $summaryPath" -ForegroundColor Green

# ============================================================
# STEP 7 - HTML Report
# ============================================================

function Get-StatusBadge {
    param([string]$Status)
    switch -Wildcard ($Status) {
        "COMPLIANT"              { return '<span style="background:#1e7e34;color:#fff;padding:3px 10px;border-radius:4px;font-size:12px;font-weight:bold;">COMPLIANT</span>' }
        "NON-COMPLIANT"          { return '<span style="background:#bd2130;color:#fff;padding:3px 10px;border-radius:4px;font-size:12px;font-weight:bold;">NON-COMPLIANT</span>' }
        "NOT-IN-OME"             { return '<span style="background:#856404;color:#fff;padding:3px 10px;border-radius:4px;font-size:12px;font-weight:bold;">NOT IN OME</span>' }
        "FW-UNVERIFIED"          { return '<span style="background:#c87900;color:#fff;padding:3px 10px;border-radius:4px;font-size:12px;font-weight:bold;">FW UNVERIFIED</span>' }
        "NO-FC-HBA"              { return '<span style="background:#555;color:#fff;padding:3px 10px;border-radius:4px;font-size:12px;">NO FC HBA</span>' }
        "NO-PERC-DETECTED"       { return '<span style="background:#555;color:#fff;padding:3px 10px;border-radius:4px;font-size:12px;">NO PERC</span>' }
        "MANUAL-CHECK-REQUIRED"  { return '<span style="background:#856404;color:#fff;padding:3px 10px;border-radius:4px;font-size:12px;font-weight:bold;">MANUAL CHECK</span>' }
        default                  { return "<span style=`"background:#6c757d;color:#fff;padding:3px 10px;border-radius:4px;font-size:12px;`">$Status</span>" }
    }
}

$hostRows = foreach ($h in ($hostSummary | Sort-Object Overall, Hostname)) {
    $rowBg = switch ($h.Overall) {
        "COMPLIANT"     { "#f0fff4" }
        "NON-COMPLIANT" { "#fff5f5" }
        default         { "#fffdf0" }
    }
    $issueHtml = if ($h.Issues -ne "None") {
        "<br><small style='color:#721c24;'>$([System.Net.WebUtility]::HtmlEncode($h.Issues))</small>"
    } else { "" }

    "<tr style='background:$rowBg'>
        <td><strong>$([System.Net.WebUtility]::HtmlEncode($h.ShortName))</strong><br><small style='color:#666;'>$([System.Net.WebUtility]::HtmlEncode($h.Hostname))</small></td>
        <td>$([System.Net.WebUtility]::HtmlEncode($h.Folder))</td>
        <td>$([System.Net.WebUtility]::HtmlEncode($h.Model))</td>
        <td>$([System.Net.WebUtility]::HtmlEncode($h.ServiceTag))</td>
        <td>$([System.Net.WebUtility]::HtmlEncode($h.ESXiVersion))</td>
        <td>$(Get-StatusBadge $h.FCStatus)</td>
        <td>$(Get-StatusBadge $h.PERCStatus)</td>
        <td>$(Get-StatusBadge $h.Overall)$issueHtml</td>
    </tr>"
}

$detailRows = foreach ($r in ($report | Where-Object { $_.HCLCompliant -ne "NOT-IN-OME" } | Sort-Object Hostname, ComponentType, ComponentName)) {
    $rowBg = switch -Wildcard ($r.HCLCompliant) {
        "COMPLIANT"   { "#f0fff4" }
        "NON-COMPLIANT" { "#fff5f5" }
        default       { "#fffdf0" }
    }
    "<tr style='background:$rowBg'>
        <td>$([System.Net.WebUtility]::HtmlEncode($r.Hostname.Split('.')[0]))</td>
        <td>$([System.Net.WebUtility]::HtmlEncode($r.ComponentName))</td>
        <td><code>$([System.Net.WebUtility]::HtmlEncode($r.CurrentVersion))</code></td>
        <td><code>$([System.Net.WebUtility]::HtmlEncode($r.HCLRequired))</code></td>
        <td>$(Get-StatusBadge $r.HCLCompliant)</td>
        <td><small>$([System.Net.WebUtility]::HtmlEncode($r.Notes))</small></td>
    </tr>"
}

$totalCount        = $totalHosts
$compliantCount    = $compliantHosts.Count
$nonCompliantCount = $nonCompliantHosts.Count
$fwUnverifiedCount = $fwUnverifiedHosts.Count
$unknownCount      = $unknownHosts.Count
$skippedCount      = $skippedESXi7
$generatedDate     = Get-Date -Format "dddd, MMMM dd yyyy 'at' HH:mm"

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Branch Host HCL Compliance Report</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: Arial, sans-serif; font-size: 13px; color: #212529; background: #f8f9fa; }
  .header { background: #1f3864; color: #fff; padding: 28px 32px; }
  .header h1 { font-size: 24px; font-weight: 700; margin-bottom: 6px; }
  .header p  { font-size: 13px; color: #9dc3e6; }
  .meta { background: #fff; border-bottom: 1px solid #dee2e6; padding: 12px 32px; display: flex; gap: 32px; font-size: 12px; color: #555; }
  .meta span strong { color: #212529; }
  .content { padding: 24px 32px; }
  .scorecard { display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; margin-bottom: 28px; }
  .card { background: #fff; border-radius: 6px; padding: 18px 20px; border-left: 5px solid #dee2e6; box-shadow: 0 1px 3px rgba(0,0,0,.07); }
  .card.total   { border-left-color: #1f3864; }
  .card.ok      { border-left-color: #1e7e34; }
  .card.bad     { border-left-color: #bd2130; }
  .card.warn    { border-left-color: #856404; }
  .card .num  { font-size: 38px; font-weight: 700; line-height: 1; margin-bottom: 6px; }
  .card.total .num { color: #1f3864; }
  .card.ok    .num { color: #1e7e34; }
  .card.bad   .num { color: #bd2130; }
  .card.warn  .num { color: #856404; }
  .card .lbl  { font-size: 12px; color: #666; text-transform: uppercase; letter-spacing: .5px; }
  h2 { font-size: 15px; font-weight: 700; color: #1f3864; margin: 24px 0 10px; padding-bottom: 6px; border-bottom: 2px solid #2e75b6; }
  table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 6px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.07); font-size: 12px; margin-bottom: 8px; }
  thead tr { background: #1f3864; color: #fff; }
  thead th { padding: 9px 10px; text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: .4px; }
  tbody tr:hover { filter: brightness(.97); }
  tbody td { padding: 8px 10px; border-bottom: 1px solid #f0f0f0; vertical-align: top; }
  code { background: #f0f0f0; padding: 1px 5px; border-radius: 3px; font-size: 11px; }
  .footer { text-align: center; padding: 20px; font-size: 11px; color: #999; border-top: 1px solid #dee2e6; margin-top: 24px; }
  .alert-box { background: #fff3cd; border: 1px solid #ffc107; border-radius: 6px; padding: 12px 16px; margin-bottom: 16px; font-size: 12px; }
  .alert-box strong { color: #856404; }
</style>
</head>
<body>

<div class="header">
  <h1>&#x1F4CB; Branch Host HCL Compliance Report</h1>
  <p>VMware ESXi 8.0 U3 &mdash; Fibre Channel HBA + PERC Storage Controller Driver/Firmware Validation</p>
</div>

<div class="meta">
  <span><strong>vCenter:</strong> $vCenter</span>
  <span><strong>Scope:</strong> $(if ($scanMode -eq "TARGETED") { "Targeted: $($targetHosts.Count) hosts" } else { "Full scan - prefix '$branchPrefix'" })</span>
  <span><strong>OME:</strong> $omeServer</span>
  <span><strong>Generated:</strong> $generatedDate</span>
</div>

<div class="content">

  <div class="scorecard">
    <div class="card total"><div class="num">$totalCount</div><div class="lbl">ESXi 8.x Hosts Scanned</div></div>
    <div class="card ok">  <div class="num">$compliantCount</div><div class="lbl">Fully Compliant</div></div>
    <div class="card bad"> <div class="num">$nonCompliantCount</div><div class="lbl">Non-Compliant</div></div>
    <div class="card warn"><div class="num">$fwUnverifiedCount</div><div class="lbl">FW Unverified (driver OK)</div></div>
    <div class="card warn"><div class="num">$skippedCount</div><div class="lbl">ESXi 7.x Skipped</div></div>
  </div>

  <div class="alert-box">
    <strong>&#x26A0; HCL Validation Note:</strong>
    PERC H755 firmware <strong>52.26.x is NOT in the VMware HCL</strong> for any driver version.
    Hosts running driver 7.728.02.00-1vmw must pair with firmware 52.21.0-4606.
    Hosts running driver 7.730.01.00-1OEM must pair with firmware 52.30.0-6115.
    Firmware updated without a matching driver update creates an unvalidated combination.
  </div>

  <h2>&#x1F4CB; Host Summary</h2>
  <table>
    <thead><tr>
      <th>Host</th><th>Folder / Location</th><th>Model</th><th>Service Tag</th>
      <th>ESXi Version</th><th>FC HBA</th><th>PERC</th><th>Overall</th>
    </tr></thead>
    <tbody>$($hostRows -join "`n")</tbody>
  </table>

  <h2>&#x26A0; PERC Firmware Unverified — Driver OK, Confirm Firmware in OME</h2>
  <p style="font-size:12px;color:#856404;margin-bottom:8px;">These hosts have a valid PERC driver version but OME firmware data could not be retrieved. They are <strong>not confirmed non-compliant</strong> — verify PERC firmware in OME or iDRAC to clear this flag.</p>
  <table>
    <thead><tr><th>Host</th><th>Component</th><th>Driver (confirmed)</th><th>Firmware</th><th>Action Required</th></tr></thead>
    <tbody>$(
      ($report | Where-Object { $_.ComponentType -eq "DRIVER-PERC-PAIR" -and $_.HCLCompliant -eq "FW-UNVERIFIED" } | Sort-Object Hostname | ForEach-Object {
        "<tr style='background:#fffdf0'><td>$([System.Net.WebUtility]::HtmlEncode($_.Hostname.Split('.')[0]))</td><td>$([System.Net.WebUtility]::HtmlEncode($_.ComponentName))</td><td><code>$([System.Net.WebUtility]::HtmlEncode(($_.CurrentVersion -split ' \+ ')[0]))</code></td><td><span style='color:#856404;font-weight:bold;'>Unavailable from OME</span></td><td><small>Check PERC firmware in OME Firmware tab or iDRAC - confirm matches HCL pair</small></td></tr>"
      }) -join "`n"
    )</tbody>
  </table>

  <h2>&#x1F50D; Component Detail</h2>
  <table>
    <thead><tr>
      <th>Host</th><th>Component</th><th>Current Version</th>
      <th>HCL Required</th><th>Status</th><th>Notes</th>
    </tr></thead>
    <tbody>$($detailRows -join "`n")</tbody>
  </table>

</div>

<div class="footer">
  Branch HCL Compliance Report &mdash; Infrastructure &amp; Virtualization Team &mdash; $generatedDate &mdash; CONFIDENTIAL
</div>

</body>
</html>
"@

$html | Out-File -FilePath $htmlPath -Encoding UTF8
Write-Host "[OK] HTML report: $htmlPath" -ForegroundColor Green

# ============================================================
# FINAL CONSOLE SUMMARY
# ============================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " SCAN COMPLETE" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  ESXi 8.x hosts scanned  : $totalHosts"           -ForegroundColor White
Write-Host "  ESXi 7.x skipped        : $skippedCount"            -ForegroundColor DarkGray
Write-Host "  COMPLIANT               : $compliantCount"           -ForegroundColor Green
Write-Host "  NON-COMPLIANT           : $nonCompliantCount"        -ForegroundColor Red
Write-Host "  FW-UNVERIFIED           : $fwUnverifiedCount"        -ForegroundColor Yellow
Write-Host "    (driver valid, confirm firmware in OME/iDRAC)" -ForegroundColor DarkYellow
Write-Host "  Unknown / Not in OME    : $unknownCount"             -ForegroundColor Yellow
Write-Host ""
Write-Host "  Detail CSV  : $outputPath"   -ForegroundColor Gray
Write-Host "  Summary TXT : $summaryPath"  -ForegroundColor Gray
Write-Host "  HTML Report : $htmlPath"     -ForegroundColor Cyan
Write-Host ""
