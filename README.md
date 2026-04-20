# HCLCheck — VMware HCL Compliance Checker for Dell ESXi Environments

HCLCheck is a PowerShell script that validates ESXi driver versions and firmware as **validated pairs** against the VMware Hardware Compatibility Guide. It queries both VMware ESXi (via PowerCLI/esxcli) and Dell OpenManage Enterprise (via REST API) simultaneously, then cross-validates results against a local HCL reference table.

## The Problem It Solves

Neither Dell OME firmware baselines nor VMware vSphere Lifecycle Manager (without OMEVV HSM fully configured per-cluster) perform cross-validation of driver and firmware versions as a **pair** against the VMware HCL:

- **Dell OME** targets specific firmware versions against Dell's baseline but has no knowledge of whether that firmware is valid when paired with the current driver version
- **vLCM + OMEVV HSM** can surface HCL violations but requires a baseline configured per cluster and does not cover standalone hosts

The result: patching cycles that appear compliant from both tools' perspectives can leave hosts in unvalidated driver/firmware states. HCLCheck finds them.

## What It Checks

| Component | Method | Validation |
|---|---|---|
| Emulex lpfc FC HBA driver | esxcli via PowerCLI | HCL validates only VMware inbox drivers (14.4.0.x-35vmw) for LPe35002-M2-D on ESXi 8.0 U3 |
| PERC H755 driver + firmware | esxcli + OME REST API | Validates driver/firmware as a pair — 52.26.x firmware is NOT in the HCL for any driver |
| PERC H965 driver + firmware | esxcli + OME REST API | Validates driver/firmware as a pair against HCL-listed combinations |

## Prerequisites

- **PowerShell 5.1** or later (Windows)
- **VMware PowerCLI** — `Install-Module VMware.PowerCLI`
- **Dell OpenManage Enterprise** REST API access (X-Auth-Token authentication)
- vCenter credentials with read access to host inventory
- OME credentials with device inventory read access

## Quick Start

```powershell
# 1. Clone or download the script
# 2. Edit the configuration block at the top of the script:

$omeServer    = "your-ome-server"        # OME hostname or IP
$vCenter      = "your-vcenter.domain"    # vCenter FQDN
$branchPrefix = "esxi-"                  # Host name prefix to filter

# 3. Run the script
.\HCLCheck_Branch.ps1

# Output files are written to C:\HCLReports\
# - Branch_HCL_YYYYMMDD-HHMM.csv       (detail report)
# - Branch_HCL_SUMMARY_YYYYMMDD-HHMM.txt (text summary)
# - Branch_HCL_REPORT_YYYYMMDD-HHMM.html (HTML report with scorecard)
```

## Targeted Rescan Mode

To re-run against specific hosts after remediation without scanning the full environment:

```powershell
$targetHosts = @(
    "esxi-host01"
    "esxi-host02"
)
```

Leave `$targetHosts` empty for a full scan of all hosts matching `$branchPrefix`.

## HCL Reference Table

The `$hclReference` hashtable at the top of the script defines the validated driver/firmware pairs. The default table covers:

- **Emulex LPe35002-M2-D** (Subsystem ID f410) FC HBA on ESXi 8.0 U3
- **PERC H755** — lsi_mr3 driver validated pairs
- **PERC H965** — bcm_mpi3 driver validated pairs

**If your environment includes different hardware, extend this table.** Look up your adapter or controller on the [VMware Hardware Compatibility Guide](https://www.vmware.com/resources/compatibility/search.php), find the validated driver and firmware version pair for your ESXi release, and add a matching entry.

Pull requests with additional validated pairs are welcome.

## Compliance Status Values

| Status | Meaning |
|---|---|
| `COMPLIANT` | Driver and firmware match a validated HCL pair |
| `NON-COMPLIANT` | Driver or firmware (or both) do not match any validated HCL pair |
| `FW-UNVERIFIED` | Driver is valid but firmware could not be retrieved from OME — verify manually in iDRAC |
| `NOT-CHECKED` | Host skipped (ESXi 7.x or no matching component found) |

## Output Example

The HTML report includes:
- Scorecard with compliant / non-compliant / FW-unverified counts
- Per-host summary table with FC HBA and PERC status
- Component detail table with current version, HCL-required version, and remediation notes

## Related Blog Post

For background on the failure patterns this tool was built to detect, the technical decisions behind the implementation, and real-world findings from production runs:

**[When Your Patching Tool Doesn't Know the HCL: Building HCLCheck for VMware and Dell](https://burdweiser.com/blog/2026-04-16-when-your-patching-tool-doesnt-know-the-hcl)**

## License

MIT License. Use freely, extend for your hardware, contribute back.
