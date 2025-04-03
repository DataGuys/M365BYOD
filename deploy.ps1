<#
.SYNOPSIS
Creates:
- A PoC security group.
- Two MAM (App Protection) policies for iOS and Android, assigned to that group.
- A Conditional Access policy targeting ONLY Office 365 ("CommonOffice365"),
  requiring "Compliant device" OR "AppProtection", while excluding:
  - Up to two break-glass accounts (prompted)
  - Any service accounts (prompted).

.DESCRIPTION
1) Prompts for up to two break-glass accounts' UPNs.  
2) Prompts for any service account UPNs.  
3) Connects to Microsoft Graph with the needed scopes.
4) Uses Microsoft Graph SDK to create & configure the resources in Intune and Entra ID.

.NOTES
- Requires the following Microsoft Graph PowerShell modules:
  - Microsoft.Graph.Authentication
  - Microsoft.Graph.Groups
  - Microsoft.Graph.Users
  - Microsoft.Graph.Identity.SignIns
  - Microsoft.Graph.DeviceManagement
#>

### --- 0. ENSURE REQUIRED MODULES ARE INSTALLED ---
$requiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Groups",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Identity.SignIns",
    "Microsoft.Graph.DeviceManagement"
)

foreach ($module in $requiredModules) {
    if (-not (Get-Module -Name $module -ListAvailable)) {
        Write-Host "Required module $module is not installed. Installing..." -ForegroundColor Yellow
        Install-Module -Name $module -Scope CurrentUser -Force
    }
}

# Import the modules
Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Groups
Import-Module Microsoft.Graph.Users
Import-Module Microsoft.Graph.Identity.SignIns
Import-Module Microsoft.Graph.DeviceManagement

### --- 1. PROMPT FOR BREAK-GLASS & SERVICE ACCOUNTS ---

# Prompt up to 2 break-glass accounts (UPNs).
# If user hits Enter with no input, we skip that entry.
Write-Host "Designed to run in the Azure Cloud Shell" -ForegroundColor Yellow
Write-Host "Enter the UPNs of up to two break-glass accounts (press Enter to skip if none)." -ForegroundColor Green
$breakGlassUPN1 = Read-Host "Break-glass account #1 (UPN)"
$breakGlassUPN2 = Read-Host "Break-glass account #2 (UPN)"

# Prompt for service accounts (multiple). We'll store them in an array.
Write-Host "Enter the UPNs of any service accounts to exclude (one per line)."
Write-Host "Press Enter on an empty line to finish."
$serviceAccountUPNs = @()
while ($true) {
    $sa = Read-Host "Service account UPN (or Enter to finish)"
    if ([string]::IsNullOrWhiteSpace($sa)) { break }
    $serviceAccountUPNs += $sa
}

Write-Host "Break-glass accounts provided:"
if ($breakGlassUPN1) { Write-Host "   $breakGlassUPN1" }
if ($breakGlassUPN2) { Write-Host "   $breakGlassUPN2" }
if ($serviceAccountUPNs.Count -gt 0) {
    Write-Host "Service accounts provided:"
    $serviceAccountUPNs | ForEach-Object { Write-Host "   $_" }
} else {
    Write-Host "No service accounts provided."
}
Write-Host ""

### --- 2. CONNECT TO MS GRAPH ---
$requiredScopes = @(
    "Directory.ReadWrite.All",
    "DeviceManagementApps.ReadWrite.All",
    "Policy.ReadWrite.ConditionalAccess"
)

Write-Host "Connecting to Microsoft Graph with required scopes..."
Connect-MgGraph -Scopes $requiredScopes
Write-Host "Connected successfully."

### --- 3. RESOLVE BREAK-GLASS & SERVICE ACCOUNTS TO OBJECT IDs ---
Write-Host "Resolving break-glass and service account UPNs to user object IDs..."

# We'll collect all user UPNs that we need to exclude
$excludeUserUPNs = @()
if ($breakGlassUPN1) { $excludeUserUPNs += $breakGlassUPN1 }
if ($breakGlassUPN2) { $excludeUserUPNs += $breakGlassUPN2 }
if ($serviceAccountUPNs.Count -gt 0) {
    $excludeUserUPNs += $serviceAccountUPNs
}

$excludeUserObjectIds = @()

foreach ($upn in $excludeUserUPNs) {
    try {
        # Get user by UPN using Graph SDK
        $user = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction Stop
        
        if ($user) {
            Write-Host "  Found $upn => Object ID: $($user.Id)"
            $excludeUserObjectIds += $user.Id
        }
    } catch {
        Write-Warning "  Could not find user with UPN=$upn. Skipping."
    }
}

Write-Host ""

### --- 4. CREATE A POC SECURITY GROUP ---
Write-Host "`n--- Creating PoC Security Group ---"
$groupParams = @{
    DisplayName = "PoC Testing Group"
    Description = "Security group for MAM+CA PoC"
    MailEnabled = $false
    MailNickname = "pocTestingGroup"
    SecurityEnabled = $true
}

$pocGroup = New-MgGroup @groupParams
Write-Host "Created group with Id: $($pocGroup.Id)"

### --- 5. CREATE iOS MAM POLICY ---
Write-Host "`n--- Creating iOS MAM Policy ---"

# Since direct cmdlets for app protection policies might not be available in the Graph SDK,
# we'll use Invoke-MgGraphRequest for these specific operations
$iosBody = @{
    displayName = "iOS App Protection Policy"
    description = "Block cut/copy/paste, Save As, and printing for iOS."
    allowedClipboardSharingLevel = "managedApps"
    allowedInboundDataTransferSources = "managedApps"
    allowedOutboundDataTransferDestinations = "managedApps"
    saveAsBlocked = $true
    printBlocked = $true
    faceIdBlocked = $false
}

$iosPolicy = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/deviceAppManagement/iosManagedAppProtections" -Body ($iosBody | ConvertTo-Json -Depth 10)
Write-Host "Created iOS MAM policy with Id: $($iosPolicy.id)"

### --- 6. CREATE ANDROID MAM POLICY ---
Write-Host "`n--- Creating Android MAM Policy ---"
$androidBody = @{
    displayName = "Android App Protection Policy"
    description = "Block cut/copy/paste, Save As, and printing for Android."
    allowedClipboardSharingLevel = "managedApps"
    allowedInboundDataTransferSources = "managedApps"
    allowedOutboundDataTransferDestinations = "managedApps"
    saveAsBlocked = $true
    printBlocked = $true
}

$androidPolicy = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/deviceAppManagement/androidManagedAppProtections" -Body ($androidBody | ConvertTo-Json -Depth 10)
Write-Host "Created Android MAM policy with Id: $($androidPolicy.id)"

### --- 7. ASSIGN MAM POLICIES TO THE POC GROUP ---
Write-Host "`n--- Assigning iOS MAM Policy to PoC Group ---"
$iosAssignBody = @{
    assignments = @(
        @{
            "@odata.type" = "#microsoft.graph.targetedManagedAppPolicyAssignment"
            target = @{
                "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                groupId = $pocGroup.Id
            }
        }
    )
}

Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/deviceAppManagement/iosManagedAppProtections/$($iosPolicy.id)/assign" -Body ($iosAssignBody | ConvertTo-Json -Depth 10)
Write-Host "Assigned iOS MAM policy to PoC group."

Write-Host "`n--- Assigning Android MAM Policy to PoC Group ---"
$androidAssignBody = @{
    assignments = @(
        @{
            "@odata.type" = "#microsoft.graph.targetedManagedAppPolicyAssignment"
            target = @{
                "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                groupId = $pocGroup.Id
            }
        }
    )
}

Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/deviceAppManagement/androidManagedAppProtections/$($androidPolicy.id)/assign" -Body ($androidAssignBody | ConvertTo-Json -Depth 10)
Write-Host "Assigned Android MAM policy to PoC group."

### --- 8. CREATE CONDITIONAL ACCESS POLICY ---
Write-Host "`n--- Creating Conditional Access Policy ---"

# Create parameters for New-MgIdentityConditionalAccessPolicy
$caParams = @{
    DisplayName = "Require Compliant or Protected Apps for O365 (PoC)"
    State = "enabled"  # can be "enabled", "disabled", or "enabledForReportingButNotEnforced"
    Conditions = @{
        Users = @{
            IncludeGroups = @($pocGroup.Id)
            ExcludeUsers = $excludeUserObjectIds
        }
        Applications = @{
            IncludeApplications = @("Office365")
        }
    }
    GrantControls = @{
        Operator = "OR"
        BuiltInControls = @("compliantDevice", "approvedApplication")
    }
}

$caPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $caParams
Write-Host "Created CA policy with Id: $($caPolicy.Id)"

Write-Host "`n===== ALL DONE! ====="
Write-Host "1) Created PoC group with ID: $($pocGroup.Id)"
Write-Host "2) Created & assigned iOS/Android MAM policies."
Write-Host "3) Created CA policy for O365 requiring Compliant or MAM devices."
Write-Host "   Excluded break-glass / service accounts (where found)."
Write-Host "Check Intune and Entra ID portals to confirm."
