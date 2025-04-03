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
3) Connects to Microsoft Graph with the needed scopes:  
   - Directory.ReadWrite.All (create group, read users)  
   - DeviceManagementApps.ReadWrite.All (create/assign MAM policies)  
   - Policy.ReadWrite.ConditionalAccess (create CA policy)  
4) Makes raw REST calls to create & configure the resources in Intune and Entra ID.

.NOTES
- Only depends on Connect-MgGraph (Microsoft.Graph.Authentication), not the entire Graph SDK.
- Make sure your signed-in account has appropriate privileges.
#>

### --- 0. PROMPT FOR BREAK-GLASS & SERVICE ACCOUNTS ---

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

### --- 1. CONNECT TO MS GRAPH ---
$requiredScopes = @(
    "Directory.ReadWrite.All",
    "DeviceManagementApps.ReadWrite.All",
    "Policy.ReadWrite.ConditionalAccess"
)

Write-Host "Connecting to Microsoft Graph with required scopes..."
Connect-MgGraph -Scopes $requiredScopes
Write-Host "Connected successfully."

# Grab the token from the current session
$mgContext = Get-MgContext
if (-not $mgContext.Scopes) {
    Write-Error "No access token found. Verify you've signed in and have the proper permissions."
    return
}
$token = $mgContext.AccessToken

### --- 2. HELPER FUNCTION FOR RAW REST CALLS ---
function Invoke-GraphApi {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("GET","POST","PUT","PATCH","DELETE")]
        [string]$Method,

        [Parameter(Mandatory=$true)]
        [string]$Uri,

        [Parameter(Mandatory=$false)]
        [hashtable]$Body
    )

    $headers = @{
        "Authorization" = "Bearer $token"
        "Content-Type"  = "application/json"
    }

    if ($Body) {
        $jsonBody = $Body | ConvertTo-Json -Depth 10
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $jsonBody
    }
    else {
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
    }
}

$graphApiUrl = "https://graph.microsoft.com/v1.0"

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
    # Filter for user by UPN
    $encodedUpn = [System.Web.HttpUtility]::UrlEncode($upn)
    $searchUrl  = "$graphApiUrl/users?\$filter=userPrincipalName eq '$encodedUpn'"
    $userResult = Invoke-GraphApi -Method GET -Uri $searchUrl

    if ($userResult.value -and $userResult.value.Count -eq 1) {
        $objId = $userResult.value[0].id
        Write-Host "  Found $upn => Object ID: $objId"
        $excludeUserObjectIds += $objId
    } else {
        Write-Warning "  Could not find user with UPN=$upn. Skipping."
    }
}

Write-Host ""

### --- 4. CREATE A POC SECURITY GROUP ---
Write-Host "`n--- Creating PoC Security Group ---"
$groupBody = @{
    displayName     = "PoC Testing Group"
    description     = "Security group for MAM+CA PoC"
    mailEnabled     = $false
    mailNickname    = "pocTestingGroup"
    securityEnabled = $true
}
$pocGroup = Invoke-GraphApi -Method POST -Uri "$graphApiUrl/groups" -Body $groupBody
Write-Host "Created group with Id: $($pocGroup.id)"

### --- 5. CREATE iOS MAM POLICY ---
Write-Host "`n--- Creating iOS MAM Policy ---"
$iosBody = @{
    displayName                          = "iOS App Protection Policy"
    description                          = "Block cut/copy/paste, Save As, and printing for iOS."
    allowedClipboardSharingLevel         = "managedApps"
    allowedInboundDataTransferSources    = "managedApps"
    allowedOutboundDataTransferDestinations = "managedApps"
    saveAsBlocked                        = $true
    printBlocked                         = $true
    faceIdBlocked                        = $false
}
$iosPolicy = Invoke-GraphApi -Method POST -Uri "$graphApiUrl/deviceAppManagement/iosManagedAppProtections" -Body $iosBody
Write-Host "Created iOS MAM policy with Id: $($iosPolicy.id)"

### --- 6. CREATE ANDROID MAM POLICY ---
Write-Host "`n--- Creating Android MAM Policy ---"
$androidBody = @{
    displayName                          = "Android App Protection Policy"
    description                          = "Block cut/copy/paste, Save As, and printing for Android."
    allowedClipboardSharingLevel         = "managedApps"
    allowedInboundDataTransferSources    = "managedApps"
    allowedOutboundDataTransferDestinations = "managedApps"
    saveAsBlocked                        = $true
    printBlocked                         = $true
}
$androidPolicy = Invoke-GraphApi -Method POST -Uri "$graphApiUrl/deviceAppManagement/androidManagedAppProtections" -Body $androidBody
Write-Host "Created Android MAM policy with Id: $($androidPolicy.id)"

### --- 7. ASSIGN MAM POLICIES TO THE POC GROUP ---
Write-Host "`n--- Assigning iOS MAM Policy to PoC Group ---"
$iosAssignBody = @{
    assignments = @(
        @{
            "@odata.type" = "#microsoft.graph.targetedManagedAppPolicyAssignment"
            target        = @{
                "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                groupId       = $pocGroup.id
            }
        }
    )
}
Invoke-GraphApi -Method POST -Uri "$graphApiUrl/deviceAppManagement/iosManagedAppProtections/$($iosPolicy.id)/assign" -Body $iosAssignBody
Write-Host "Assigned iOS MAM policy to PoC group."

Write-Host "`n--- Assigning Android MAM Policy to PoC Group ---"
$androidAssignBody = @{
    assignments = @(
        @{
            "@odata.type" = "#microsoft.graph.targetedManagedAppPolicyAssignment"
            target        = @{
                "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                groupId       = $pocGroup.id
            }
        }
    )
}
Invoke-GraphApi -Method POST -Uri "$graphApiUrl/deviceAppManagement/androidManagedAppProtections/$($androidPolicy.id)/assign" -Body $androidAssignBody
Write-Host "Assigned Android MAM policy to PoC group."

### --- 8. CREATE CONDITIONAL ACCESS POLICY ---
Write-Host "`n--- Creating Conditional Access Policy ---"
# This policy will:
# - Target the PoC group for Office 365 (CommonOffice365)
# - Exclude the break-glass & service accounts we found
# - Enforce Compliant device OR AppProtection
# - State is "enabled"

# Build the JSON structure for excludes.
# We'll exclude them by user IDs in "excludeUsers".
# If we had groups, we'd do "excludeGroups".
$caPolicyBody = @{
    displayName = "Require Compliant or Protected Apps for O365 (PoC)"
    state       = "enabled"  # can be "enabled", "disabled", or "enabledForReportingButNotEnforced"
    conditions  = @{
        users = @{
            includeGroups = @($pocGroup.id)
            # If we found user object IDs to exclude, place them here:
            excludeUsers  = $excludeUserObjectIds
        }
        applications = @{
            includeApplications = @("CommonOffice365")
        }
    }
    grantControls = @{
        operator        = "OR"
        builtInControls = @("CompliantDevice", "AppProtection")
    }
}

$caPolicy = Invoke-GraphApi -Method POST -Uri "$graphApiUrl/identity/conditionalAccess/policies" -Body $caPolicyBody
Write-Host "Created CA policy with Id: $($caPolicy.id)"

Write-Host "`n===== ALL DONE! ====="
Write-Host "1) Created PoC group with ID: $($pocGroup.id)"
Write-Host "2) Created & assigned iOS/Android MAM policies."
Write-Host "3) Created CA policy for O365 requiring Compliant or MAM devices."
Write-Host "   Excluded break-glass / service accounts (where found)."
Write-Host "Check Intune and Entra ID portals to confirm."
