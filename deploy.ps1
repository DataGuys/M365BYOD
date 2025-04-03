<#
.SYNOPSIS
Demonstration that uses Connect-MgGraph for authentication, then raw REST calls to:
1) Create a PoC security group
2) Create & assign iOS/Android MAM policies
3) Create a Conditional Access policy

.DESCRIPTION
- This script uses minimal reliance on Graph modules:
  - Only Connect-MgGraph (for sign-in) + Get-MgContext to retrieve token.
  - REST calls for the actual requests (Invoke-RestMethod) to create resources.

.NOTES
- Ensure you have at least the Microsoft.Graph.Authentication module installed (so Connect-MgGraph works).
- You need tenant admin or delegated permissions for:
   Directory.ReadWrite.All,
   DeviceManagementApps.ReadWrite.All,
   Policy.ReadWrite.ConditionalAccess.
#>

### 0. Define the scopes (permissions) you need
#    - Directory.ReadWrite.All: create groups
#    - DeviceManagementApps.ReadWrite.All: create/assign MAM policies
#    - Policy.ReadWrite.ConditionalAccess: create CA policies
$requiredScopes = @(
    "Directory.ReadWrite.All",
    "DeviceManagementApps.ReadWrite.All",
    "Policy.ReadWrite.ConditionalAccess"
)

### 1. Connect to Microsoft Graph (interactive or device code, depending on your environment)
Write-Host "Connecting to Microsoft Graph with the required scopes..."
Connect-MgGraph -Scopes $requiredScopes
Write-Host "Connected."

### 2. Grab the token from the current Graph context
$mgContext = Get-MgContext
if (-not $mgContext.AccessToken) {
    Write-Error "No access token found. Ensure you're signed in and have consented to the requested scopes."
    return
}
$token = $mgContext.AccessToken

### 3. Define a helper function to call Graph with raw REST
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

### 4. Variables for Graph API endpoints
$graphApiUrl = "https://graph.microsoft.com/v1.0"

### 5. Create a PoC Security Group
Write-Host "`n--- Creating PoC Security Group ---"
$pocGroupBody = @{
    displayName     = "PoC Testing Group"
    description     = "Security group for MAM+CA PoC"
    mailEnabled     = $false
    mailNickname    = "pocTestingGroup"
    securityEnabled = $true
}
$pocGroup = Invoke-GraphApi -Method POST -Uri "$($graphApiUrl)/groups" -Body $pocGroupBody
Write-Host "Created PoC group with Id: $($pocGroup.id)"

### 6. Create iOS MAM Policy
Write-Host "`n--- Creating iOS MAM Policy ---"
$iosPolicyBody = @{
    displayName       = "iOS App Protection Policy"
    description       = "Block cut/copy/paste, Save As, and printing for iOS."
    allowedClipboardSharingLevel = "managedApps"
    allowedInboundDataTransferSources = "managedApps"
    allowedOutboundDataTransferDestinations = "managedApps"
    saveAsBlocked     = $true
    printBlocked      = $true
    faceIdBlocked     = $false
}
$iosPolicy = Invoke-GraphApi -Method POST -Uri "$graphApiUrl/deviceAppManagement/iosManagedAppProtections" -Body $iosPolicyBody
Write-Host "Created iOS MAM policy with Id: $($iosPolicy.id)"

### 7. Create Android MAM Policy
Write-Host "`n--- Creating Android MAM Policy ---"
$androidPolicyBody = @{
    displayName       = "Android App Protection Policy"
    description       = "Block cut/copy/paste, Save As, and printing for Android."
    allowedClipboardSharingLevel = "managedApps"
    allowedInboundDataTransferSources = "managedApps"
    allowedOutboundDataTransferDestinations = "managedApps"
    saveAsBlocked     = $true
    printBlocked      = $true
}
$androidPolicy = Invoke-GraphApi -Method POST -Uri "$graphApiUrl/deviceAppManagement/androidManagedAppProtections" -Body $androidPolicyBody
Write-Host "Created Android MAM policy with Id: $($androidPolicy.id)"

### 8. Assign MAM Policies to the PoC Group
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
Invoke-GraphApi -Method POST -Uri "$($graphApiUrl)/deviceAppManagement/iosManagedAppProtections/$($iosPolicy.id)/assign" -Body $iosAssignBody
Write-Host "Assigned iOS policy to PoC group."

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
Invoke-GraphApi -Method POST -Uri "$($graphApiUrl)/deviceAppManagement/androidManagedAppProtections/$($androidPolicy.id)/assign" -Body $androidAssignBody
Write-Host "Assigned Android policy to PoC group."

### 9. Create a Conditional Access Policy
Write-Host "`n--- Creating Conditional Access Policy ---"
# This CA policy enforces that users in the PoC group, when accessing O365, must
#   have a compliant device OR be using an app with MAM (AppProtection).
# "CommonOffice365" is a known service principal for Office 365. 
# The policy is set to "enabled". 

$caPolicyBody = @{
    displayName = "Require Compliant or Protected Apps for O365 (PoC)"
    state       = "enabled"  # or "disabled" / "enabledForReportingButNotEnforced"
    conditions  = @{
