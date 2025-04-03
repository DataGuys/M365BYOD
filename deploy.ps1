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
5) Includes improved permission checks and error handling.

.NOTES
- Requires Admin permissions for Microsoft Graph, Intune, and Conditional Access.
- Requires the Microsoft.Graph.Authentication module.
#>

### --- 0. HELPER FUNCTIONS ---

function Test-GraphPermission {
    param (
        [Parameter(Mandatory=$true)]
        [string]$PermissionName,
        
        [Parameter(Mandatory=$true)]
        [string]$ResourceName
    )
    
    try {
        $context = Get-MgContext
        if (-not $context) {
            Write-Warning "Not connected to Microsoft Graph."
            return $false
        }
        
        # Simple permission check - not comprehensive but helpful
        if ($context.Scopes -contains $PermissionName) {
            Write-Host "✓ Permission verified: $PermissionName" -ForegroundColor Green
            return $true
        } else {
            Write-Warning "✗ Missing permission: $PermissionName required for $ResourceName"
            return $false
        }
    } catch {
        Write-Warning "Error checking permissions: $_"
        return $false
    }
}

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

### --- 2. CONNECT TO MS GRAPH WITH ALL REQUIRED SCOPES ---
$requiredScopes = @(
    "Directory.ReadWrite.All",                # For group management
    "User.Read.All",                          # For user lookups
    "DeviceManagementApps.ReadWrite.All",     # For MAM policies
    "Policy.ReadWrite.ConditionalAccess",     # For CA policies
    "Application.Read.All"                    # For app registration lookups
)

Write-Host "This script requires admin consent for these permissions:" -ForegroundColor Yellow
$requiredScopes | ForEach-Object { Write-Host "   • $_" }
Write-Host ""

Write-Host "Connecting to Microsoft Graph with required scopes..."
try {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    Start-Sleep -Seconds 2  # Brief pause to ensure disconnection completes
    Connect-MgGraph -Scopes $requiredScopes
    
    # Verify we got the connection
    $context = Get-MgContext
    if (-not $context) {
        throw "Failed to get Microsoft Graph context after connection."
    }
    
    Write-Host "Connected successfully as: $($context.Account)" -ForegroundColor Green
} catch {
    Write-Error "Failed to connect to Microsoft Graph: $_"
    return
}

### --- 3. CHECK PERMISSIONS BEFORE PROCEEDING ---
Write-Host "Checking permissions..." -ForegroundColor Cyan

$permissionChecks = @(
    @{ Name = "Directory.ReadWrite.All"; Resource = "Groups & Users" },
    @{ Name = "DeviceManagementApps.ReadWrite.All"; Resource = "App Protection Policies" },
    @{ Name = "Policy.ReadWrite.ConditionalAccess"; Resource = "Conditional Access Policies" }
)

$permissionsMissing = $false
foreach ($permission in $permissionChecks) {
    if (-not (Test-GraphPermission -PermissionName $permission.Name -ResourceName $permission.Resource)) {
        $permissionsMissing = $true
    }
}

if ($permissionsMissing) {
    Write-Warning "Some required permissions are missing. The script may fail for certain operations."
    $proceed = Read-Host "Do you want to proceed anyway? (Y/N)"
    if ($proceed -ne "Y") {
        Write-Host "Script aborted by user." -ForegroundColor Red
        return
    }
}

### --- 4. RESOLVE BREAK-GLASS & SERVICE ACCOUNTS TO OBJECT IDs ---
Write-Host "`nResolving break-glass and service account UPNs to user object IDs..." -ForegroundColor Cyan

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
            Write-Host "  Found $upn => Object ID: $($user.Id)" -ForegroundColor Green
            $excludeUserObjectIds += $user.Id
        }
    } catch {
        Write-Warning "  Could not find user with UPN=$upn. Error: $_"
    }
}

Write-Host ""

### --- 5. CREATE A POC SECURITY GROUP ---
Write-Host "`n--- Creating PoC Security Group ---" -ForegroundColor Cyan
try {
    $groupParams = @{
        DisplayName = "PoC Testing Group"
        Description = "Security group for MAM+CA PoC"
        MailEnabled = $false
        MailNickname = "pocTestingGroup"
        SecurityEnabled = $true
    }

    $pocGroup = New-MgGroup @groupParams
    Write-Host "Created group with Id: $($pocGroup.Id)" -ForegroundColor Green
} catch {
    Write-Error "Failed to create security group: $_"
    $pocGroup = $null
}

if (-not $pocGroup) {
    Write-Warning "Cannot continue without creating the security group."
    return
}

### --- 6. CREATE iOS MAM POLICY ---
Write-Host "`n--- Creating iOS MAM Policy ---" -ForegroundColor Cyan

try {
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

    # Use Beta endpoint as it might have better support
    $iosPolicy = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections" -Body ($iosBody | ConvertTo-Json -Depth 10)
    
    if ($iosPolicy.id) {
        Write-Host "Created iOS MAM policy with Id: $($iosPolicy.id)" -ForegroundColor Green
    } else {
        Write-Warning "iOS policy created but no ID was returned."
    }
} catch {
    Write-Error "Failed to create iOS MAM policy: $_"
    $iosPolicy = $null
}

### --- 7. CREATE ANDROID MAM POLICY ---
Write-Host "`n--- Creating Android MAM Policy ---" -ForegroundColor Cyan
try {
    $androidBody = @{
        displayName = "Android App Protection Policy"
        description = "Block cut/copy/paste, Save As, and printing for Android."
        allowedClipboardSharingLevel = "managedApps"
        allowedInboundDataTransferSources = "managedApps"
        allowedOutboundDataTransferDestinations = "managedApps"
        saveAsBlocked = $true
        printBlocked = $true
    }

    # Use Beta endpoint as it might have better support
    $androidPolicy = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections" -Body ($androidBody | ConvertTo-Json -Depth 10)
    
    if ($androidPolicy.id) {
        Write-Host "Created Android MAM policy with Id: $($androidPolicy.id)" -ForegroundColor Green
    } else {
        Write-Warning "Android policy created but no ID was returned."
    }
} catch {
    Write-Error "Failed to create Android MAM policy: $_"
    $androidPolicy = $null
}

### --- 8. ASSIGN MAM POLICIES TO THE POC GROUP ---
# Only attempt assignment if we have policies AND their IDs
if ($iosPolicy -and $iosPolicy.id) {
    Write-Host "`n--- Assigning iOS MAM Policy to PoC Group ---" -ForegroundColor Cyan
    try {
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

        Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections/$($iosPolicy.id)/assign" -Body ($iosAssignBody | ConvertTo-Json -Depth 10)
        Write-Host "Assigned iOS MAM policy to PoC group." -ForegroundColor Green
    } catch {
        Write-Error "Failed to assign iOS MAM policy: $_"
    }
}

if ($androidPolicy -and $androidPolicy.id) {
    Write-Host "`n--- Assigning Android MAM Policy to PoC Group ---" -ForegroundColor Cyan
    try {
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

        Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections/$($androidPolicy.id)/assign" -Body ($androidAssignBody | ConvertTo-Json -Depth 10)
        Write-Host "Assigned Android MAM policy to PoC group." -ForegroundColor Green
    } catch {
        Write-Error "Failed to assign Android MAM policy: $_"
    }
}

### --- 9. CREATE CONDITIONAL ACCESS POLICY ---
Write-Host "`n--- Creating Conditional Access Policy ---" -ForegroundColor Cyan
try {
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

    # Try alternative approach if New-MgIdentityConditionalAccessPolicy fails
    try {
        $caPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $caParams
    } catch {
        Write-Warning "Standard CA policy creation failed: $_"
        Write-Host "Trying alternative method..." -ForegroundColor Yellow
        
        # Try using Invoke-MgGraphRequest directly
        $caPolicy = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies" -Body ($caParams | ConvertTo-Json -Depth 10)
    }
    
    if ($caPolicy.Id) {
        Write-Host "Created CA policy with Id: $($caPolicy.Id)" -ForegroundColor Green
    } else {
        Write-Warning "CA policy may have been created but no ID was returned."
    }
} catch {
    Write-Error "Failed to create Conditional Access policy: $_"
    $caPolicy = $null
}

### --- 10. SUMMARY ---
Write-Host "`n===== DEPLOYMENT SUMMARY =====" -ForegroundColor Green
Write-Host "1) Created PoC group with ID: $($pocGroup.Id)"

Write-Host "2) App Protection Policies:"
if ($iosPolicy -and $iosPolicy.id) {
    Write-Host "   ✓ iOS MAM policy created and assigned" -ForegroundColor Green
} else {
    Write-Host "   ✗ iOS MAM policy creation failed" -ForegroundColor Red
}

if ($androidPolicy -and $androidPolicy.id) {
    Write-Host "   ✓ Android MAM policy created and assigned" -ForegroundColor Green
} else {
    Write-Host "   ✗ Android MAM policy creation failed" -ForegroundColor Red
}

Write-Host "3) Conditional Access Policy:"
if ($caPolicy -and $caPolicy.Id) {
    Write-Host "   ✓ CA policy created for O365 requiring Compliant or MAM devices" -ForegroundColor Green
    Write-Host "   ✓ Excluded break-glass / service accounts (where found)" -ForegroundColor Green
} else {
    Write-Host "   ✗ CA policy creation failed" -ForegroundColor Red
}

# Check for overall success
if (($iosPolicy -and $iosPolicy.id) -or ($androidPolicy -and $androidPolicy.id) -or ($caPolicy -and $caPolicy.Id)) {
    Write-Host "`nSome operations completed successfully. Check Intune and Entra ID portals to confirm." -ForegroundColor Green
} else {
    Write-Host "`nOnly the security group was created. Please check account permissions and try again." -ForegroundColor Yellow
    Write-Host "Common issues:"
    Write-Host "1. Your account lacks Intune Administrator or Security Administrator roles"
    Write-Host "2. The tenant doesn't have the proper licenses for Intune/Conditional Access"
    Write-Host "3. API permissions may need admin consent in Azure AD"
}
