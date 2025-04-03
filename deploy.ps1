<#
.SYNOPSIS
Creates a PoC security group for BYOD implementation with Intune MAM and Conditional Access.

.DESCRIPTION
This script:
1) Creates a security group for BYOD testing
2) Resolves break-glass and service accounts for documentation
3) Provides guidance in comments for manual policy creation in the portals

.NOTES
- Created to address permission issues with Microsoft Graph API for Intune and CA policies
- Only requires Directory.ReadWrite.All permission which is more commonly available
- After creating the group, use the admin portals to create the MAM and CA policies
#>

### --- 1. PROMPT FOR BREAK-GLASS & SERVICE ACCOUNTS ---

# Prompt up to 2 break-glass accounts (UPNs).
# If user hits Enter with no input, we skip that entry.
Install-Module -Name Microsoft.Graph.Intune
Connect-MSGraph -AdminConsent
Update-MSGraphEnvironment -SchemaVersion 'beta'

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

# Prompt for users to include in the PoC group (optional)
Write-Host "Enter the UPNs of any users to include in the PoC group (one per line)."
Write-Host "Press Enter on an empty line to finish."
$includeUserUPNs = @()
while ($true) {
    $user = Read-Host "User to include in PoC group (or Enter to finish)"
    if ([string]::IsNullOrWhiteSpace($user)) { break }
    $includeUserUPNs += $user
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
if ($includeUserUPNs.Count -gt 0) {
    Write-Host "Users to include in PoC group:"
    $includeUserUPNs | ForEach-Object { Write-Host "   $_" }
} else {
    Write-Host "No users specified for PoC group."
}
Write-Host ""

### --- 2. CONNECT TO MS GRAPH ---
$requiredScopes = @(
    "Directory.ReadWrite.All",  # For group management
    "User.Read.All"             # For user lookups
)

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

### --- 3. RESOLVE USER UPNs TO OBJECT IDs ---
Write-Host "`nResolving user UPNs to object IDs..." -ForegroundColor Cyan

# Collect all break-glass and service accounts (to document)
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

# Resolve users to include in the PoC group
$includeUserObjectIds = @()
foreach ($upn in $includeUserUPNs) {
    try {
        # Get user by UPN using Graph SDK
        $user = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction Stop
        
        if ($user) {
            Write-Host "  Found $upn => Object ID: $($user.Id)" -ForegroundColor Green
            $includeUserObjectIds += $user.Id
        }
    } catch {
        Write-Warning "  Could not find user with UPN=$upn. Error: $_"
    }
}

### --- 4. CREATE A POC SECURITY GROUP ---
Write-Host "`n--- Creating PoC Security Group ---" -ForegroundColor Cyan
try {
    $groupParams = @{
        DisplayName = "BYOD PoC Testing Group"
        Description = "Security group for MAM+CA PoC"
        MailEnabled = $false
        MailNickname = "byodPoCTestingGroup"
        SecurityEnabled = $true
    }

    $pocGroup = New-MgGroup @groupParams
    Write-Host "Created group with Id: $($pocGroup.Id)" -ForegroundColor Green
    
    # If we have users to add to the group, add them now
    if ($includeUserObjectIds.Count -gt 0) {
        Write-Host "Adding users to the PoC group..." -ForegroundColor Cyan
        foreach ($userId in $includeUserObjectIds) {
            try {
                New-MgGroupMember -GroupId $pocGroup.Id -DirectoryObjectId $userId
                Write-Host "  Added user with ID: $userId to the group" -ForegroundColor Green
            } catch {
                Write-Warning "  Failed to add user with ID: $userId to the group. Error: $_"
            }
        }
    }
} catch {
    Write-Error "Failed to create security group: $_"
    return
}

### --- 5. EXPORT SETTINGS FOR MANUAL POLICY CREATION ---
# Create a settings file to help with manual policy creation
$dateTime = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$settingsFile = "BYOD_PoC_Settings_$dateTime.json"

$settings = @{
    GroupInfo = @{
        DisplayName = "BYOD PoC Testing Group"
        Id = $pocGroup.Id
    }
    ExcludedAccounts = @()
    MAMPolicyInfo = @{
        iOS = @{
            DisplayName = "iOS App Protection Policy"
            Description = "Block cut/copy/paste, Save As, and printing for iOS."
            Settings = @{
                AllowedClipboardSharingLevel = "managedApps"
                AllowedInboundDataTransferSources = "managedApps"
                AllowedOutboundDataTransferDestinations = "managedApps"
                SaveAsBlocked = $true
                PrintBlocked = $true
                FaceIdBlocked = $false
            }
        }
        Android = @{
            DisplayName = "Android App Protection Policy"
            Description = "Block cut/copy/paste, Save As, and printing for Android."
            Settings = @{
                AllowedClipboardSharingLevel = "managedApps"
                AllowedInboundDataTransferSources = "managedApps"
                AllowedOutboundDataTransferDestinations = "managedApps"
                SaveAsBlocked = $true
                PrintBlocked = $true
            }
        }
    }
    ConditionalAccessInfo = @{
        DisplayName = "Require Compliant or Protected Apps for O365 (PoC)"
        State = "enabled"
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
}

# Add excluded account details to the settings
foreach ($upn in $excludeUserUPNs) {
    try {
        $user = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue
        
        if ($user) {
            $settings.ExcludedAccounts += @{
                UPN = $upn
                Id = $user.Id
                DisplayName = $user.DisplayName
            }
        } else {
            $settings.ExcludedAccounts += @{
                UPN = $upn
                Id = "Not Found"
                DisplayName = "Not Found"
            }
        }
    } catch {
        $settings.ExcludedAccounts += @{
            UPN = $upn
            Id = "Error retrieving"
            DisplayName = "Error retrieving"
        }
    }
}

# Export the settings to a JSON file
$settings | ConvertTo-Json -Depth 10 | Out-File -FilePath $settingsFile
Write-Host "`nExported settings to: $settingsFile" -ForegroundColor Green

### --- 6. PRINT MANUAL SETUP INSTRUCTIONS ---
Write-Host "`n===== MANUAL SETUP INSTRUCTIONS =====" -ForegroundColor Yellow
Write-Host "Due to permission limitations, you need to manually create the following in the admin portals:" -ForegroundColor Yellow

Write-Host "`n1. CREATE iOS MAM POLICY"
Write-Host "   a. Go to: https://intune.microsoft.com/"
Write-Host "   b. Navigate to Apps > App protection policies"
Write-Host "   c. Click '+ Create policy' and select iOS/iPadOS"
Write-Host "   d. Name: 'iOS App Protection Policy'"
Write-Host "   e. Description: 'Block cut/copy/paste, Save As, and printing for iOS.'"
Write-Host "   f. Configure these settings:"
Write-Host "      - Data Transfer: Allow only to managed apps"
Write-Host "      - Save As: Block"
Write-Host "      - Printing: Block"
Write-Host "   g. Assign to the group with ID: $($pocGroup.Id)"

Write-Host "`n2. CREATE ANDROID MAM POLICY"
Write-Host "   a. Go to: https://intune.microsoft.com/"
Write-Host "   b. Navigate to Apps > App protection policies"
Write-Host "   c. Click '+ Create policy' and select Android"
Write-Host "   d. Name: 'Android App Protection Policy'"
Write-Host "   e. Description: 'Block cut/copy/paste, Save As, and printing for Android.'"
Write-Host "   f. Configure these settings:"
Write-Host "      - Data Transfer: Allow only to managed apps"
Write-Host "      - Save As: Block"
Write-Host "      - Printing: Block"
Write-Host "   g. Assign to the group with ID: $($pocGroup.Id)"

Write-Host "`n3. CREATE CONDITIONAL ACCESS POLICY"
Write-Host "   a. Go to: https://portal.azure.com/#blade/Microsoft_AAD_IAM/ConditionalAccessBlade"
Write-Host "   b. Click '+ New policy'"
Write-Host "   c. Name: 'Require Compliant or Protected Apps for O365 (PoC)'"
Write-Host "   d. Users:"
Write-Host "      - Include: Select the group with ID: $($pocGroup.Id)"
if ($excludeUserObjectIds.Count -gt 0) {
    Write-Host "      - Exclude: The following user IDs:"
    foreach ($id in $excludeUserObjectIds) {
        Write-Host "        $id"
    }
}
Write-Host "   e. Cloud apps: Office 365"
Write-Host "   f. Grant access: Require one of the following controls"
Write-Host "      - Compliant device"
Write-Host "      - Approved client app"
Write-Host "   g. Enable policy: Yes"

Write-Host "`n===== SUCCESS =====" -ForegroundColor Green
Write-Host "1) Created PoC group with ID: $($pocGroup.Id)"
Write-Host "2) Created settings file: $settingsFile"
Write-Host "3) Follow the manual instructions above to complete setup"
Write-Host "4) Check Intune and Entra ID portals to confirm."
