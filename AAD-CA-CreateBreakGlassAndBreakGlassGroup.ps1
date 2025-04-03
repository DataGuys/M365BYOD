#Run the top 3 lines in PowerShell runas Administrator
#Uninstall-Module Microsoft.Graph -Force
#Install-Module Microsoft.Graph

# Login to Microsoft Graph
Connect-MgGraph -Scopes Directory.ReadWrite.All

# Load assembly for password generation
Add-Type -AssemblyName System.Web

# Define the names and UPNs for the Break Glass accounts
$breakGlassAccounts = @(
    @{Name = "BreakGlassAccount1"; UserPrincipalName = "breakglass1@helient.onmicrosoft.com"},
    @{Name = "BreakGlassAccount2"; UserPrincipalName = "breakglass2@helient.onmicrosoft.com"}
)

# Array to store account details for export
$accountDetailsForExport = @()
$accountDetailsForExport = $null

# Create the Break Glass accounts and assign the Global Administrator role
foreach ($account in $breakGlassAccounts) {
    # Generate a random password
    $password = [System.Web.Security.Membership]::GeneratePassword(32, 5)
    $PasswordProfile =@{
    Password = $password
    ForceChangePasswordNextSignIn = $false
    }    
    # Create user
    $user = New-MgUser -DisplayName $account.Name -PasswordProfile $PasswordProfile -UserPrincipalName $account.UserPrincipalName -MailNickname $account.Name -AccountEnabled
    
    # Get the directory role
    $globalAdminRoleId = (Get-MgDirectoryRole | Where-Object {$_.DisplayName -eq "Global Administrator"}).Id
    # Assign role to user
    New-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRoleId -DirectoryObject $user
    
    Write-Host "Break Glass account $($account.Name) created with password: $password and assigned Global Administrator role"

    $accountDetailsForExport += @{
        UserName = $account.UserPrincipalName;
        Password = $password;
        Groups = @();
        UserId = $user.Id
    }
}

# Create Break Glass Security Group
$GroupParam = @{
     DisplayName = "HEL-BreakGlass"
     GroupTypes = @(
     )
     SecurityEnabled     = $true
     IsAssignableToRole  = $false
     MailEnabled         = $false
     MailNickname        = (New-Guid).Guid.Substring(0,10)
}
 
$BreakGlassGroup = New-MgGroup -BodyParameter $GroupParam


# Add the Break Glass accounts to the security group and update account details
foreach ($accountDetail in $accountDetailsForExport) {
    Add-MgGroupMember -GroupId $breakGlassGroup.Id -DirectoryObject $accountDetail.UserId
    Write-Host "Break Glass account $($accountDetail.UserName) added to Break Glass Security Group"
    
    # Get and store groups the user is a member of
    $groups = Get-MgGroupMember -GroupId $breakGlassGroup.Id | Where-Object {$_.OdataType -eq '#microsoft.graph.group'}
    $accountDetail.Groups = ($groups | ForEach-Object {$_.DisplayName}) -join ', '
}

# Export account details to CSV
$exportData = $accountDetailsForExport | Select-Object UserName, Password, Groups
$exportData | Export-Csv -Path ".\BreakGlassAccounts.csv" -NoTypeInformation

Write-Host "Account details exported to BreakGlassAccounts.csv"
