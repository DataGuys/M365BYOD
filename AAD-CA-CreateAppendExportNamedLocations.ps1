Install-Module AzureAD
# Import the module
Import-Module AzureAD

# Connect to Azure AD
Connect-AzureAD

# Get all Azure AD roles
$roles = Get-AzureADDirectoryRole

# Create an empty hashtable to hold results
$userRoles = @{}

# Loop through each role and get members
foreach ($role in $roles) {
    $members = Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId

    foreach ($member in $members) {
        if (-not $userRoles.ContainsKey($member.ObjectId)) {
            $userRoles[$member.ObjectId] = @{
                'UserName' = $member.DisplayName
                'Roles'    = @()
            }
        }
        
        $userRoles[$member.ObjectId].Roles += $role.DisplayName
    }
}

# Convert hashtable to array of objects for export
$results = $userRoles.Values | ForEach-Object {
    [PSCustomObject]@{
        'UserName' = $_.UserName
        'Roles'    = ($_.Roles -join ', ')
    }
}

# Export results to CSV
$results | Export-Csv -Path 'AzureADRolesByUser.csv' -NoTypeInformation



# Create App Registration without identifierUri
$appName = "NamedLocationApp"
$app = New-AzureADApplication -DisplayName $appName
$appget = Get-AzureADApplication -SearchString $appName
$graphApp = Get-AzureADServicePrincipal -Filter "displayName eq 'Microsoft Graph'"

#Directory Roles List
$RolesList = 'AdministrativeUnit.Read.All',
'Application.Read.All',
'AuditLog.Read.All',
'Directory.Read.All',
'Group.Read.All',
'Policy.Read.All',
'PrivilegedAccess.Read.AzureAD',
'Reports.Read.All',
'RoleManagement.Read.Directory',
'User.Read.All',
'UserAuthenticationMethod.Read.All'

# Assuming you want "Directory.Read.All" permission
$permission = $graphApp.AppRoles | Where-Object { $_.Value -eq "Directory.Read.All" } | Select-Object -First 1
$permissionReq = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
$permissionReq.ResourceAppId = $graphApp.AppId
$permissionReq.ResourceAccess = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList $permission.Id, "Role"

$app = Set-AzureADApplication -ObjectId $appget.ObjectId -RequiredResourceAccess $permissionReq

# Assuming you want "policy.Read.All" permission
$permission = $graphApp.AppRoles | Where-Object { $_.Value -eq "Policy.Read.All" } | Select-Object -First 1
$permissionReq = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
$permissionReq.ResourceAppId = $graphApp.AppId
$permissionReq.ResourceAccess = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList $permission.Id, "Role"

$app = Set-AzureADApplication -ObjectId $appget.ObjectId -RequiredResourceAccess $permissionReq

$AppObjectID = (Get-AzureADApplication -SearchString "NamedLocationApp").ObjectId
# Variables
$appId = $appget.AppId # Replace with your App ID

# Fetch the service principal of the app
$servicePrincipal = Get-AzureADServicePrincipal -ObjectId $appget.AppId

# Grant admin consent
$servicePrincipal.Oauth2Permissions | ForEach-Object {
    Set-AzureADOAuth2PermissionGrant -ObjectId $_.Id -ConsentType AllPrincipals -PrincipalId $servicePrincipal.ObjectId -Scope $_.Scope
}

Write-Output "Admin consent granted for all permissions"

# Set the expiry for the secret
$endDate = Get-Date -Date "2032-12-31T00:00:00Z"

# Create the client secret
$secret = New-AzureADApplicationPasswordCredential -ObjectId $AppObjectID -EndDate $endDate

# Print the secret (make sure to store this securely)
$secret.Value

# Variables
$tenantId = "04a44596-adcd-41ae-87e6-f1fdd2838714"
$clientID = (Get-AzureADApplication -SearchString "NamedLocationApp").AppId
$clientSecret = $secret.Value
$resourceURL = "https://graph.microsoft.com"
$tokenURL = "https://login.microsoftonline.com/$tenantId/oauth2/token"

# Get an access token
$body = @{
    client_id     = $clientID
    scope         = "https://graph.microsoft.com/.default"
    client_secret = $clientSecret
    grant_type    = "client_credentials"
}

$response = Invoke-RestMethod -Method Post -Uri $tokenURL -ContentType "application/x-www-form-urlencoded" -Body $body -UseBasicParsing
$token = $response.access_token

# Fetch the Named Location data
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

$namedLocationsURL = "$resourceURL/v1.0/identity/conditionalAccess/namedLocations"
$namedLocations = Invoke-RestMethod -Method Get -Uri $namedLocationsURL -Headers $headers

# Export the data to CSV
$namedLocations.value | Export-Csv -Path "NamedLocations.csv" -NoTypeInformation

Write-Output "Named Location data exported to NamedLocations.csv"

