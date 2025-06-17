# version 0.1 #

#Pulls all Service Principal Ids then gets all Application role assignments for the Service Principals and exports to csv.
#Allows for insight into all Application permission grants to service prinicpals in the tenant.

# Requirements #
#AzPowerShell pwsh module
#https://learn.microsoft.com/en-us/powershell/azure/?view=azps-14.0.0

# Permissions #
#Application.Read.All

###

# Define the Application (Client) ID and Secret
$ApplicationClientId = 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX'
$ApplicationClientSecret = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
$TenantId = 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX'

# Convert the Client Secret to a Secure String
$SecureClientSecret = ConvertTo-SecureString -String $ApplicationClientSecret -AsPlainText -Force

# Create a PSCredential Object Using the Client ID and Secure Client Secret
$ClientSecretCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ApplicationClientId, $SecureClientSecret

# Connect to Microsoft Graph Using the Tenant ID and Client Secret Credential
Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $ClientSecretCredential -NoWelcome

$ids = (Get-AzADServicePrincipal).id

$results = foreach ($_ in $ids) {
  Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId "$_" -All
  }

$results | Export-csv -UseQuotes AsNeeded -Path ./privileged_apps.csv -Force
