# version 0.1 #
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
