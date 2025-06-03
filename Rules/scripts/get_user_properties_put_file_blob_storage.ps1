# version 0.1 #

# Script to get user properties from their respective Entra profiles, export to a csv file, and then upload the csv file to Azure Blob Storage.
# The csv file can then be utilized in KQL queries as a reference or as whitelisting mechanism using externaldata.

# Requirements #
#MgGraph pwsh module
#https://learn.microsoft.com/en-us/powershell/microsoftgraph/overview?view=graph-powershell-1.0
#AzPowerShell pwsh module
#https://learn.microsoft.com/en-us/powershell/azure/?view=azps-14.0.0

# Permissions #
# User.Read.All
# Adequate permissions to put a file in Blob storage, Storage Blob Data Contributor

###

# Define the Application (Client) ID, Secret, and TenantID
$ApplicationClientId = 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX'
$ApplicationClientSecret = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
$TenantId = 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX'

# Convert the Client Secret to a Secure String
$SecureClientSecret = ConvertTo-SecureString -String $ApplicationClientSecret -AsPlainText -Force

# Create a PSCredential Object Using the Client ID and Secure Client Secret
$ClientSecretCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ApplicationClientId, $SecureClientSecret

# Connect to Microsoft Graph Using the Tenant ID and Client Secret Credential
Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $ClientSecretCredential -NoWelcome

####

# Get list of all users with the below properties and export to csv file
(Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users?`$select=accountenabled,displayname,userprincipalname,id,country,usagelocation,usertype" -OutputType PSObject).value | Export-Csv -UseQuotes AsNeeded -Path ./user_properties.csv

# End session, suppress output
Disconnect-MgGraph | Out-Null

###

# Build authentication
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ApplicationClientId, $SecureClientSecret

# Authenticate to Azure
#Connect-AzAccount -ServicePrincipal -Credential $Credential -Tenant $TenantId

# Get context
$context = (New-AzStorageContext -ConnectionString "DefaultEndpointsProtocol=https;AccountName=<storage account name>;AccountKey=<Account key, ends in ==>;EndpointSuffix=core.windows.net").Context

# Upload file to container, -Force to write over existing csv file 
Set-AzStorageBlobContent -Container "externaldata" -File "./user_properties.csv" -Context $context -Force | Out-Null

# End session, suppress output
Disconnect-AzAccount | Out-Null
