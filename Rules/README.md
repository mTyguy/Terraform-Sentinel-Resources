Current Rules:

User login related detections:
- NonUS_Logins_Watchlist_v02 -- Rule is intended to trigger off successful NonUS logins, disabled, utilize NonUS_Logins_Watchlist_with_Whitelisting_v02 for it's whitelisting capabilities, or run this detection in parallel.
- NonUS_Logins_Watchlist_with_Whitelisting_v02 -- Rule is intended to trigger off successful NonUS logins. Includes a builtin whitelisting mechanism that checks a remote csv file for users' regular locations -- see /scripts/get_user_properties_put_file_blob_storage.ps1. Intentionally excluding countries designated by US Federal Government as Foriengn Adversaries.
- FA_Logins_Watchlist_v02 -- Rule is intended to trigger off successful logins from countries designated as Foriegn Adversaries by US Federal Government.

User post compromise detections:
- Risky_User_Registers_New_MFA_v01 -- Rule to detect when a user with an active risk state registers a new MFA method.

Application/Service Principal related detections:
- Application__Registered_RedirectUri_LocalHost_Authentication_v01 -- Rule to detect when an application is registered with a RedirectUri set to localhost or loopback address.
- Application_RedirectUri_LocalHost_Authentication_Added_v01 -- Rule to detect when a registered application is given a Redirect Url for localhost or loopback address.

- Mail_Api_Permissions_Grant_Application -- Rule to detect when constent is given to application type API permissions. Permissions are related to retrieving and sending emails. Masquarading, malicious, or unapproved apps can use these api permissions for nefarious purposes.
- Mail_Api_Permissions_Grant_Delegated -- Rule to detect when constent is given to delegated type API permissions. Permissions are related to retrieving and sending emails. Masquarading, malicious, or unapproved apps can use these api permissions for nefarious purposes.
  - For the two above, see threat intel regarding "Activity Profile: Suspicious OAuth applications used to retrieve and send emails" https://security.microsoft.com/threatanalytics3/ba008625-320a-4c71-b996-977049575144/analystreport.

Device related detections:
- Unapproved_RMM_Tools_v01 -- Rule is intended to trigger off the detection of unapproved RMM tools via a url connection.
- Malicious_Browser_Extensions -- Rule is intended to trigger off the detection of malicicious browser extensions based on id string. Can create this as a custom rule in defender, then create an action that blocks and quarantines the file for automatic remediation or make a playbook in Sentinel. Threat Intel from https://arstechnica.com/security/2025/07/browser-extensions-turn-nearly-1-million-browsers-into-website-scraping-bots/
- FileFix_v01 -- Rule is intended to trigger off FileFix, a ClickFix alternative. See threat intel -- https://mrd0x.com/filefix-clickfix-alternative/
 
/externaldata holds external data to be used in KQL queries

/scripts holds helper scripts to retrieve information to be used in KQL externaldata or auditing
  - get_user_properties_put_file_blob_storage.ps1 -- pulls accountEnabled,displayName,userPrincipalName,id,country,usageLocation,userType from users' properties in Entra, exports to csv, and uploads to azure storage to be queried in KQL.
  - privileged_apps.ps1 -- pulls all Service Principal Ids then gets all Application role assignments for the Service Principals and exports to csv. Allows for insight into all Application permission grants to service prinicpals in the tenant.
