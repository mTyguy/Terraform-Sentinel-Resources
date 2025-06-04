Current Rules:

User login related detections:
- NonUS_Logins_Watchlist_v02 -- Rule is intended to trigger off successful NonUS logins, disabled, utilize NonUS_Logins_Watchlist_with_Whitelisting_v02 for it's whitelisting capabilities, or run this detection in parallel.
- NonUS_Logins_Watchlist_with_Whitelisting_v02 -- Rule is intended to trigger off successful NonUS logins. Includes a builtin whitelisting mechanism that checks a remote csv file for user travel destination countries and return dates. Intentionally excluding countries designated by US Federal Government as Foriengn Adversaries.
- FA_Logins_Watchlist_v02 -- Rule is intended to trigger off successful logins from countries designated as Foriegn Adversaries by US Federal Government.

Application/Service Principal related detections:
- NRT_Application__Registered_RedirectUri_LocalHost_Authentication_v01 -- Rule to detect when an application is registered with a RedirectUri set to localhost or loopback address.
- NRT_Application_RedirectUri_LocalHost_Authentication_Added_v01 -- Rule to detect when a registered application is given a Redirect Url for localhost or loopback address.

Device related detections:
- Unapproved_RMM_Tools_v01 -- Rule is intended to trigger off the detection of unapproved RMM tools via a url connection.
 
/externaldata holds external data to be used in KQL queries

/scripts holds helper scripts to retrieve externaldata
