Current Rules:

1). NonUS_Logins_Watchlist_v03 -- Rule is intended to trigger off successful NonUS logins. Includes a builtin whitelisting mechanism that checks a remote csv file for user travel destination countries and return dates. Intentionally excluding countries designated by US Federal Government as Foriengn Adversaries

2). FA_Logins_Watchlist_v02 -- Rule intended to trigger off successful logins from countries designated as Foriegn Adversaries by US Federal Government

3). Unapproved_RMM_Tools_v01 -- Rule is intended to trigger off the detection of unapproved RMM tools via a url connection
 
/externaldata holds external data to be used in KQL queries

/scripts holds helper scripts to retrieve externaldata
