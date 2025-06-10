Modules for creating a Linux VM to ingest syslog information and automatically send them to Sentinel. Useful for remote locations where a local linux machine is not viable.

You can also run a similar solution on-prem using an Azure Arc enabled server where it is feasible to have a local linux machine.

/networkingConfig holds networking information. Including NSG rules on what approved IPs may SSH into this machine and what public IPs may send syslogs to the VM for ingestion.
/dataCollection hold the data collection rule and association to send the syslogs to the log analytics workspace / sentinel instance.
