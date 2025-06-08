Modules for creating a Linux server machine to ingest syslog information.

After creation, need to configure a Data Collection Rule to specify what logs to ingest based on rules.

Then, any syslog device can be configured to send log information to the log analytics workspace / sentinel instance.

/networkingConfig holds networking information. Including NSG rules on what approved IPs may SSH into this machine and what public IPs may send logs to the VM for ingestion.
