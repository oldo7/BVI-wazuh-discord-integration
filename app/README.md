## Requirements
- Wazuh manager and agents: version 4.9 or newer (tested on 4.14.5)

## Installation

1. Fill up the .env - warning - the wazuh user and passwords are for the API user, not the ones you use for accss via dashboard. the api user credentials can usually be found in wazuh-install-files/wazuh-passwords.txt.
2. pip install -r requirements.txt
3. Make sure that inbound port 8000 is allowed by the firewall on the machine running the orchestrator
4. Make sure that all agents have ssh installed and prepare their ssh credentials. The ssh account should have sufficient permissions to add scripts to `/var/ossec/active-response/bin/`.
5. python install.py
6. python orchestrator.py
