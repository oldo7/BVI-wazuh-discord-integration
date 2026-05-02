## Requirements

- Wazuh manager and agents: version 4.9 or newer (tested on 4.14.5)
- SSH installed and configured on all agents and manager

## Installation

1. Fill up the .env (see instructions in the file).
2. pip install -r requirements.txt
3. Make sure that inbound port 8000 is allowed by the firewall on the machine running the orchestrator
4. Make sure that all agents have SSH installed. The SSH account must have permission to write to `/var/ossec/active-response/bin/`.
5. Fill in `agents.json` with SSH credentials for each agent (see format in the file).
6. python install.py

## Adding new commands / alert mappings

1. Edit `commands.json` directly to add new commands or alert mappings. In the "rules" section you see rule_id from wazuh manager that will trigger an alert. Possible commands as reactions to that alert are in the corresponding square brackets. In the "commands" section are all possible commands and their corresponing parameters - name of the script to be executed on agents when this command is used, and what parameters that script recieves.
2. For each new command, add an agent script to the `agent_scripts/` folder. Every command defined in `commands.json` must have a corresponding script in `agent_scripts/` with the same name as the `script` field. This is the script that will execute on the agent once you execute that given command. The script will execute with parameters that you can define in the "data" field in commands.json. You can use the "template" script and commands to create new scripts and commands.
3. Run `python configure.py` — it will update ossec.conf on the manager and deploy scripts to all agents in `agents.json`. To correctly deploy the scripts, make sure that you have set ssh credentials for every agent in `agents.json`

## Running the app

1. python orchestrator.py
