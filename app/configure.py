#!/usr/bin/env python3
import os
import sys
import json
import paramiko
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

WAZUH_MANAGER_SSH_HOST = os.getenv('WAZUH_MANAGER_SSH_HOST')
WAZUH_MANAGER_SSH_USER = os.getenv('WAZUH_MANAGER_SSH_USER', 'root')
WAZUH_MANAGER_SSH_PASS = os.getenv('WAZUH_MANAGER_SSH_PASSWORD')
OSSEC_CONF_PATH = '/var/ossec/etc/ossec.conf'
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'commands.json')

# ---------------------------------------------------------------------------

def _ssh_connect():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(WAZUH_MANAGER_SSH_HOST, username=WAZUH_MANAGER_SSH_USER, password=WAZUH_MANAGER_SSH_PASS, timeout=10)
    return client

def _ssh_run(client, cmd):
    _, stdout, stderr = client.exec_command(cmd)
    return stdout.read().decode(), stderr.read().decode()

def read_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)

def write_config(config):
    with open(CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=4)

def add_ossec_command(client, name, timeout_allowed):
    conf, _ = _ssh_run(client, f'cat {OSSEC_CONF_PATH}')
    if f'<name>{name}</name>' in conf:
        print(f"  Command '{name}' already in ossec.conf, skipping.")
        return
    timeout_line = '    <timeout_allowed>yes</timeout_allowed>\n' if timeout_allowed else ''
    block = f'\n  <command>\n    <name>{name}</name>\n    <executable>{name}</executable>\n{timeout_line}  </command>\n'
    pos = conf.rfind('</ossec_config>')
    new_conf = conf[:pos] + block + conf[pos:]
    sftp = client.open_sftp()
    with sftp.open(OSSEC_CONF_PATH, 'w') as f:
        f.write(new_conf)
    sftp.close()
    _ssh_run(client, f'chown root:wazuh {OSSEC_CONF_PATH}')
    _ssh_run(client, 'systemctl restart wazuh-manager')
    print(f"  Added '{name}' to ossec.conf and restarted wazuh-manager.")

# ---------------------------------------------------------------------------

def menu_alert_mappings():
    config = read_config()
    rules = config['rules']
    commands = config['commands']

    print("\n=== Current alert mappings ===")
    if not rules:
        print("  (none)")
    for rule_id, cmds in rules.items():
        print(f"  Rule {rule_id}: {', '.join(cmds)}")

    print("\n  1) Add new alert mapping")
    print("  2) Modify existing alert mapping")
    print("  3) Back")
    choice = input("  > ").strip()

    if choice == '1':
        rule_id = input("  Rule ID: ").strip()
        if rule_id in rules:
            print(f"  Rule {rule_id} already exists. Use modify (option 2).")
            return
        print(f"  Available commands: {', '.join(commands.keys())}")
        raw = input("  Commands (comma-separated): ").strip()
        cmds = [c.strip() for c in raw.split(',') if c.strip() in commands]
        if not cmds:
            print("  No valid commands entered.")
            return
        rules[rule_id] = cmds
        write_config(config)
        print(f"  Added: Rule {rule_id} → {cmds}")

    elif choice == '2':
        rule_id = input("  Rule ID to modify: ").strip()
        if rule_id not in rules:
            print(f"  Rule {rule_id} not found.")
            return
        print(f"  Current commands: {', '.join(rules[rule_id])}")
        print(f"  Available commands: {', '.join(commands.keys())}")
        raw = input("  New commands (comma-separated): ").strip()
        cmds = [c.strip() for c in raw.split(',') if c.strip() in commands]
        if not cmds:
            print("  No valid commands entered.")
            return
        rules[rule_id] = cmds
        write_config(config)
        print(f"  Updated: Rule {rule_id} → {cmds}")


def menu_add_command():
    config = read_config()

    print("\n=== Add new command ===")
    keyword = input("  Discord keyword (what user types in reply): ").strip().lower()
    if not keyword:
        return
    if keyword in config['commands']:
        print(f"  Command '{keyword}' already exists.")
        return

    script_name = input("  Script name (executable in /var/ossec/active-response/bin/ on agents): ").strip()
    if not script_name:
        return

    print("  What data does this command need from the alert?")
    print("  1) srcip — source IP")
    print("  2) username — target username")
    print("  3) both")
    print("  4) none")
    data_type = {'1': 'srcip', '2': 'username', '3': 'both', '4': 'none'}.get(input("  > ").strip(), 'none')

    timeout = input("  Allow timeout parameter? (y/n): ").strip().lower() == 'y'

    config['commands'][keyword] = {
        'script': script_name,
        'data': data_type,
        'timeout': timeout
    }
    write_config(config)
    print(f"  Added '{keyword}' to commands.json.")

    try:
        client = _ssh_connect()
        add_ossec_command(client, script_name, timeout)
        client.close()
    except Exception as e:
        print(f"  ERROR updating ossec.conf: {e}")
        timeout_line = '    <timeout_allowed>yes</timeout_allowed>\n' if timeout else ''
        print(f"  Add this manually to ossec.conf on the manager:")
        print(f"  <command>\n    <name>{script_name}</name>\n    <executable>{script_name}</executable>\n{timeout_line}  </command>")

    print(f"\n  Deploy the script to each agent:")
    print(f"    scp <script> root@<AGENT_IP>:/var/ossec/active-response/bin/{script_name}")
    print(f"    ssh root@<AGENT_IP> \"chmod 750 /var/ossec/active-response/bin/{script_name} && chown root:wazuh /var/ossec/active-response/bin/{script_name}\"")

# ---------------------------------------------------------------------------

def main():
    print("=== Wazuh-Discord Orchestrator — Configuration ===")
    while True:
        print("\n  1) Manage alert-command mappings")
        print("  2) Add new command")
        print("  3) Exit")
        choice = input("  > ").strip()
        if choice == '1':
            menu_alert_mappings()
        elif choice == '2':
            menu_add_command()
        elif choice == '3':
            break

if __name__ == '__main__':
    main()
