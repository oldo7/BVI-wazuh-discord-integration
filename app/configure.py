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
AGENT_SCRIPTS_REMOTE = '/var/ossec/active-response/bin/'
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, 'commands.json')
AGENTS_PATH = os.path.join(BASE_DIR, 'agents.json')
SCRIPTS_DIR = os.path.join(BASE_DIR, 'agent_scripts')

# ---------------------------------------------------------------------------

def _ssh_connect(host, user, passwd):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=user, password=passwd, timeout=10)
    return client

def _ssh_run(client, cmd):
    _, stdout, stderr = client.exec_command(cmd)
    return stdout.read().decode(), stderr.read().decode()

def ok(msg):   print(f"  OK: {msg}")
def info(msg): print(f"  {msg}")
def err(msg):  print(f"  ERROR: {msg}")

# ---------------------------------------------------------------------------

def sync_ossec(commands):
    print("\n[1] Syncing ossec.conf on manager...")
    try:
        client = _ssh_connect(WAZUH_MANAGER_SSH_HOST, WAZUH_MANAGER_SSH_USER, WAZUH_MANAGER_SSH_PASS)
    except Exception as e:
        err(f"Cannot SSH into manager: {e}")
        return

    conf, _ = _ssh_run(client, f'cat {OSSEC_CONF_PATH}')
    changed = False

    for cmd_name, cmd_def in commands.items():
        script = cmd_def['script']
        timeout = cmd_def.get('timeout', False)
        if f'<name>{script}</name>' in conf:
            info(f"Command '{script}' already in ossec.conf, skipping.")
            continue
        timeout_line = '    <timeout_allowed>yes</timeout_allowed>\n' if timeout else ''
        block = f'\n  <command>\n    <name>{script}</name>\n    <executable>{script}</executable>\n{timeout_line}  </command>\n'
        pos = conf.rfind('</ossec_config>')
        conf = conf[:pos] + block + conf[pos:]
        info(f"Added command '{script}'.")
        changed = True

    if changed:
        sftp = client.open_sftp()
        with sftp.open(OSSEC_CONF_PATH, 'w') as f:
            f.write(conf)
        sftp.close()
        _ssh_run(client, f'chown root:wazuh {OSSEC_CONF_PATH}')
        _ssh_run(client, 'systemctl restart wazuh-manager')
        ok("ossec.conf updated and wazuh-manager restarted.")
    else:
        ok("No changes needed.")

    client.close()


def deploy_scripts(commands):
    print("\n[2] Deploying agent scripts...")

    scripts = list({cmd_def['script'] for cmd_def in commands.values()})

    missing = [s for s in scripts if not os.path.exists(os.path.join(SCRIPTS_DIR, s))]
    if missing:
        err(f"The following scripts are missing from agent_scripts/: {', '.join(missing)}")
        err("Add them before running configure.py.")
        sys.exit(1)

    try:
        with open(AGENTS_PATH) as f:
            agents = json.load(f)
    except Exception as e:
        err(f"Could not read agents.json: {e}")
        sys.exit(1)

    if not agents:
        info("No agents in agents.json. Deploy scripts manually:")
        _print_manual(scripts, ["<AGENT_IP>"])
        return

    failed = []
    for agent in agents:
        ip = agent['ip']
        user = agent.get('user', 'root')
        passwd = agent.get('password', '')
        print(f"\n  Agent {ip}...")
        try:
            client = _ssh_connect(ip, user, passwd)
            sftp = client.open_sftp()
            for script in scripts:
                local = os.path.join(SCRIPTS_DIR, script)
                remote = AGENT_SCRIPTS_REMOTE + script
                sftp.put(local, remote)
                _ssh_run(client, f'chmod 750 {remote} && chown root:wazuh {remote}')
                info(f"Deployed: {script}")
            sftp.close()
            client.close()
            ok(f"Agent {ip} done.")
        except Exception as e:
            err(f"Failed to connect to {ip}: {e}")
            failed.append(ip)

    if failed:
        print("\n  Deploy manually to failed agents:")
        _print_manual(scripts, failed)


def _print_manual(scripts, ips):
    for ip in ips:
        for script in scripts:
            print(f"    scp agent_scripts/{script} root@{ip}:{AGENT_SCRIPTS_REMOTE}{script}")
            print(f"    ssh root@{ip} \"chmod 750 {AGENT_SCRIPTS_REMOTE}{script} && chown root:wazuh {AGENT_SCRIPTS_REMOTE}{script}\"")

# ---------------------------------------------------------------------------

def main():
    print("=== Wazuh-Discord Orchestrator — Configure ===")

    try:
        with open(CONFIG_PATH) as f:
            config = json.load(f)
    except Exception as e:
        print(f"ERROR: Could not read commands.json: {e}")
        sys.exit(1)

    commands = config.get('commands', {})
    if not commands:
        print("No commands defined in commands.json.")
        sys.exit(0)

    sync_ossec(commands)
    deploy_scripts(commands)

    print("\n=== Done ===")

if __name__ == '__main__':
    main()
