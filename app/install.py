#!/usr/bin/env python3
import os
import sys
import socket
import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import paramiko
except ImportError:
    print("ERROR: paramiko is required. Run: pip install paramiko")
    sys.exit(1)

load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

DISCORD_BOT_TOKEN      = os.getenv('DISCORD_BOT_TOKEN')
FLASK_PORT             = os.getenv('FLASK_PORT', '8000')
WAZUH_MANAGER_URL      = os.getenv('WAZUH_MANAGER_URL')
WAZUH_USERNAME         = os.getenv('WAZUH_USERNAME')
WAZUH_PASSWORD         = os.getenv('WAZUH_PASSWORD')
WAZUH_MANAGER_SSH_HOST = os.getenv('WAZUH_MANAGER_SSH_HOST')
WAZUH_MANAGER_SSH_USER = os.getenv('WAZUH_MANAGER_SSH_USER', 'root')
WAZUH_MANAGER_SSH_PASS = os.getenv('WAZUH_MANAGER_SSH_PASSWORD')

OSSEC_CONF_PATH       = '/var/ossec/etc/ossec.conf'
INTEGRATION_SCRIPT_PATH = '/var/ossec/integrations/custom-webhook'
AGENT_SCRIPTS_REMOTE  = '/var/ossec/active-response/bin/'
AGENT_SCRIPTS_LOCAL   = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'agent_scripts')

COMMANDS = [
    'custom-command',
    'block-ssh-user',
    'logout-ssh',
    'log-attacker',
    'disable-linux-user',
    'delete-linux-user',
]

INTEGRATION_SCRIPT_CONTENT = """\
#!/usr/bin/env python3
import sys
import json
import requests

alert_file = sys.argv[1]
webhook_url = sys.argv[3]

with open(alert_file, 'r') as f:
    alert = json.load(f)

requests.post(webhook_url, json=alert)
"""

# ---------------------------------------------------------------------------

def step(n, msg):
    print(f"\n[{n}] {msg}")

def ok(msg):
    print(f"    OK: {msg}")

def info(msg):
    print(f"    {msg}")

def error(msg):
    print(f"    ERROR: {msg}")
    sys.exit(1)

# ---------------------------------------------------------------------------

def check_env():
    step(1, "Validating .env...")
    required = [
        'DISCORD_BOT_TOKEN', 'WAZUH_MANAGER_URL', 'WAZUH_USERNAME',
        'WAZUH_PASSWORD', 'WAZUH_MANAGER_SSH_HOST', 'WAZUH_MANAGER_SSH_PASSWORD',
    ]
    missing = [v for v in required if not os.getenv(v)]
    if missing:
        error(f"Missing required .env values: {', '.join(missing)}")
    ok("All required values present.")


def sanity_checks():
    step(2, "Sanity checks...")

    # Wazuh API
    try:
        resp = requests.post(
            f"{WAZUH_MANAGER_URL}/security/user/authenticate",
            auth=(WAZUH_USERNAME, WAZUH_PASSWORD),
            verify=False,
            params={"raw": "true"},
            timeout=10,
        )
        if resp.status_code != 200:
            error(f"Wazuh API returned {resp.status_code} — check WAZUH_USERNAME / WAZUH_PASSWORD.")
        token = resp.text.strip('"')
        ok("Wazuh API authentication successful.")
    except Exception as e:
        error(f"Cannot reach Wazuh API: {e}")

    # SSH
    try:
        client = _ssh_connect()
        client.close()
        ok("SSH connection to manager successful.")
    except Exception as e:
        error(f"Cannot SSH into manager: {e}")

    return token


def _ssh_connect():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        WAZUH_MANAGER_SSH_HOST,
        username=WAZUH_MANAGER_SSH_USER,
        password=WAZUH_MANAGER_SSH_PASS,
        timeout=10,
    )
    return client


def _ssh_run(client, cmd):
    _, stdout, stderr = client.exec_command(cmd)
    return stdout.read().decode(), stderr.read().decode()


def get_orchestrator_ip():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((WAZUH_MANAGER_SSH_HOST, 80))
        return s.getsockname()[0]


# ---------------------------------------------------------------------------

def configure_ossec(client, orchestrator_ip):
    step(3, "Configuring ossec.conf on manager...")

    conf, err = _ssh_run(client, f"cat {OSSEC_CONF_PATH}")
    if not conf:
        error(f"Could not read {OSSEC_CONF_PATH}: {err}")

    changed = False

    # Integration block
    if '<name>custom-webhook</name>' not in conf:
        block = (
            f"\n  <integration>\n"
            f"    <name>custom-webhook</name>\n"
            f"    <hook_url>http://{orchestrator_ip}:{FLASK_PORT}/webhook</hook_url>\n"
            f"    <level>3</level>\n"
            f"    <alert_format>json</alert_format>\n"
            f"  </integration>\n"
        )
        conf = _insert_before_closing_tag(conf, block)
        info("Added integration block.")
        changed = True
    else:
        info("Integration block already present, skipping.")

    # Command blocks
    for name in COMMANDS:
        if f'<name>{name}</name>' not in conf:
            block = (
                f"\n  <command>\n"
                f"    <name>{name}</name>\n"
                f"    <executable>{name}</executable>\n"
                f"    <timeout_allowed>yes</timeout_allowed>\n"
                f"  </command>\n"
            )
            conf = _insert_before_closing_tag(conf, block)
            info(f"Added command block: {name}")
            changed = True
        else:
            info(f"Command '{name}' already present, skipping.")

    if not changed:
        info("No changes needed.")
        return

    # Validate locally before touching the remote file
    try:
        import xml.etree.ElementTree as ET
        ET.fromstring(f"<root>{conf}</root>")
    except ET.ParseError as e:
        error(f"ossec.conf is invalid XML after edit — aborting to avoid breaking manager.\n{e}")

    sftp = client.open_sftp()
    with sftp.open(OSSEC_CONF_PATH, 'w') as f:
        f.write(conf)
    sftp.close()

    _ssh_run(client, f"chown root:wazuh {OSSEC_CONF_PATH}")
    ok("ossec.conf updated.")


def _insert_before_closing_tag(conf, block):
    pos = conf.rfind('</ossec_config>')
    return conf[:pos] + block + conf[pos:]


# ---------------------------------------------------------------------------

def deploy_integration_script(client):
    step(4, "Deploying integration script to manager...")

    sftp = client.open_sftp()
    try:
        with sftp.open(INTEGRATION_SCRIPT_PATH, 'w') as f:
            f.write(INTEGRATION_SCRIPT_CONTENT)
    except Exception as e:
        error(f"Could not write integration script: {e}")
    sftp.close()

    _ssh_run(client, f"chmod 755 {INTEGRATION_SCRIPT_PATH} && chown root:wazuh {INTEGRATION_SCRIPT_PATH}")
    ok(f"Integration script deployed to {INTEGRATION_SCRIPT_PATH}.")

    _ssh_run(client, "pip3 install requests -q 2>&1 || pip install requests -q 2>&1")
    ok("python3 requests library available on manager.")

    _ssh_run(client, "systemctl restart wazuh-manager")
    ok("wazuh-manager restarted.")


# ---------------------------------------------------------------------------

def handle_agents(token):
    step(5, "Agent script deployment...")

    try:
        resp = requests.get(
            f"{WAZUH_MANAGER_URL}/agents",
            headers={"Authorization": f"Bearer {token}"},
            params={"limit": 500},
            verify=False,
            timeout=10,
        )
        agents = resp.json().get('data', {}).get('affected_items', [])
        agents = [a for a in agents if a.get('id') != '000']
    except Exception as e:
        error(f"Could not fetch agent list: {e}")

    if not agents:
        info("No agents registered (besides manager). Skipping.")
        return

    info(f"Found {len(agents)} agent(s):")
    for a in agents:
        print(f"       [{a['id']}] {a['name']}  —  {a.get('ip', 'unknown IP')}")

    print("\n    Deploy scripts via SSH or manually?")
    print("    1) SSH (automatic)")
    print("    2) Manual (print instructions)")
    choice = input("    Enter 1 or 2: ").strip()

    failed = []

    if choice == '1':
        failed = _deploy_agents_auto(agents)
    else:
        failed = agents

    if failed:
        print("\n    The following agents need scripts deployed manually:")
        for a in failed:
            print(f"       [{a['id']}] {a['name']}  —  {a.get('ip', 'unknown IP')}")
        _print_manual_instructions(failed)


def _deploy_agents_auto(agents):
    failed = []
    for agent in agents:
        agent_ip = agent.get('ip', '')
        print(f"\n    Agent [{agent['id']}] {agent['name']} ({agent_ip})")
        user = input(f"      SSH user (default: root): ").strip() or 'root'
        passwd = input(f"      SSH password: ").strip()

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(agent_ip, username=user, password=passwd, timeout=10)
            sftp = client.open_sftp()

            for script in COMMANDS:
                local = os.path.join(AGENT_SCRIPTS_LOCAL, script)
                remote = AGENT_SCRIPTS_REMOTE + script
                if not os.path.exists(local):
                    print(f"      WARNING: {local} not found locally, skipping.")
                    continue
                sftp.put(local, remote)
                _ssh_run(client, f"chmod 750 {remote} && chown root:wazuh {remote}")
                print(f"      Deployed: {script}")

            sftp.close()
            client.close()
            ok(f"Agent {agent['name']} done.")
        except Exception as e:
            print(f"      ERROR connecting to {agent_ip}: {e}")
            failed.append(agent)

    return failed


def _print_manual_instructions(agents):
    brace = "{" + ",".join(COMMANDS) + "}"
    perms = f"chmod 750 {AGENT_SCRIPTS_REMOTE}{brace} && chown root:wazuh {AGENT_SCRIPTS_REMOTE}{brace}"

    print("\n    Copy the scripts from the agent_scripts/ folder to each agent.")
    print("    Run the following commands from this machine:\n")
    for agent in agents:
        ip = agent.get('ip', 'AGENT_IP')
        print(f"    # [{agent['id']}] {agent['name']} ({ip})")
        print(f"    scp agent_scripts/* root@{ip}:{AGENT_SCRIPTS_REMOTE}")
        print(f"    ssh root@{ip} \"{perms}\"")
        print()


# ---------------------------------------------------------------------------

def main():
    print("=== Wazuh-Discord Orchestrator — Installation ===")

    check_env()
    token = sanity_checks()

    orchestrator_ip = get_orchestrator_ip()
    info(f"Detected orchestrator IP: {orchestrator_ip}")

    client = _ssh_connect()
    configure_ossec(client, orchestrator_ip)
    deploy_integration_script(client)
    client.close()

    handle_agents(token)

    print("\n=== Installation complete ===")
    print("\nRemaining manual steps:")
    print("  1. Ensure port 8000 (or your FLASK_PORT) is open in your firewall on this machine.")
    print("  2. Make sure your Discord bot is created on the Developer Portal and invited to your server.")
    print("  3. Run:  python orchestrator.py")


if __name__ == '__main__':
    main()
