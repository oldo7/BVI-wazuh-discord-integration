from flask import Flask, request
import discord
import threading
import asyncio
import os
import json
import requests
import time
from dotenv import load_dotenv
from datetime import datetime

_config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'commands.json')
with open(_config_path) as _f:
    _config = json.load(_f)

RULE_COMMANDS = _config['rules']
COMMANDS = _config['commands']

### DISCORD ###
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))
intents = discord.Intents.default()
intents.message_content = True
bot = discord.Client(intents=intents)
channel_id = None

alert_store = {}

WAZUH_MANAGER_URL = os.getenv('WAZUH_MANAGER_URL')
WAZUH_USERNAME = os.getenv('WAZUH_USERNAME')
WAZUH_PASSWORD = os.getenv('WAZUH_PASSWORD')
FLASK_PORT = int(os.getenv('FLASK_PORT', 8000))

wazuh_token = None
token_expiry = 0

@bot.event
async def on_ready():
    global channel_id
    for guild in bot.guilds:
        for channel in guild.text_channels:
            channel_id = channel.id
            print(f"Bot online and ready to send messages to #{channel.name}")
            return

@bot.event
async def on_message(message):
    if message.author == bot.user:
        return

    if message.reference and message.reference.message_id:
        original_msg_id = str(message.reference.message_id)
        try:
            original_msg = await message.channel.fetch_message(message.reference.message_id)
            if original_msg.author == bot.user:
                handle_command(original_msg_id, message.content)
        except:
            pass

def run_bot():
    bot.run(os.getenv('DISCORD_BOT_TOKEN'))

async def send_discord_message(message, alert_data=None):
    channel = bot.get_channel(channel_id)
    sent_msg = await channel.send(message)
    print(f"Discord message sent: {message}")
    if alert_data:
        alert_store[str(sent_msg.id)] = alert_data

### FLASK ###
app = Flask(__name__)

def handle_command(original_msg_id, command):
    alert = alert_store[original_msg_id]
    print(f"Command received: {command}")

    parts = command.strip().lower().split()
    cmd = parts[0]
    param = parts[1] if len(parts) > 1 else None
    rule_id = alert.get('rule', {}).get('id', '')

    if rule_id not in RULE_COMMANDS or cmd not in RULE_COMMANDS[rule_id]:
        print(f"Command '{cmd}' not allowed for rule {rule_id}")
        return

    if cmd not in COMMANDS:
        print(f"Command '{cmd}' has no definition in commands.json")
        return

    src_ip = alert.get('data', {}).get('srcip', '')
    agent_id = alert.get('agent', {}).get('id', '')
    username = alert.get('data', {}).get('dstuser', '')
    if not username:
        username = alert.get('data', {}).get('win', {}).get('eventdata', {}).get('targetUserName', '')

    cmd_def = COMMANDS[cmd]
    script = cmd_def['script']
    data_type = cmd_def['data']

    if data_type == 'srcip':
        if not src_ip:
            print(f"Command '{cmd}' requires srcip but none found in alert")
            return
        data = {'srcip': src_ip}
        if cmd_def.get('timeout') and param:
            try:
                data['timeout'] = int(param) * 60
            except ValueError:
                data['timeout'] = 120
        elif cmd_def.get('timeout'):
            data['timeout'] = 120
    elif data_type == 'username':
        if not username:
            print(f"Command '{cmd}' requires username but none found in alert")
            return
        data = {'username': username}
    elif data_type == 'both':
        data = {'srcip': src_ip, 'username': username}
    else:
        data = {}

    if not agent_id:
        print(f"No agent_id in alert")
        return

    send_active_response(agent_id, f"!{script}", data)

def format_alert(alert):
    rule = alert.get('rule', {})
    agent = alert.get('agent', {})
    data = alert.get('data', {})
    win = data.get('win', {})
    eventdata = win.get('eventdata', {})

    level = rule.get('level', '?')
    description = rule.get('description', 'Unknown alert')
    agent_name = agent.get('name', 'Unknown')
    agent_ip = agent.get('ip', 'Unknown')

    timestamp_raw = alert.get('timestamp', '')
    dt = datetime.fromisoformat(timestamp_raw.replace('Z', '+00:00'))
    timestamp = dt.strftime('%d-%m-%Y %H:%M:%S')

    src_ip = data.get('srcip', '')
    if not src_ip:
        src_ip = alert.get('srcip', '')

    full_log = alert.get('full_log', 'No details')
    file_path = data.get('file', '')

    message = f"**======= Wazuh Alert =======**\n"
    message += f"{timestamp}\n"
    message += f"**Level:** {level}\n"
    message += f"**Rule:** {description}\n"
    message += f"**Agent:** {agent_name} ({agent_ip})\n"

    if src_ip:
        message += f"**Source IP:** {src_ip}\n"
    if file_path:
        message += f"**File:** {file_path}\n"

    if eventdata.get('targetUserName'):
        message += f"**Target User:** {eventdata['targetUserName']}\n"
    if eventdata.get('targetDomainName'):
        message += f"**Target Domain:** {eventdata['targetDomainName']}\n"
    if eventdata.get('subjectUserName'):
        message += f"**Subject User:** {eventdata['subjectUserName']}\n"
    if eventdata.get('memberName') or eventdata.get('memberSid'):
        member = eventdata.get('memberName', eventdata.get('memberSid', ''))
        message += f"**Member:** {member}\n"
    if eventdata.get('groupName') or eventdata.get('targetUserName'):
        group = eventdata.get('groupName', eventdata.get('targetUserName', ''))
        if group and group != eventdata.get('targetUserName'):
            message += f"**Group:** {group}\n"
    if win.get('system', {}).get('eventID'):
        message += f"**Event ID:** {win['system']['eventID']}\n"

    if data.get('dstuser'):
        message += f"**Target User:** {data['dstuser']}\n"
    if data.get('srcuser'):
        message += f"**Source User:** {data['srcuser']}\n"
    if data.get('command'):
        message += f"**Command:** {data['command'][:100]}\n"
    if data.get('tty'):
        message += f"**TTY:** {data['tty']}\n"

    message += f"**Details:** {full_log[:300]}\n"
    return message

@app.route('/webhook', methods=['POST'])
def webhook():
    alert = request.get_json()
    rule_id = alert.get('rule', {}).get('id', '')
    if rule_id in RULE_COMMANDS:
        message = format_alert(alert)
        asyncio.run_coroutine_threadsafe(
            send_discord_message(message, alert),
            bot.loop
        )
    return "OK", 200


### WAZUH API ###
def get_wazuh_token():
    global wazuh_token, token_expiry
    if token_expiry > time.time():
        return wazuh_token
    response = requests.post(
        f"{WAZUH_MANAGER_URL}/security/user/authenticate",
        auth=(WAZUH_USERNAME, WAZUH_PASSWORD),
        verify=False,
        params={"raw": "true"}
    )
    if response.status_code == 200:
        wazuh_token = response.text.strip('"')
        token_expiry = time.time() + 800
        return wazuh_token
    else:
        print(f"Failed to get token: {response.status_code}")
        return None

def send_active_response(agent_id, command, data):
    token = get_wazuh_token()
    if not token:
        return False
    response = requests.put(
        f"{WAZUH_MANAGER_URL}/active-response",
        params={"agents_list": agent_id},
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"command": command, "alert": {"data": data}},
        verify=False
    )
    return response.status_code == 200

if __name__ == '__main__':
    threading.Thread(target=run_bot, daemon=True).start()
    app.run(host='0.0.0.0', port=FLASK_PORT)
