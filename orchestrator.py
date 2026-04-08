from flask import Flask, request
import discord
import threading
import asyncio
import os
import requests
import time
from dotenv import load_dotenv
from datetime import datetime

### DISCORD ###
# Setup
load_dotenv()
intents = discord.Intents.default()
intents.message_content = True
bot = discord.Client(intents=intents)
channel_id = None

# Alert <-> message mapping
alert_store = {}

# Wazuh API config
WAZUH_MANAGER_URL = os.getenv('WAZUH_MANAGER_URL')
WAZUH_USERNAME = os.getenv('WAZUH_USERNAME')
WAZUH_PASSWORD = os.getenv('WAZUH_PASSWORD')

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


# Receive message
@bot.event
async def on_message(message):
    if message.author == bot.user:
        return
    
    # check if reply
    if message.reference and message.reference.message_id:
        original_msg_id = str(message.reference.message_id)
        
        # Check if the original message was sent by the bot
        try:
            original_msg = await message.channel.fetch_message(message.reference.message_id)
            if original_msg.author == bot.user:
                handle_command(original_msg_id, message.content)
        except:
            pass

def run_bot():
    bot.run(os.getenv('DISCORD_BOT_TOKEN'))

# Send message
async def send_discord_message(message, alert_data=None):
    channel = bot.get_channel(channel_id)
    sent_msg = await channel.send(message)
    print(f"Discord message sent: {message}")
    
    if alert_data:
        alert_store[str(sent_msg.id)] = alert_data

### FLASK ###
app = Flask(__name__)

# Handle commands from Discord replies
def handle_command(original_msg_id, command):
    alert = alert_store[original_msg_id]
    del alert_store[original_msg_id]
    print(f"Command received: {command}")
    cmd = command.strip().lower()

    # Extract attacker IP and agent on which the alert occured
    src_ip = alert.get('data', {}).get('srcip', '')
    agent_id = alert.get('agent', {}).get('id', '')
    if cmd == "block":
        if src_ip and agent_id:
            result = block_ip(agent_id, src_ip)
    elif cmd == "blockuser":
        dstuser = alert.get('data', {}).get('dstuser', '')
        if dstuser and agent_id:
            result = block_ssh_user(agent_id, dstuser)
    elif cmd == "logout":
        src_ip = alert.get('data', {}).get('srcip', '')
        if src_ip and agent_id:
            result = logout_ssh(agent_id, src_ip)
            print(result)
    elif cmd == "log":
        src_ip = alert.get('data', {}).get('srcip', '')
        if src_ip and agent_id:
            result = log_attacker(agent_id, src_ip)
    else:
        print(f"Unknown command: {cmd}")

# Extract data from alert and format incoming alert for discord
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
    
    # Build message
    message = f"**======= Wazuh Alert =======**\n"
    message += f"{timestamp}\n"
    message += f"**Level:** {level}\n"
    message += f"**Rule:** {description}\n"
    message += f"**Agent:** {agent_name} ({agent_ip})\n"
    
    if src_ip:
        message += f"**Source IP:** {src_ip}\n"
    
    if file_path:
        message += f"**File:** {file_path}\n"
    
    # windows specific fields
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
    
    # linux specific fields
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
    
    # Only process level 7+ alerts (this will be configurable)
    if alert.get('rule', {}).get('level', 0) >= 7:
        message = format_alert(alert)
        #asyncio.create_task equivalent across threads
        asyncio.run_coroutine_threadsafe(
            send_discord_message(message, alert), 
            bot.loop
        )
    
    return "OK", 200


### WAZUH API ###
def get_wazuh_token():
    global wazuh_token, token_expiry
    # Reuse token if still valid
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
        # Refresh every 15 minutes
        token_expiry = time.time() + 800
        return wazuh_token
    else:
        print(f"Failed to get token: {response.status_code}")
        return None


def block_ip(agent_id, ip_address, timeout=120):
    token = get_wazuh_token()
    if not token:
        return False
    
    url = f"{WAZUH_MANAGER_URL}/active-response"
    params = {"agents_list": agent_id}
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "command": "!custom-command",
        "alert": {
            "data": {
                "srcip": ip_address,
                "timeout": timeout
            }
        }
    }
    
    response = requests.put(
        url,
        params=params,
        headers=headers,
        json=payload,
        verify=False
    )

    return response.status_code == 200

def block_ssh_user(agent_id, username):
    token = get_wazuh_token()
    if not token:
        return False
    
    payload = {
        "command": "!block-ssh-user",
        "alert": {
            "data": {
                "username": username
            }
        }
    }
    
    response = requests.put(
        f"{WAZUH_MANAGER_URL}/active-response",
        params={"agents_list": agent_id},
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json=payload,
        verify=False
    )
    
    return response.status_code == 200

def logout_ssh(agent_id, src_ip):
    token = get_wazuh_token()
    if not token:
        return False
    
    payload = {
        "command": "!logout-ssh",
        "alert": {
            "data": {
                "srcip": src_ip
            }
        }
    }
    
    response = requests.put(
        f"{WAZUH_MANAGER_URL}/active-response",
        params={"agents_list": agent_id},
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json=payload,
        verify=False
    )
    
    return response.status_code == 200

def log_attacker(agent_id, src_ip):
    token = get_wazuh_token()
    if not token:
        return False
    
    payload = {
        "command": "!log-attacker",
        "alert": {
            "data": {
                "srcip": src_ip
            }
        }
    }
    
    response = requests.put(
        f"{WAZUH_MANAGER_URL}/active-response",
        params={"agents_list": agent_id},
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json=payload,
        verify=False
    )
    
    return response.status_code == 200

if __name__ == '__main__':
    threading.Thread(target=run_bot, daemon=True).start()
    app.run(host='0.0.0.0', port=8000)