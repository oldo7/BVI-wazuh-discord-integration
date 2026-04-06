from flask import Flask, request
import discord
import threading
import asyncio
import os
from dotenv import load_dotenv
from datetime import datetime

### DISCORD ###
# Setup
load_dotenv()
intents = discord.Intents.default()
intents.message_content = True
bot = discord.Client(intents=intents)
channel_id = None

@bot.event
async def on_ready():
    global channel_id
    for guild in bot.guilds:
        for channel in guild.text_channels:
            channel_id = channel.id
            print(f"Bot online and ready to send messages to #{channel.name}")
            return

def run_bot():
    bot.run(os.getenv('DISCORD_BOT_TOKEN'))

# Send message
async def send_discord_message(message):
    channel = bot.get_channel(channel_id)
    await channel.send(message)
    print(f"Discord message sent: {message}")


### FLASK ###
app = Flask(__name__)

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
        if group and group != eventdata.get('targetUserName'):  # Avoid duplicate
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
            send_discord_message(message), 
            bot.loop
        )
    
    return "OK", 200

if __name__ == '__main__':
    threading.Thread(target=run_bot, daemon=True).start()
    app.run(host='0.0.0.0', port=8000)