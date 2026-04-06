from flask import Flask, request
import discord
import threading
import asyncio
import os
from dotenv import load_dotenv

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
#Flask setup
app = Flask(__name__)

# Request handling
@app.route('/webhook', methods=['POST'])
def webhook():
    # TODO: create message based on messages
    alert = request.get_json()
    print("============ NEW ALERT ==========")
    print(alert)
    asyncio.run_coroutine_threadsafe(send_discord_message("alert"), bot.loop) #asyncio.create_task equivalent across threads
    return "OK", 200



if __name__ == '__main__':
    # Run discord bot loop in new thread
    threading.Thread(target=run_bot, daemon=True).start()

    # Run Flask loop
    app.run(host='0.0.0.0', port=8000)