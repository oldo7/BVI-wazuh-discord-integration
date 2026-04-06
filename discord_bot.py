import discord
from discord.ext import commands
import os
from dotenv import load_dotenv

load_dotenv()

# Bot setup
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

# Store channel ID for sending messages
target_channel_id = None

@bot.event
async def on_ready():
    print(f'✅ Bot is online! Logged in as {bot.user}')
    
    # Find a channel to send messages to (uses first text channel it finds)
    global target_channel_id
    for guild in bot.guilds:
        for channel in guild.text_channels:
            target_channel_id = channel.id
            print(f"📢 Will send messages to: #{channel.name} in server {guild.name}")
            break
        if target_channel_id:
            break

# Function to send message (called from your Flask script)
async def send_message_to_discord(content):
    if target_channel_id:
        channel = bot.get_channel(target_channel_id)
        if channel:
            await channel.send(content)
            print(f"✅ Message sent: {content}")
        else:
            print("❌ Channel not found")
    else:
        print("❌ No channel found - bot not ready yet")

# Run the bot
if __name__ == "__main__":
    # Get token from .env file or environment variable
    token = os.getenv('DISCORD_BOT_TOKEN')
    if not token:
        print("❌ DISCORD_BOT_TOKEN not found in .env file")
    else:
        bot.run(token)