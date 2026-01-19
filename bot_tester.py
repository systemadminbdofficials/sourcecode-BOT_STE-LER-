from telegram.ext import Application

TOKEN = "YOUR BOT TOKEN FOR TEST CONNECT"

app = Application.builder().token(TOKEN).build()

print("Telegram API connected ✅")
