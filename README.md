# 🛡️ Lua Script Security Scanner Bot

Bot Discord canggih untuk menganalisis dan mendeteksi script Lua yang berbahaya, khususnya untuk script SAMP (San Andreas Multiplayer) dan Moonloader.

## ✨ Fitur Utama

### 🎯 4 Level Analisis Keamanan
- **🟢 Level 1 (SAFE)**: Script aman, tidak ada pola berbahaya
- **🟡 Level 2 (SUSPICIOUS)**: Mencurigakan tapi mungkin legitimate 
- **🟠 Level 3 (VERY SUSPICIOUS)**: Sangat mencurigakan (obfuscated/encoded)
- **🔴 Level 4 (DANGEROUS)**: Sangat berbahaya (data theft confirmed)

### 🤖 AI-Powered Analysis
- Menggunakan OpenAI GPT-4 untuk analisis konteks
- Membedakan antara penggunaan legitimate vs malicious
- Deteksi kombinasi pattern berbahaya

### 📁 Support Multiple Format
- ✅ `.lua`, `.txt` (script files)
- ✅ `.zip`, `.7z`, `.rar` (archive files)
- Ekstraksi otomatis dan scan mendalam

### 🚨 Advanced Pattern Detection
Mendeteksi 15+ pola berbahaya termasuk:
- **Data Theft**: `discord.com/api/webhooks`, `sendToDiscordEmbed`
- **System Access**: `os.execute`, `os.remove`, `io.popen`
- **Player Data**: `sampGetPlayerNickname`, `sampGetCurrentServerAddress`
- **Obfuscation**: `loadstring`, `LuaObfuscator.com`, `eval`
- **Network**: `socket.http`, `http.request`, `http://`

## 🚀 Quick Setup

### 1. Clone Repository
```bash
git clone https://github.com/yourusername/lua-scanner-bot
cd lua-scanner-bot
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configuration
```bash
# Copy environment file
cp .env.example .env

# Edit dengan token dan API key Anda
nano .env
```

### 4. Run Locally
```bash
python bot.py
```

## 🚂 Railway Deployment

### 1. Connect GitHub ke Railway
1. Fork repository ini
2. Buka [Railway.app](https://railway.app)
3. Klik "Deploy from GitHub"
4. Pilih repository yang di-fork

### 2. Set Environment Variables
Di Railway dashboard, tambahkan variables:
```
BOT_TOKEN=your_discord_bot_token
OPENAI_API_KEY=your_openai_api_key
ALERT_CHANNEL_ID=your_channel_id (optional)
```

### 3. Deploy
Railway akan otomatis build dan deploy bot Anda!

## 🔧 Configuration

### Environment Variables
| Variable | Description | Required |
|----------|-------------|----------|
| `BOT_TOKEN` | Discord Bot Token | ✅ |
| `OPENAI_API_KEY` | OpenAI API Key untuk AI analysis | ✅ |
| `ALERT_CHANNEL_ID` | Channel ID untuk alert file berbahaya | ❌ |

### Bot Permissions
Bot memerlukan permissions:
- `Read Messages`
- `Send Messages`
- `Embed Links`
- `Attach Files`

## 📖 Usage Examples

### Scan Single File
Upload file `.lua` atau `.txt` ke channel dimana bot aktif.

### Scan Archive
Upload file `.zip`, `.7z`, atau `.rar` berisi multiple script.

### Response Examples

#### 🟢 Safe File
```
✅ Hasil Scan: script.lua
File Aman - Tidak ditemukan pola berbahaya
📊 Files Scanned: 1 file(s)
```

#### 🔴 Dangerous File
```
🔴 Hasil Scan: malware.lua
🚨 BAHAYA TINGGI - File mengandung kode berbahaya yang dapat mencuri data!

🔴 Sangat Berbahaya
📁 script.lua (Line 15)
🔍 Pattern: discord.com/api/webhooks
💡 Discord webhook - sangat mungkin untuk mencuri data pengguna
```

## 🧠 AI Analysis Features

### Smart Context Detection
```lua
-- AMAN (AI detects legitimate usage)
local config = io.open('moonloader/config.txt', '"# BotScanner" 
