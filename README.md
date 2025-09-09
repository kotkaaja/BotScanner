
# 🛡️ Lua Script Security Scanner Bot v2.0

Bot Discord cerdas generasi baru dengan sistem analis berlapis untuk menganalisis dan mendeteksi script Lua berbahaya secara akurat dan andal.

---

## ✨ Fitur Utama

### 🧠 Sistem Analis Berlapis & Cerdas
Bot menggunakan sistem fallback tiga tingkat untuk memastikan waktu aktif dan akurasi maksimum:
1. **Analyst Utama (OpenAI)** → Analisis konteks terdalam.
2. **Analyst Cadangan (Gemini)** → Dipakai jika OpenAI gagal (misalnya kuota habis).
3. **Analyst Manual** → Jika kedua AI gagal, bot kembali ke analisis pola bawaan.

Logika AI diperketat untuk mendeteksi pencurian data secara agresif dan memahami konteks script (misalnya, membedakan alat keamanan dari malware).

### 🎯 4 Level Analisis Keamanan
- **🟢 Level 1 (SAFE)**: Script aman, tidak ada pola berbahaya
- **🟡 Level 2 (SUSPICIOUS)**: Mencurigakan tapi mungkin legitimate 
- **🟠 Level 3 (VERY SUSPICIOUS)**: Sangat mencurigakan (obfuscated/encoded)
- **🔴 Level 4 (DANGEROUS)**: Sangat berbahaya (data theft confirmed)

### 🕹️ Kontrol Penuh dengan Perintah
Selain mode unggah-dan-pindai otomatis, Anda dapat memilih analis manual dengan perintah `!scan`:
- `!scan openai` + file → Pakai OpenAI
- `!scan gemini` + file → Pakai Gemini
- `!scan manual` + file → Pakai mode manual
- `!scan auto` + file → Fallback otomatis (OpenAI → Gemini → Manual)

### 🔑 Dukungan Multi-API Key
Bot mendukung banyak API key untuk setiap layanan.  
Jika satu kunci mencapai limit, bot otomatis pindah ke kunci berikutnya.

### 📁 Dukungan Format Luas
- **Script tunggal**: `.lua`, `.txt`  
- **Arsip**: `.zip`, `.7z`, `.rar` (otomatis diekstrak & dipindai semua file)

### 🚨 Deteksi Pola Kontekstual
Bot mendeteksi **15+ pola berbahaya** dan memanfaatkan AI untuk memutuskan apakah penggunaan pola itu wajar atau berbahaya.

---

## 🚀 Pengaturan Cepat

### 🚨 Advanced Pattern Detection
Mendeteksi 15+ pola berbahaya termasuk:
- **Data Theft**: `discord.com/api/webhooks`, `sendToDiscordEmbed`
- **System Access**: `os.execute`, `os.remove`, `io.popen`
- **Player Data**: `sampGetPlayerNickname`, `sampGetCurrentServerAddress`
- **Obfuscation**: `loadstring`, `LuaObfuscator.com`, `eval`
- **Network**: `socket.http`, `http.request`, `http://`

---
## 📊 Contoh Hasil Scan

Jika Anda mengunggah file `stealer.lua`, bot akan merespons seperti ini:

### Mode Auto (OpenAI → fallback jika gagal)

**🔍 Hasil Analisis File:** `stealer.lua`

- **Deteksi Pola**:  
  - `sampGetPlayerNickname` ✅  
  - `sampGetCurrentServerAddress` ✅  
  - `os.execute` (akses sistem) ✅  

- **Kesimpulan AI**:  
  Script mencoba **mengambil nickname + IP server**, lalu mengirim ke server eksternal.  
  → **Ini terindikasi sebagai pencurian data (MALICIOUS).**

**📢 Rekomendasi:**  
Hapus file ini segera. Jangan jalankan di environment lokal Anda.

---



## 🚀 Quick Setup

### 1. Clone Repository
```bash
git clonehttps://github.com/kotkaaja/BotScanner.git
cd BotScanner
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

Bot ini memakai **environment variables** untuk semua setting.  
Bisa diatur lewat `.env` file (lokal) atau langsung di dashboard hosting.

### 1. File `.env` (opsional untuk development)
Buat file `.env` di root project:

```env
BOT_TOKEN=your_discord_bot_token_here
OPENAI_API_KEYS=sk-xxx,sk-yyy
GEMINI_API_KEYS=AIza-xxx,AiZa-yyy
ALLOWED_CHANNEL_IDS=1234567890,9876543210
ALERT_CHANNEL_ID=1122334455


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
