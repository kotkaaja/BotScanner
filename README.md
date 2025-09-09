# 🛡️ Lua Script Security Scanner Bot v2.0

Bot Discord cerdas generasi baru dengan sistem analis berlapis untuk menganalisis dan mendeteksi script Lua berbahaya secara akurat dan andal.

## ✨ Fitur Utama

### 🧠 Sistem Analis Berlapis & Cerdas
Bot menggunakan sistem fallback tiga tingkat untuk memastikan waktu aktif dan akurasi maksimum:
1.  **Analyst Utama (OpenAI)**: Menggunakan GPT-4o untuk analisis konteks terdalam.
2.  **Analyst Cadangan (Gemini)**: Jika OpenAI gagal (misalnya, karena kuota habis), bot secara otomatis beralih ke Google Gemini.
3.  **Analyst Manual**: Jika kedua AI gagal, bot akan kembali ke analisis berbasis pola bawaan.
Logika AI juga telah diperketat untuk secara agresif mendeteksi pencurian data dan memahami konteks script (misalnya, membedakan alat keamanan dari malware).

### 🕹️ Kontrol Penuh dengan Perintah
Selain mode unggah-dan- pindai otomatis, Anda dapat secara manual memilih analis yang akan digunakan dengan perintah `!scan`:
- `!scan openai` + file: Memaksa pemindaian dengan OpenAI.
- `!scan gemini` + file: Memaksa pemindaian dengan Gemini.
- `!scan manual` + file: Memaksa pemindaian dengan mode manual.

### 🔑 Dukungan Multi-API Key
Untuk ketahanan maksimum terhadap batas kuota, bot mendukung banyak API key untuk setiap layanan. Jika satu kunci mencapai batasnya, bot akan secara otomatis mencoba kunci berikutnya dalam daftar.

### 📁 Dukungan Format Luas
- **Script Tunggal**: `.lua`, `.txt`
- **Arsip**: `.zip`, `.7z`, `.rar` (ekstraksi dan pemindaian otomatis semua file di dalamnya)

### 🚨 Deteksi Pola Kontekstual
Mendeteksi 15+ pola berbahaya dan menggunakan AI untuk menentukan apakah penggunaannya wajar atau berbahaya dalam konteks tujuan script.

---
## 🚀 Pengaturan Cepat

### 1. Dapatkan Kode
```bash
# Fork atau clone repository ini
git clone [https://github.com/kotkaaja/BotScanner.git/](https://github.com/kotkaaja/BotScanner.git/)
cd lua-scanner-bot
2. Instal Ketergantungan
Pastikan file requirements.txt Anda sudah benar, lalu jalankan:

Bash

pip install -r requirements.txt
3. Konfigurasi Variabel Lingkungan
Bot sekarang dikonfigurasi sepenuhnya melalui Variabel Lingkungan di hosting Anda (misalnya, Railway, Heroku).

🔧 Konfigurasi
Variabel Lingkungan (Environment Variables)
Atur variabel-variabel berikut di dashboard hosting Anda.

Variabel	Deskripsi	Wajib?	Contoh Nilai
BOT_TOKEN	Token bot Discord Anda.	✅	MTA...
OPENAI_API_KEYS	Satu atau lebih API key OpenAI, dipisahkan koma.	✅ (Salah satu)	sk-...,sk-...
GEMINI_API_KEYS	Satu atau lebih API key Gemini, dipisahkan koma.	✅ (Salah satu)	AIza...,AIza...
ALLOWED_CHANNEL_IDS	Batasi bot ke channel tertentu. Pisahkan dengan koma untuk >1.	❌	12345...,98765...
ALERT_CHANNEL_ID	Channel khusus untuk notifikasi file berbahaya (Level 4).	❌	56789...

Ekspor ke Spreadsheet
Catatan: Bot memerlukan setidaknya satu API key, baik OPENAI_API_KEYS atau GEMINI_API_KEYS, untuk dapat berfungsi dengan analisis AI.

Izin Bot (Bot Permissions)
Bot memerlukan izin berikut di server Anda:

Membaca Pesan/Lihat Channel

Mengirim Pesan

Menyematkan Tautan

Melampirkan File

📖 Contoh Penggunaan
Mode Otomatis (Upload Langsung)
Cukup unggah file .lua, .txt, atau arsip (.zip, .7z, .rar) ke channel yang diizinkan. Bot akan otomatis memindai menggunakan sistem fallback (OpenAI → Gemini → Manual).

Mode Manual (Dengan Perintah)
Untuk memaksa penggunaan analis tertentu, gunakan perintah !scan saat mengunggah file.
Contoh: Tulis !scan gemini di kolom pesan, lalu unggah file Anda dalam pesan yang sama.

📊 Contoh Hasil
🟢 File Aman
Bot akan memberikan ringkasan yang dihasilkan AI tentang tujuan script, bahkan jika aman.

✅ AMAN
Tujuan Script: Library untuk mengelola koneksi HTTPS dan mendeteksi skrip berbahaya.
Ringkasan AI: Skrip ini berfungsi sebagai alat keamanan (anti-keylogger) yang sah...
🔴 File Berbahaya
Laporan akan menyoroti bahaya, menjelaskan tujuan jahatnya, dan mencantumkan pola yang terdeteksi.

🚨 BAHAYA TINGGI
Tujuan Script: Pencuri data (Keylogger).
Ringkasan AI: AI dengan keyakinan tinggi mengidentifikasi skrip ini sebagai keylogger. Skrip ini mengambil nama pemain, alamat server, dan input pengguna, lalu mengirimkannya ke Discord webhook. Ini adalah malware.

📝 Detail Pola Terdeteksi
📁 keylogger.lua (Line 25)
💡 Alasan: Discord webhook - sangat mungkin untuk mencuri data pengguna

Dianalisis oleh: OpenAI • 1 file