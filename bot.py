import discord
import os
import zipfile
import shutil
import re
import json
import asyncio
from typing import List, Tuple, Dict
import py7zr
import rarfile
from openai import AsyncOpenAI
import time

# --- Konfigurasi ---
BOT_TOKEN = os.getenv("BOT_TOKEN")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY") or os.getenv("GEMINI_API_KEY")
ALERT_CHANNEL_ID = os.getenv("ALERT_CHANNEL_ID")
ALLOWED_CHANNEL_IDS = os.getenv("ALLOWED_CHANNEL_IDS")

ALLOWED_EXTENSIONS = ['.lua', '.txt', '.zip', '.7z', '.rar']
TEMP_DIR = "temp_scan"
ZIP_COOLDOWN_SECONDS = 180
zip_cooldowns = {}

# --- Validasi Konfigurasi Awal ---
print("🔧 Loading environment variables...")
if not BOT_TOKEN:
    print("FATAL ERROR: BOT_TOKEN environment variable not found.")
    exit()
if not OPENAI_API_KEY:
    print("FATAL ERROR: OPENAI_API_KEY or GEMINI_API_KEY environment variable not found.")
    exit()

if ALERT_CHANNEL_ID:
    try:
        ALERT_CHANNEL_ID = int(ALERT_CHANNEL_ID)
        print(f"✅ Alert channel set: {ALERT_CHANNEL_ID}")
    except ValueError:
        ALERT_CHANNEL_ID = None
else:
    print("ℹ️ ALERT_CHANNEL_ID not set. Alert notifications disabled.")

parsed_channel_ids = []
if ALLOWED_CHANNEL_IDS:
    try:
        parsed_channel_ids = [int(channel_id.strip()) for channel_id in ALLOWED_CHANNEL_IDS.split(',')]
        print(f"✅ Bot is restricted to channel(s): {parsed_channel_ids}")
    except ValueError:
        print("FATAL ERROR: ALLOWED_CHANNEL_IDS contains invalid values.")
        exit()
else:
    print("⚠️ WARNING: ALLOWED_CHANNEL_IDS is not set. Bot will respond in all channels.")
ALLOWED_CHANNEL_IDS = parsed_channel_ids

# --- Inisialisasi Klien AI ---
try:
    print("🤖 Initializing OpenAI client...")
    openai_client = AsyncOpenAI(api_key=OPENAI_API_KEY)
    print("✅ OpenAI client initialized successfully.")
except Exception as e:
    print(f"FATAL ERROR: Failed to initialize OpenAI client: {e}")
    exit()

# --- Sistem Level Bahaya & Pola ---
class DangerLevel:
    SAFE, SUSPICIOUS, VERY_SUSPICIOUS, DANGEROUS = 1, 2, 3, 4

SUSPICIOUS_PATTERNS = {
    "discord.com/api/webhooks": {"level": DangerLevel.DANGEROUS, "description": "Discord webhook - sangat mungkin untuk mencuri data pengguna"},
    "pastebin.com": {"level": DangerLevel.DANGEROUS, "description": "Upload ke Pastebin - kemungkinan besar untuk mengirim data curian"},
    "hastebin.com": {"level": DangerLevel.DANGEROUS, "description": "Upload ke Hastebin - kemungkinan besar untuk mengirim data curian"},
    "loadstring": {"level": DangerLevel.VERY_SUSPICIOUS, "description": "Eksekusi kode dinamis - sangat berbahaya jika berisi kode tersembunyi"},
    "LuaObfuscator.com": {"level": DangerLevel.VERY_SUSPICIOUS, "description": "Kode yang diobfuscate - menyembunyikan fungsi sebenarnya"},
    "dofile": {"level": DangerLevel.VERY_SUSPICIOUS, "description": "Menjalankan file eksternal - berbahaya jika file tidak diketahui"},
    "io.open": {"level": DangerLevel.SUSPICIOUS, "description": "Membuka/membuat file - bisa legitimate untuk konfigurasi"},
    "os.execute": {"level": DangerLevel.SUSPICIOUS, "description": "Menjalankan perintah sistem - berbahaya jika tidak untuk fungsi legitimate"},
    "socket.http": {"level": DangerLevel.SUSPICIOUS, "description": "Komunikasi HTTP - bisa legitimate untuk API atau update"},
    "http.request": {"level": DangerLevel.SUSPICIOUS, "description": "Request HTTP - bisa legitimate untuk komunikasi API"},
    "sampGetPlayerNickname": {"level": DangerLevel.SUSPICIOUS, "description": "Mengambil nickname pemain - bisa legitimate untuk fitur game"},
    "sampGetCurrentServerAddress": {"level": DangerLevel.SUSPICIOUS, "description": "Mengambil alamat server - bisa legitimate untuk fitur reconnect"},
    "io.popen": {"level": DangerLevel.SUSPICIOUS, "description": "Membuka proses eksternal - berbahaya jika tidak untuk fungsi legitimate"},
    "os.remove": {"level": DangerLevel.SUSPICIOUS, "description": "Menghapus file - bisa legitimate untuk cleanup"},
    "os.rename": {"level": DangerLevel.SUSPICIOUS, "description": "Mengubah nama file - bisa legitimate untuk manajemen file"}
}

# --- Fungsi Analisis AI ---
async def analyze_with_ai(code_snippet: str, detected_patterns: List[str], file_name: str) -> Dict:
    try:
        prompt = f"""
        Anda adalah seorang ahli keamanan siber Lua yang sangat tegas dan tidak mentolerir pencurian data. Analisis skrip Lua berikut dengan nama file '{file_name}'.
        ATURAN UTAMA ANDA:
        1.  **PRIORITAS #1: DETEKSI PENCURIAN DATA.** Jika Anda melihat kombinasi apapun dari fungsi pengumpul data (`sampGetPlayerNickname`, `sampGetCurrentServerAddress`, dll.) DENGAN fungsi pengiriman data (`discord.com/api/webhooks`, `http.request`), Anda HARUS mengklasifikasikannya sebagai **DANGEROUS (Level 4)**. Tidak ada pengecualian.
        2.  **ANALISIS KONTEKS FUNGSI.** Untuk setiap pola mencurigakan yang terdeteksi, tentukan apakah itu relevan dengan tujuan utama skrip. Jika sebuah skrip modifikasi mobil sederhana tiba-tiba memiliki webhook, itu adalah **DANGEROUS (Level 4)**. Namun, jika skrip konfigurasi menggunakan `io.open` untuk menyimpan pengaturan, itu **SAFE (Level 1)**.
        3.  **IDENTIFIKASI ALAT KEAMANAN.** Jika skrip justru MEMBLOKIR atau MENDETEKSI pola berbahaya, itu adalah **SAFE (Level 1)**.
        4.  **BERIKAN ANALISIS UNTUK SEMUA FILE.** Meskipun tidak ada pola mencurigakan, tetap berikan analisis singkat tentang tujuan skrip.
        Berikut adalah isi skripnya:
        ```lua
        {code_snippet[:3500]}
        ```
        Berikan jawaban HANYA dalam format JSON berikut:
        {{
            "danger_level": <1-4>,
            "script_purpose": "Deskripsi singkat dan jelas mengenai tujuan utama skrip ini.",
            "analysis_summary": "Penjelasan ringkas mengapa skrip ini aman atau berbahaya, berdasarkan ATURAN UTAMA Anda."
        }}
        """
        response = await openai_client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are an extremely strict Lua cybersecurity analyst. Your primary directive is to detect data theft. You must adhere to the main rules provided by the user. Respond ONLY in the requested JSON format."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.0
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        print(f"AI Analysis error: {e}")
        return {"danger_level": 2, "script_purpose": "Tidak dapat dianalisis oleh AI.", "analysis_summary": f"Analisis AI gagal: {str(e)}"}

# --- Fungsi Utilitas & Scanner ---
def extract_archive(file_path: str, extract_to: str) -> bool:
    try:
        # --- BLOK INI TELAH DIPERBAIKI ---
        if file_path.endswith('.zip'):
            with zipfile.ZipFile(file_path, 'r') as z:
                z.extractall(extract_to)
        elif file_path.endswith('.7z'):
            with py7zr.SevenZipFile(file_path, mode='r') as z:
                z.extractall(extract_to)
        elif file_path.endswith('.rar'):
            with rarfile.RarFile(file_path) as z:
                z.extractall(extract_to)
        return True
    except Exception as e:
        print(f"Error extracting {file_path}: {e}")
        return False

async def scan_file_content(file_path: str) -> Tuple[List[Dict], Dict]:
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f: content = f.read()
        
        detected_issues = []
        for pattern, info in SUSPICIOUS_PATTERNS.items():
            for match in re.finditer(pattern, content, re.IGNORECASE):
                detected_issues.append({
                    'pattern': pattern,
                    'line': content[:match.start()].count('\n') + 1,
                    'description': info['description']
                })

        detected_patterns_for_ai = list(dict.fromkeys(issue['pattern'] for issue in detected_issues))
        file_name = os.path.basename(file_path)
        ai_summary = await analyze_with_ai(content, detected_patterns_for_ai, file_name)
        return detected_issues, ai_summary
    except Exception as e:
        print(f"Error scanning file {file_path}: {e}")
        return [], {}

# --- Bot Discord ---
intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)

def get_level_emoji_color(level: int) -> Tuple[str, int]:
    if level == DangerLevel.SAFE: return "🟢", 0x00FF00
    if level == DangerLevel.SUSPICIOUS: return "🟡", 0xFFFF00
    if level == DangerLevel.VERY_SUSPICIOUS: return "🟠", 0xFF8C00
    return "🔴", 0xFF0000

@client.event
async def on_ready():
    print(f'🤖 Bot scanner siap! Login sebagai {client.user}')
    if not os.path.exists(TEMP_DIR): os.makedirs(TEMP_DIR)

@client.event
async def on_message(message):
    if message.author == client.user: return
    if ALLOWED_CHANNEL_IDS and message.channel.id not in ALLOWED_CHANNEL_IDS: return
    if not message.attachments: return

    attachment = message.attachments[0]
    file_extension = os.path.splitext(attachment.filename)[1].lower()

    if file_extension not in ALLOWED_EXTENSIONS:
        await message.reply(f"❌ **Format File Tidak Didukung**: `{attachment.filename}`.")
        return

    processing_message, download_path = None, os.path.join(TEMP_DIR, attachment.filename)
    try:
        if file_extension in ['.zip', '.7z', '.rar']:
            user_id = message.author.id
            current_time = time.time()
            if user_id in zip_cooldowns and (current_time - zip_cooldowns[user_id]) < ZIP_COOLDOWN_SECONDS:
                remaining_time = int(ZIP_COOLDOWN_SECONDS - (current_time - zip_cooldowns[user_id]))
                await message.reply(f"⏳ **Cooldown Aktif**. Harap tunggu **{remaining_time} detik** lagi.")
                return
            zip_cooldowns[user_id] = current_time
            processing_message = await message.reply(f"⚙️ **Menganalisis Arsip...** File `{attachment.filename}` sedang diproses.")

        await attachment.save(download_path)
        all_issues, scanned_files, all_ai_summaries = [], [], []
        
        scan_paths = []
        extract_folder = os.path.join(TEMP_DIR, "extracted")
        if file_extension in ['.zip', '.7z', '.rar']:
            if extract_archive(download_path, extract_folder):
                for root, _, files in os.walk(extract_folder):
                    for file in files:
                        if file.endswith(('.lua', '.txt')):
                            scan_paths.append((os.path.join(root, file), os.path.relpath(os.path.join(root, file), extract_folder)))
            else: raise Exception(f"Gagal mengekstrak `{attachment.filename}`.")
        else:
            scan_paths.append((download_path, attachment.filename))

        for file_path, display_name in scan_paths:
            issues, ai_summary = await scan_file_content(file_path)
            scanned_files.append(display_name)
            if issues: all_issues.extend([(display_name, issue) for issue in issues])
            if ai_summary: all_ai_summaries.append(ai_summary)
        
        if os.path.exists(extract_folder): shutil.rmtree(extract_folder)

        best_summary = max(all_ai_summaries, key=lambda x: x.get('danger_level', 0), default={})
        max_level = best_summary.get('danger_level', DangerLevel.SAFE)
        emoji, color = get_level_emoji_color(max_level)
        embed = discord.Embed(color=color)
        
        level_titles = {
            DangerLevel.SAFE: "✅ AMAN", DangerLevel.SUSPICIOUS: "🤔 MENCURIGAKAN",
            DangerLevel.VERY_SUSPICIOUS: "⚠️ SANGAT MENCURIGAKAN", DangerLevel.DANGEROUS: "🚨 BAHAYA TINGGI"
        }
        embed.title = f"{emoji} **{level_titles.get(max_level, 'HASIL SCAN')}**"
        embed.description = (f"**Tujuan Script:** {best_summary.get('script_purpose', 'N/A')}\n"
                           f"**Ringkasan AI:** {best_summary.get('analysis_summary', 'N/A')}")

        if all_issues:
            field_value = ""
            for filepath, issue in all_issues[:4]:
                field_value += f"📁 `{filepath}` (Line {issue['line']})\n"
                field_value += f"🔍 **Pattern:** `{issue['pattern']}`\n"
                field_value += f"💡 **Alasan:** {issue['description']}\n\n"

            if len(all_issues) > 4:
                field_value += f"... dan {len(all_issues) - 4} lainnya."
            embed.add_field(name="📝 Detail Pola Terdeteksi", value=field_value.strip(), inline=False)
        
        embed.set_footer(text=f"Dipindai oleh Lua Security Bot • {len(scanned_files)} file dianalisis")
        
        if processing_message: await processing_message.edit(content=None, embed=embed)
        else: await message.reply(embed=embed)
        
        if max_level >= DangerLevel.DANGEROUS and ALERT_CHANNEL_ID:
            try:
                alert_channel = client.get_channel(ALERT_CHANNEL_ID)
                if alert_channel: await alert_channel.send(f"🚨 **Peringatan Keamanan** oleh {message.author.mention} di {message.channel.mention}", embed=embed)
            except Exception as e: print(f"Gagal mengirim alert: {e}")

    except Exception as e:
        error_message = f"❌ Terjadi error saat memindai file: {str(e)}"
        if processing_message: await processing_message.edit(content=error_message, embed=None)
        else: await message.reply(error_message)
    finally:
        if os.path.exists(download_path): os.remove(download_path)

# --- Jalankan Bot ---
if __name__ == "__main__":
    print("🚀 Memulai Lua Security Scanner Bot...")
    client.run(BOT_TOKEN)