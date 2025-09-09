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

ALLOWED_EXTENSIONS = ['.lua', '.txt', '.zip', '.7z', '.rar']
TEMP_DIR = "temp_scan"
ZIP_COOLDOWN_SECONDS = 180  # Cooldown 3 menit (180 detik)
zip_cooldowns = {} # Dictionary untuk melacak waktu submit terakhir user

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
        print("WARNING: ALERT_CHANNEL_ID is not a valid integer. Disabling alerts.")
        ALERT_CHANNEL_ID = None
else:
    print("ℹ️ ALERT_CHANNEL_ID not set. Alert notifications disabled.")

# --- Inisialisasi Klien AI ---
try:
    print("🤖 Initializing OpenAI client...")
    openai_client = AsyncOpenAI(api_key=OPENAI_API_KEY)
    print("✅ OpenAI client initialized successfully.")
except Exception as e:
    print(f"FATAL ERROR: Failed to initialize OpenAI client: {e}")
    exit()

# --- Sistem Level Bahaya ---
class DangerLevel:
    SAFE = 1
    SUSPICIOUS = 2
    VERY_SUSPICIOUS = 3
    DANGEROUS = 4

# --- Pola-pola Berbahaya ---
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

# --- Fungsi Analisis AI yang Ditingkatkan ---
async def analyze_with_ai(code_snippet: str, detected_patterns: List[str], file_name: str) -> Dict:
    """Menggunakan OpenAI GPT untuk analisis konteks, tujuan, dan keamanan script."""
    try:
        prompt = f"""
        Anda adalah seorang ahli keamanan siber dan programmer Lua senior. Analisis skrip Lua berikut dengan nama file '{file_name}'.

        Tugas Anda adalah:
        1.  **Identifikasi Tujuan Utama Skrip**: Apa fungsi utama dari skrip ini? (contoh: 'anti-cheat', 'manajemen UI', 'menyimpan konfigurasi pemain', 'fitur admin', 'backdoor/pencuri data').
        2.  **Analisis Kontekstual**: Berdasarkan tujuan utama skrip, evaluasi pola-pola yang terdeteksi ini: `{', '.join(detected_patterns) if detected_patterns else 'Tidak ada'}`. Apakah penggunaan fungsi-fungsi tersebut wajar untuk tujuan skrip? Contoh: `io.open` wajar jika tujuannya untuk menyimpan konfigurasi, tapi sangat mencurigakan jika tujuannya adalah fitur UI sederhana.
        3.  **Tentukan Level Bahaya**: Berikan skor bahaya dari 1 (Aman) hingga 4 (Sangat Berbahaya) berdasarkan analisis kontekstual Anda.
        4.  **Berikan Ringkasan**: Jelaskan analisis Anda dalam beberapa kalimat yang mudah dimengerti.

        Berikut adalah isi skripnya (dibatasi hingga 3000 karakter):
        ```lua
        {code_snippet[:3000]}
        ```

        Mohon berikan jawaban HANYA dalam format JSON berikut:
        {{
            "danger_level": <1-4>,
            "script_purpose": "Deskripsi singkat dan jelas mengenai tujuan utama skrip ini.",
            "analysis_summary": "Penjelasan ringkas mengapa skrip ini aman atau berbahaya, dengan mempertimbangkan konteks penggunaannya.",
            "is_legitimate": <true/false>
        }}
        """
        
        response = await openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a senior Lua script cybersecurity analyst. Your goal is to determine the script's purpose and analyze suspicious patterns within that context. Respond ONLY in the requested JSON format."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.2
        )
        
        ai_response_content = response.choices[0].message.content
        return json.loads(ai_response_content)
        
    except Exception as e:
        print(f"AI Analysis error: {e}")
        return {
            "danger_level": 2,
            "script_purpose": "Tidak dapat dianalisis oleh AI.",
            "analysis_summary": f"Analisis AI gagal. Error: {str(e)}",
            "is_legitimate": False
        }

# --- Fungsi Utilitas Ekstraksi ---
def extract_archive(file_path: str, extract_to: str) -> bool:
    """Mengekstrak berbagai format arsip."""
    try:
        if file_path.endswith('.zip'):
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(extract_to)
        elif file_path.endswith('.7z'):
            with py7zr.SevenZipFile(file_path, mode='r') as z:
                z.extractall(extract_to)
        elif file_path.endswith('.rar'):
            with rarfile.RarFile(file_path) as rf:
                rf.extractall(extract_to)
        return True
    except Exception as e:
        print(f"Error extracting {file_path}: {e}")
        return False

# --- Fungsi Scanner Inti ---
async def scan_file_content(file_path: str) -> Tuple[List[Dict], str, Dict]:
    """Memindai konten file dan menganalisisnya dengan AI. Mengembalikan (issues, content, ai_summary)."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        detected_issues = []
        detected_patterns_for_ai = []
        ai_summary = {}

        for pattern, info in SUSPICIOUS_PATTERNS.items():
            if re.search(pattern, content, re.IGNORECASE):
                detected_patterns_for_ai.append(pattern)
                matches = list(re.finditer(pattern, content, re.IGNORECASE))
                for match in matches:
                    start = max(0, match.start() - 100)
                    end = min(len(content), match.end() + 100)
                    context = content[start:end]
                    detected_issues.append({
                        'pattern': pattern,
                        'level': info['level'],
                        'description': info['description'],
                        'context': context.strip(),
                        'line': content[:match.start()].count('\n') + 1
                    })
        
        if detected_patterns_for_ai:
            file_name = os.path.basename(file_path)
            ai_summary = await analyze_with_ai(content, detected_patterns_for_ai, file_name)
        
        return detected_issues, content, ai_summary
        
    except Exception as e:
        print(f"Error scanning file {file_path}: {e}")
        return [], "", {}

# --- Bot Discord ---
intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)

def get_level_emoji_color(level: int) -> Tuple[str, int]:
    """Mengembalikan emoji dan warna untuk level bahaya."""
    if level == DangerLevel.SAFE: return "🟢", 0x00FF00
    if level == DangerLevel.SUSPICIOUS: return "🟡", 0xFFFF00
    if level == DangerLevel.VERY_SUSPICIOUS: return "🟠", 0xFF8C00
    return "🔴", 0xFF0000

@client.event
async def on_ready():
    print(f'🤖 Bot scanner siap! Login sebagai {client.user}')
    if not os.path.exists(TEMP_DIR):
        os.makedirs(TEMP_DIR)

@client.event
async def on_message(message):
    if message.author == client.user or not message.attachments:
        return

    attachment = message.attachments[0]
    file_extension = os.path.splitext(attachment.filename)[1].lower()

    if file_extension not in ALLOWED_EXTENSIONS:
        await message.channel.send(f"❌ **Format File Tidak Didukung**: `{attachment.filename}`.\n✅ Format yang didukung: `{', '.join(ALLOWED_EXTENSIONS)}`")
        return

    processing_message = None
    download_path = os.path.join(TEMP_DIR, attachment.filename)

    try:
        # Logika Cooldown dan Notifikasi Proses untuk file arsip
        if file_extension in ['.zip', '.7z', '.rar']:
            user_id = message.author.id
            current_time = time.time()

            if user_id in zip_cooldowns and (current_time - zip_cooldowns[user_id]) < ZIP_COOLDOWN_SECONDS:
                remaining_time = int(ZIP_COOLDOWN_SECONDS - (current_time - zip_cooldowns[user_id]))
                await message.channel.send(f"⏳ **Cooldown Aktif**. Harap tunggu **{remaining_time} detik** lagi sebelum mengirim arsip baru.")
                return
            
            zip_cooldowns[user_id] = current_time
            processing_message = await message.channel.send(f"⚙️ **Memproses Arsip...** File `{attachment.filename}` sedang dianalisis. Ini mungkin perlu beberapa saat.")

        await attachment.save(download_path)
        
        all_issues = []
        scanned_files = []
        all_ai_summaries = []
        
        # Proses file arsip atau file tunggal
        if file_extension in ['.zip', '.7z', '.rar']:
            extract_folder = os.path.join(TEMP_DIR, "extracted")
            if extract_archive(download_path, extract_folder):
                for root, _, files in os.walk(extract_folder):
                    for file in files:
                        if file.endswith(('.lua', '.txt')):
                            file_path = os.path.join(root, file)
                            issues, content, ai_summary = await scan_file_content(file_path)
                            relative_path = os.path.relpath(file_path, extract_folder)
                            scanned_files.append(relative_path)
                            if issues:
                                all_issues.extend([(relative_path, issue) for issue in issues])
                            if ai_summary:
                                all_ai_summaries.append(ai_summary)
                shutil.rmtree(extract_folder)
            else:
                raise Exception(f"Gagal mengekstrak `{attachment.filename}`. File mungkin rusak atau terproteksi.")
        else:
            issues, content, ai_summary = await scan_file_content(download_path)
            scanned_files.append(attachment.filename)
            if issues:
                all_issues.extend([(attachment.filename, issue) for issue in issues])
            if ai_summary:
                all_ai_summaries.append(ai_summary)

        # Tentukan level bahaya tertinggi dari semua file
        max_level = DangerLevel.SAFE
        if all_issues:
            max_level = max(issue[1]['level'] for issue in all_issues)
        
        # Biarkan AI menentukan level akhir jika ada analisis
        if all_ai_summaries:
            ai_max_level = max(summary.get('danger_level', DangerLevel.SAFE) for summary in all_ai_summaries)
            max_level = max(max_level, ai_max_level)

        # Buat laporan
        emoji, color = get_level_emoji_color(max_level)
        embed = discord.Embed(title=f"{emoji} Hasil Scan: `{attachment.filename}`", color=color)
        
        # Tambahkan ringkasan dari AI
        if all_ai_summaries:
            # Ambil ringkasan dari file yang paling berbahaya menurut AI
            best_summary = max(all_ai_summaries, key=lambda x: x.get('danger_level', 0))
            embed.add_field(
                name="🧠 Analisis AI",
                value=f"**Tujuan Script:** {best_summary.get('script_purpose', 'N/A')}\n"
                      f"**Ringkasan:** {best_summary.get('analysis_summary', 'N/A')}",
                inline=False
            )

        if not all_issues:
            embed.description = "✅ **File Aman** - Tidak ditemukan pola mencurigakan."
        else:
            descriptions = {
                DangerLevel.DANGEROUS: "🚨 **BAHAYA TINGGI** - Ditemukan kode yang dapat mencuri data!",
                DangerLevel.VERY_SUSPICIOUS: "⚠️ **SANGAT MENCURIGAKAN** - Ditemukan kode tersembunyi atau ter-obfuscate.",
                DangerLevel.SUSPICIOUS: "🤔 **MENCURIGAKAN** - Ditemukan fungsi berisiko yang perlu diperiksa."
            }
            embed.description = descriptions.get(max_level, "🤔 **MENCURIGAKAN**")
            
            issues_by_level = {}
            for filepath, issue in all_issues:
                level = issue['level']
                issues_by_level.setdefault(level, []).append((filepath, issue))
            
            for level in sorted(issues_by_level.keys(), reverse=True):
                level_emoji, _ = get_level_emoji_color(level)
                issues = issues_by_level[level]
                field_value = ""
                for filepath, issue in issues[:3]:
                    field_value += f"📁 `{filepath}` (Line {issue['line']})\n"
                    field_value += f"🔍 Pattern: `{issue['pattern']}`\n"
                    field_value += f"💡 {issue['description']}\n\n"
                if len(issues) > 3:
                    field_value += f"... dan {len(issues) - 3} lainnya."
                
                level_names = {
                    DangerLevel.DANGEROUS: "Sangat Berbahaya",
                    DangerLevel.VERY_SUSPICIOUS: "Sangat Mencurigakan", 
                    DangerLevel.SUSPICIOUS: "Mencurigakan"
                }
                embed.add_field(name=f"{level_emoji} {level_names.get(level, 'Unknown')}", value=field_value, inline=False)
        
        embed.set_footer(text=f"Dipindai oleh Lua Security Bot • {len(scanned_files)} file dianalisis")
        
        if processing_message:
            await processing_message.edit(content=None, embed=embed)
        else:
            await message.channel.send(embed=embed)
        
        # Kirim notifikasi ke channel alert jika berbahaya
        if max_level >= DangerLevel.DANGEROUS and ALERT_CHANNEL_ID:
            try:
                alert_channel = client.get_channel(ALERT_CHANNEL_ID)
                if alert_channel:
                    await alert_channel.send(f"🚨 **Peringatan Keamanan** oleh {message.author.mention} di channel {message.channel.mention}", embed=embed)
            except Exception as e:
                print(f"Gagal mengirim alert: {e}")

    except Exception as e:
        error_message = f"❌ Terjadi error saat memindai file: {str(e)}"
        if processing_message:
            await processing_message.edit(content=error_message, embed=None)
        else:
            await message.channel.send(error_message)
    finally:
        if os.path.exists(download_path):
            os.remove(download_path)

# --- Jalankan Bot ---
if __name__ == "__main__":
    print("🚀 Memulai Lua Security Scanner Bot...")
    client.run(BOT_TOKEN)