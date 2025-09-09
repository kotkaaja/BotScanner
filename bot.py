import discord
from discord.ext import commands
import os
import zipfile
import shutil
import re
import json
import asyncio
from typing import List, Tuple, Dict
import py7zr
import rarfile
from openai import AsyncOpenAI, RateLimitError
import google.generativeai as genai
import time
import itertools

# ============================
# KONFIGURASI ENVIRONMENT
# ============================
BOT_TOKEN = os.getenv("BOT_TOKEN")
OPENAI_API_KEYS = os.getenv("OPENAI_API_KEYS", "").split(',')
GEMINI_API_KEYS = os.getenv("GEMINI_API_KEYS", "").split(',')
ALERT_CHANNEL_ID = os.getenv("ALERT_CHANNEL_ID")
ALLOWED_CHANNEL_IDS = os.getenv("ALLOWED_CHANNEL_IDS")

# Konstanta
ALLOWED_EXTENSIONS = ['.lua', '.txt', '.zip', '.7z', '.rar']
TEMP_DIR = "temp_scan"
ZIP_COOLDOWN_SECONDS = 180
zip_cooldowns = {}

# ============================
# VALIDASI & INISIALISASI
# ============================
print("🔧 Memuat konfigurasi environment...")

# Validasi bot token
if not BOT_TOKEN:
    print("❌ FATAL ERROR: BOT_TOKEN tidak ditemukan!")
    exit()

# Bersihkan dan validasi API keys
OPENAI_API_KEYS = [key.strip() for key in OPENAI_API_KEYS if key.strip()]
GEMINI_API_KEYS = [key.strip() for key in GEMINI_API_KEYS if key.strip()]

if not OPENAI_API_KEYS and not GEMINI_API_KEYS:
    print("⚠️ WARNING: Tidak ada API key yang tersedia. Bot akan berjalan dalam mode MANUAL saja.")
else:
    print(f"✅ Berhasil memuat {len(OPENAI_API_KEYS)} OpenAI key(s) dan {len(GEMINI_API_KEYS)} Gemini key(s)")

# Validasi channel settings
if ALERT_CHANNEL_ID:
    try:
        ALERT_CHANNEL_ID = int(ALERT_CHANNEL_ID)
    except ValueError:
        print("⚠️ WARNING: ALERT_CHANNEL_ID tidak valid, fitur alert dinonaktifkan")
        ALERT_CHANNEL_ID = None

if ALLOWED_CHANNEL_IDS:
    try:
        ALLOWED_CHANNEL_IDS = [int(cid.strip()) for cid in ALLOWED_CHANNEL_IDS.split(',')]
        print(f"✅ Bot dibatasi pada {len(ALLOWED_CHANNEL_IDS)} channel(s)")
    except ValueError:
        print("❌ FATAL ERROR: ALLOWED_CHANNEL_IDS format tidak valid!")
        exit()

# Inisialisasi key cyclers untuk load balancing
openai_key_cycler = itertools.cycle(OPENAI_API_KEYS) if OPENAI_API_KEYS else None
gemini_key_cycler = itertools.cycle(GEMINI_API_KEYS) if GEMINI_API_KEYS else None

# ============================
# SISTEM LEVEL BAHAYA
# ============================
class DangerLevel:
    SAFE = 1
    SUSPICIOUS = 2
    VERY_SUSPICIOUS = 3
    DANGEROUS = 4

# Pola-pola berbahaya dengan level dan deskripsi
SUSPICIOUS_PATTERNS = {
    # Level DANGEROUS - Sangat berbahaya
    "discord.com/api/webhooks": {
        "level": DangerLevel.DANGEROUS,
        "description": "Discord webhook - sangat mungkin untuk mencuri data pengguna"
    },
    "pastebin.com": {
        "level": DangerLevel.DANGEROUS,
        "description": "Upload ke Pastebin - kemungkinan besar untuk mengirim data curian"
    },
    "hastebin.com": {
        "level": DangerLevel.DANGEROUS,
        "description": "Upload ke Hastebin - kemungkinan besar untuk mengirim data curian"
    },
    "api.telegram.org/bot": {
        "level": DangerLevel.DANGEROUS,
        "description": "Telegram bot API - sangat mungkin untuk mencuri data pengguna"
    },
    "username": {
        "level": DangerLevel.DANGEROUS,
        "description": "Kata 'username' - indikasi pengumpulan data kredensial"
    },
    "password": {
        "level": DangerLevel.DANGEROUS,
        "description": "Kata 'password' - indikasi pengumpulan data kredensial"
    },
    "api.telegram.org/": {
        "level": DangerLevel.DANGEROUS,
        "description": "Telegram API - sangat mungkin untuk mencuri data pengguna"
    },
    "discordapp.com/api/webhooks": {
        "level": DangerLevel.DANGEROUS,
        "description": "Discord webhook (legacy) - sangat mungkin untuk mencuri data pengguna"
    },
    "discordapp.com/api/": {
        "level": DangerLevel.DANGEROUS,
        "description": "Discord API (legacy) - sangat mungkin untuk mencuri data pengguna"
    },
    "telegram.org/bot": {
        "level": DangerLevel.DANGEROUS,
        "description": "Telegram bot API (legacy) - sangat mungkin untuk mencuri data pengguna"
    },
    "api.telegram.org": {
        "level": DangerLevel.DANGEROUS,
        "description": "Telegram API (legacy) - sangat mungkin untuk mencuri data pengguna"
    },

    
    # Level VERY_SUSPICIOUS - Sangat mencurigakan
    "loadstring": {
        "level": DangerLevel.VERY_SUSPICIOUS,
        "description": "Eksekusi kode dinamis - sangat berbahaya jika berisi kode tersembunyi"
    },
    "LuaObfuscator.com": {
        "level": DangerLevel.VERY_SUSPICIOUS,
        "description": "Kode yang diobfuscate - menyembunyikan fungsi sebenarnya"
    },
    "dofile": {
        "level": DangerLevel.VERY_SUSPICIOUS,
        "description": "Menjalankan file eksternal - berbahaya jika file tidak diketahui"
    },
    
    # Level SUSPICIOUS - Mencurigakan tapi bisa legitimate
    "io.open": {
        "level": DangerLevel.SUSPICIOUS,
        "description": "Membuka/membuat file - bisa legitimate untuk konfigurasi"
    },
    "os.execute": {
        "level": DangerLevel.SUSPICIOUS,
        "description": "Menjalankan perintah sistem - berbahaya jika tidak untuk fungsi legitimate"
    },
    "socket.http": {
        "level": DangerLevel.SUSPICIOUS,
        "description": "Komunikasi HTTP - bisa legitimate untuk API atau update"
    },
    "http.request": {
        "level": DangerLevel.SUSPICIOUS,
        "description": "Request HTTP - bisa legitimate untuk komunikasi API"
    },
    "sampGetPlayerNickname": {
        "level": DangerLevel.SUSPICIOUS,
        "description": "Mengambil nickname pemain - bisa legitimate untuk fitur game"
    },
    "sampGetCurrentServerAddress": {
        "level": DangerLevel.SUSPICIOUS,
        "description": "Mengambil alamat server - bisa legitimate untuk fitur reconnect"
    },
    "io.popen": {
        "level": DangerLevel.SUSPICIOUS,
        "description": "Membuka proses eksternal - berbahaya jika tidak untuk fungsi legitimate"
    },
    "os.remove": {
        "level": DangerLevel.SUSPICIOUS,
        "description": "Menghapus file - bisa legitimate untuk cleanup"
    },
    "os.rename": {
        "level": DangerLevel.SUSPICIOUS,
        "description": "Mengubah nama file - bisa legitimate untuk manajemen file"
    }
}

# ============================
# FUNGSI ANALISIS AI
# ============================
AI_PROMPT = """
Anda adalah seorang ahli keamanan siber Lua yang sangat tegas dan berpengalaman. Analisis skrip Lua berikut dengan teliti.

ATURAN MUTLAK YANG TIDAK BISA DILANGGAR:

🚨 LEVEL 4 (DANGEROUS) - MUTLAK BERBAHAYA - TIDAK ADA PENGECUALIAN:
Jika ditemukan pola berikut, WAJIB dikategorikan Level 4 tanpa memedulikan konteks atau penjelasan apapun:
- discord.com/api/webhooks, discordapp.com/api/webhooks
- discord.com/api/, discordapp.com/api/
- api.telegram.org/bot, telegram.org/bot, api.telegram.org/
- pastebin.com, hastebin.com

BAHKAN JIKA:
- Ada komentar "untuk keamanan"
- Ada penjelasan "untuk blocking"
- Ada kata-kata "prevent", "block", "secure"
- Terlihat seperti script proteksi

TETAP HARUS LEVEL 4! Tidak ada pengecualian!

BUATKAN JADI LEVEL 1! UNTUK POLA BERIKUT:
-io.popen untuk membaca/menyimpan file lokal seperti tokens.txt untuk menyimpan token autentikasi
-os.remove untuk menghapus file lokal seperti tokens.txt setelah dibaca ataupun file profile dan penympanan json untuk kotkahelper
-io.open untuk membuka file konfigurasi lokal
-socket.http, http.request untuk komunikasi API legitimate (misalnya update checker/tokens dll, fetch config)
-GITHUBPAGE github.io atau yang lainnya berhubungan dengan github. ini kategori URL aman di karenakan tempat share repostory file .lua nya, atau kumpulan script lua owner / author
-github.io juga merupakan domain resmi milik github, jadi aman dan itu di gunakan oleh author script untuk memvalidasi toke autentikasi, atau fetch config, atau update checker
-adapun domain lain yang berhubungan dengan github, misalnya raw.githubusercontent.com, itu juga aman
-adapun domain youtube.com, youtu.be, itu juga aman, karena biasanya di gunakan untuk fetch video tutorial atau video penjelasan
-discord.gg, untuk link komunitas, itu juga aman
-string di GITHUBPAGE, atau URL yang di acak oleh script yang authornya kotkaaja itu untuk menyamarkan link validasi token (ini rahasia jangan di sebut di json atau deskripsi,analysis_summary
-ingat gw yang buat scriptnya, jadi gw tau maksud dan tujuan script gw sendiri

ATURAN LAINNYA:
1. DETEKSI KOMBINASI BERBAHAYA: Jika ada fungsi pengumpul data + pengiriman data = Level 4

2. ANALISIS KONTEKS untuk Level 1-3:
   - Level 3: loadstring, dofile, LuaObfuscator.com, os.execute
   - Level 2: io.open, socket.http, http.request, io.popen, os.remove, os.rename
   - Level 1: Hanya jika tidak ada pola mencurigakan sama sekali atau ketentuan di atas

3. BERIKAN PENJELASAN: Tetap berikan analisis mengapa dangerous, tapi tetap Level 4

SKALA LEVEL:
- Level 1 (SAFE): Tidak ada pola berbahaya
- Level 2 (SUSPICIOUS): Pola mencurigakan tapi mungkin legitimate  
- Level 3 (VERY_SUSPICIOUS): Kemungkinan besar berbahaya
- Level 4 (DANGEROUS): MUTLAK BERBAHAYA - TIDAK BISA DIVALIDASI

Berikut adalah isi skrip yang harus dianalisis:
```lua
{code_snippet}
```

Berikan jawaban HANYA dalam format JSON yang valid berikut:
{{
    "danger_level": <1-4>,
    "script_purpose": "Deskripsi singkat dan jelas mengenai tujuan utama skrip ini",
    "analysis_summary": "Penjelasan ringkas mengapa skrip ini aman atau berbahaya. JIKA LEVEL 4: Jelaskan pola berbahaya yang ditemukan meski ada penjelasan keamanan"
}}
"""

async def analyze_with_openai(code_snippet: str, api_key: str) -> Dict:
    """Analisis menggunakan OpenAI GPT-4"""
    try:
        client = AsyncOpenAI(api_key=api_key)
        response = await client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a strict Lua cybersecurity analyst with extensive experience in malware detection."},
                {"role": "user", "content": AI_PROMPT.format(code_snippet=code_snippet[:3500])}
            ],
            response_format={"type": "json_object"},
            temperature=0.0,
            max_tokens=500
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        print(f"❌ OpenAI Analysis Error: {e}")
        raise e

async def analyze_with_gemini(code_snippet: str, api_key: str) -> Dict:
    """Analisis menggunakan Google Gemini"""
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-1.5-flash')
        response = await model.generate_content_async(
            AI_PROMPT.format(code_snippet=code_snippet[:3500])
        )
        
        # Bersihkan response dari markdown formatting
        cleaned_response = response.text.strip()
        cleaned_response = re.sub(r'```json\s*', '', cleaned_response)
        cleaned_response = re.sub(r'```\s*$', '', cleaned_response)
        cleaned_response = cleaned_response.strip()
        
        return json.loads(cleaned_response)
    except Exception as e:
        print(f"❌ Gemini Analysis Error: {e}")
        raise e

def analyze_manually(detected_issues: List[Dict]) -> Dict:
    """Analisis manual berdasarkan pola yang terdeteksi"""
    if not detected_issues:
        return {
            "danger_level": DangerLevel.SAFE,
            "script_purpose": "Tidak ada pola mencurigakan terdeteksi",
            "analysis_summary": "Analisis manual tidak menemukan pola berbahaya yang dikenal"
        }
    
    max_level = max(issue['level'] for issue in detected_issues)
    issue_count = len(detected_issues)
    
    # Logika untuk menentukan summary berdasarkan level tertinggi
    if max_level == DangerLevel.DANGEROUS:
        summary = f"Ditemukan {issue_count} pola berbahaya tingkat TINGGI. Kemungkinan besar malware!"
    elif max_level == DangerLevel.VERY_SUSPICIOUS:
        summary = f"Ditemukan {issue_count} pola sangat mencurigakan. Perlu investigasi lebih lanjut."
    elif max_level == DangerLevel.SUSPICIOUS:
        summary = f"Ditemukan {issue_count} pola mencurigakan. Mungkin legitimate tapi perlu hati-hati."
    else:
        summary = f"Analisis manual menemukan {issue_count} pola dengan tingkat bahaya rendah."
    
    return {
        "danger_level": max_level,
        "script_purpose": "Analisis manual berdasarkan pattern matching",
        "analysis_summary": summary
    }

async def get_ai_analysis(code_snippet: str, detected_issues: List[Dict], choice: str) -> Tuple[Dict, str]:
    """
    Mendapatkan analisis AI dengan fallback system
    choice: 'auto', 'openai', 'gemini', 'manual'
    """
    
    # Jika dipilih manual atau tidak ada API key, langsung manual
    if choice == 'manual' or (not openai_key_cycler and not gemini_key_cycler):
        print("🔧 Menggunakan analisis manual...")
        return analyze_manually(detected_issues), "Manual"
    
    # Jika choice adalah 'openai' atau 'auto', coba OpenAI dulu
    if choice in ['auto', 'openai'] and openai_key_cycler:
        print("🤖 Mencoba analisis dengan OpenAI...")
        for attempt in range(len(OPENAI_API_KEYS)):
            key = next(openai_key_cycler)
            try:
                print(f"   └─ Menggunakan OpenAI key: ...{key[-4:]}")
                result = await analyze_with_openai(code_snippet, key)
                return result, "OpenAI"
            except RateLimitError:
                print(f"   └─ ⚠️ OpenAI key ...{key[-4:]} mencapai batas kuota")
                continue
            except Exception as e:
                print(f"   └─ ❌ OpenAI key ...{key[-4:]} gagal: {str(e)[:50]}...")
                continue
        
        print("❌ Semua OpenAI key gagal atau mencapai limit")
    
    # Jika OpenAI gagal atau choice adalah 'gemini', coba Gemini
    if choice in ['auto', 'gemini'] and gemini_key_cycler:
        print("🧠 Mencoba analisis dengan Gemini...")
        for attempt in range(len(GEMINI_API_KEYS)):
            key = next(gemini_key_cycler)
            try:
                print(f"   └─ Menggunakan Gemini key: ...{key[-4:]}")
                result = await analyze_with_gemini(code_snippet, key)
                return result, "Gemini"
            except Exception as e:
                print(f"   └─ ❌ Gemini key ...{key[-4:]} gagal: {str(e)[:50]}...")
                continue
        
        print("❌ Semua Gemini key gagal atau mencapai limit")
    
    # Fallback ke analisis manual
    print("🔧 Fallback ke analisis manual...")
    return analyze_manually(detected_issues), "Manual"

# ============================
# FUNGSI UTILITAS FILE
# ============================
def extract_archive(file_path: str, extract_to: str) -> bool:
    """Ekstrak file arsip (zip, 7z, rar)"""
    try:
        if file_path.endswith('.zip'):
            with zipfile.ZipFile(file_path, 'r') as zip_file:
                zip_file.extractall(extract_to)
        elif file_path.endswith('.7z'):
            with py7zr.SevenZipFile(file_path, mode='r') as seven_zip:
                seven_zip.extractall(extract_to)
        elif file_path.endswith('.rar'):
            with rarfile.RarFile(file_path) as rar_file:
                rar_file.extractall(extract_to)
        return True
    except Exception as e:
        print(f"❌ Error mengekstrak {file_path}: {e}")
        return False

async def scan_file_content(file_path: str, choice: str) -> Tuple[List[Dict], Dict, str]:
    """Scan konten file untuk pola berbahaya"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
        
        # Deteksi pola berbahaya
        detected_issues = []
        for pattern, info in SUSPICIOUS_PATTERNS.items():
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                detected_issues.append({
                    'pattern': pattern,
                    'line': line_number,
                    'description': info['description'],
                    'level': info['level']
                })
        
        # Analisis dengan AI atau manual
        ai_summary, analyst = await get_ai_analysis(content, detected_issues, choice)
        
        return detected_issues, ai_summary, analyst
        
    except Exception as e:
        print(f"❌ Error scanning file {file_path}: {e}")
        return [], {}, "Error"

# ============================
# BOT DISCORD
# ============================
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

# Override default help command
bot.remove_command('help')

def get_level_emoji_color(level: int) -> Tuple[str, int]:
    """Mendapatkan emoji dan warna berdasarkan level bahaya"""
    if level == DangerLevel.SAFE:
        return "🟢", 0x00FF00
    elif level == DangerLevel.SUSPICIOUS:
        return "🟡", 0xFFFF00
    elif level == DangerLevel.VERY_SUSPICIOUS:
        return "🟠", 0xFF8C00
    else:  # DANGEROUS
        return "🔴", 0xFF0000

async def process_analysis(message_context, attachment, choice: str):
    """Proses analisis file yang diunggah"""
    
    # Cek channel permission
    if ALLOWED_CHANNEL_IDS and message_context.channel.id not in ALLOWED_CHANNEL_IDS:
        return
    
    # Cek ekstensi file
    if not any(attachment.filename.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS):
        await message_context.reply(
            f"❌ **Format File Tidak Didukung**: `{attachment.filename}`\n"
            f"**Format yang didukung**: {', '.join(ALLOWED_EXTENSIONS)}"
        )
        return
    
    processing_message = None
    download_path = os.path.join(TEMP_DIR, attachment.filename)
    
    try:
        # Cooldown untuk file arsip
        if attachment.filename.lower().endswith(('.zip', '.7z', '.rar')):
            user_id = message_context.author.id
            current_time = time.time()
            
            if user_id in zip_cooldowns:
                time_left = ZIP_COOLDOWN_SECONDS - (current_time - zip_cooldowns[user_id])
                if time_left > 0:
                    await message_context.reply(
                        f"⏳ **Cooldown Aktif**\n"
                        f"Harap tunggu **{int(time_left)} detik** lagi sebelum menganalisis arsip."
                    )
                    return
            
            zip_cooldowns[user_id] = current_time
            processing_message = await message_context.reply(
                f"⚙️ **Menganalisis Arsip...**\n"
                f"Mengekstrak dan memindai: `{attachment.filename}`"
            )
        
        # Download file
        await attachment.save(download_path)
        
        # Inisialisasi variabel hasil
        all_issues = []
        scanned_files = []
        all_ai_summaries = []
        analysts = set()
        
        # Tentukan file yang akan discan
        scan_paths = []
        extract_folder = os.path.join(TEMP_DIR, "extracted")
        
        if attachment.filename.lower().endswith(('.zip', '.7z', '.rar')):
            # Ekstrak arsip
            if extract_archive(download_path, extract_folder):
                for root, dirs, files in os.walk(extract_folder):
                    for file in files:
                        if file.endswith(('.lua', '.txt')):
                            file_path = os.path.join(root, file)
                            relative_path = os.path.relpath(file_path, extract_folder)
                            scan_paths.append((file_path, relative_path))
            else:
                raise Exception("Gagal mengekstrak arsip")
        else:
            # File tunggal
            scan_paths.append((download_path, attachment.filename))
        
        # Scan semua file
        for file_path, display_name in scan_paths:
            issues, ai_summary, analyst = await scan_file_content(file_path, choice)
            
            scanned_files.append(display_name)
            analysts.add(analyst)
            
            if issues:
                all_issues.extend([(display_name, issue) for issue in issues])
            
            if ai_summary:
                all_ai_summaries.append(ai_summary)
        
        # Cleanup extracted files
        if os.path.exists(extract_folder):
            shutil.rmtree(extract_folder)
        
        # Tentukan level bahaya tertinggi
        best_summary = max(all_ai_summaries, key=lambda x: x.get('danger_level', 0), default={})
        max_level = best_summary.get('danger_level', DangerLevel.SAFE)
        
        # Buat embed response
        emoji, color = get_level_emoji_color(max_level)
        embed = discord.Embed(color=color)
        
        # Title berdasarkan level
        level_titles = {
            DangerLevel.SAFE: "✅ AMAN",
            DangerLevel.SUSPICIOUS: "🤔 MENCURIGAKAN", 
            DangerLevel.VERY_SUSPICIOUS: "⚠️ SANGAT MENCURIGAKAN",
            DangerLevel.DANGEROUS: "🚨 BAHAYA TINGGI"
        }
        
        embed.title = f"{emoji} **{level_titles.get(max_level, 'HASIL SCAN')}**"
        embed.description = (
            f"**Tujuan Script:** {best_summary.get('script_purpose', 'N/A')}\n"
            f"**Ringkasan AI:** {best_summary.get('analysis_summary', 'N/A')}"
        )
        
        # Detail pola yang terdeteksi
        if all_issues:
            field_value = ""
            for filepath, issue in all_issues[:4]:  # Tampilkan max 4 issues
                field_value += (
                    f"📁 `{filepath}` (Line {issue['line']})\n"
                    f"💡 **Alasan:** {issue['description']}\n\n"
                )
            
            if len(all_issues) > 4:
                field_value += f"... dan {len(all_issues) - 4} pola lainnya."
            
            embed.add_field(
                name="📝 Detail Pola Terdeteksi", 
                value=field_value.strip(), 
                inline=False
            )
        
        # Footer dengan info analyst
        analyst_text = ", ".join(sorted(list(analysts)))
        embed.set_footer(
            text= f"Dianalisis oleh: {analyst_text} • {len(scanned_files)} file diperiksa\n"
            "NOTE: JIKA DIANLISIS OLEH AI, BACA DESKRIPSI DENGAN TELITI!\n"
            "Script cheat/ilegal biasa dikategorikan DANGEROUS/BERBAHAYA oleh AI. padahal aman\n"
            "Gunakan !scan manual atau !help jika Anda ragu"
            )
        # Send/edit response
        if processing_message:
            await processing_message.edit(content=None, embed=embed)
        else:
            await message_context.reply(embed=embed)
        
        # Send alert jika berbahaya
        if max_level >= DangerLevel.DANGEROUS and ALERT_CHANNEL_ID:
            alert_channel = bot.get_channel(ALERT_CHANNEL_ID)
            if alert_channel:
                await alert_channel.send(
                    f"🚨 **PERINGATAN KEAMANAN**\n"
                    f"Ditemukan file berbahaya oleh {message_context.author.mention} "
                    f"di {message_context.channel.mention}",
                    embed=embed
                )
    
    except Exception as e:
        error_msg = f"❌ **Error saat menganalisis file**: {str(e)}"
        if processing_message:
            await processing_message.edit(content=error_msg)
        else:
            await message_context.reply(error_msg)
        print(f"❌ Process Analysis Error: {e}")
    
    finally:
        # Cleanup
        if os.path.exists(download_path):
            os.remove(download_path)

# ============================
# EVENTS & COMMANDS
# ============================
@bot.event
async def on_ready():
    print(f'🤖 Bot scanner siap! Login sebagai {bot.user}')
    if not os.path.exists(TEMP_DIR):
        os.makedirs(TEMP_DIR)
    
    # Show available analysts
    available_analysts = []
    if OPENAI_API_KEYS:
        available_analysts.append(f"OpenAI ({len(OPENAI_API_KEYS)} keys)")
    if GEMINI_API_KEYS:
        available_analysts.append(f"Gemini ({len(GEMINI_API_KEYS)} keys)")
    available_analysts.append("Manual")
    
    print(f"📊 Available analysts: {', '.join(available_analysts)}")

@bot.command(name='scan', help='Memindai file dengan analis pilihan')
async def scan_command(ctx, analyst: str = 'auto'):
    """
    Memindai file dengan analis pilihan
    Usage: !scan [auto|openai|gemini|manual]
    Default: auto
    """
    analyst = analyst.lower()
    valid_analysts = ['auto', 'openai', 'gemini', 'manual']
    
    if analyst not in valid_analysts:
        await ctx.reply(
            f"❌ **Pilihan analis tidak valid!**\n"
            f"**Pilihan yang tersedia**: {', '.join(valid_analysts)}\n"
            f"**Contoh**: `!scan auto` atau `!scan openai`"
        )
        return
    
    if not ctx.message.attachments:
        await ctx.reply(
            f"❌ **Tidak ada file yang diunggah!**\n"
            f"Silakan unggah file bersamaan dengan perintah `!scan {analyst}`"
        )
        return
    
    await process_analysis(ctx, ctx.message.attachments[0], choice=analyst)

@bot.command(name='help', help='Menampilkan bantuan')
async def help_command(ctx):
    """Menampilkan bantuan penggunaan bot"""
    embed = discord.Embed(
        title="🛡️ Lua Security Scanner Bot - Bantuan",
        color=0x3498db
    )
    
    embed.add_field(
        name="🔍 Cara Scan Otomatis",
        value="Upload file langsung ke chat (tanpa command)",
        inline=False
    )
    
    embed.add_field(
        name="⚙️ Scan dengan Pilihan Analyst",
        value=(
            "`!scan auto` - OpenAI → Gemini → Manual\n"
            "`!scan openai` - Hanya OpenAI\n"
            "`!scan gemini` - Hanya Gemini\n"
            "`!scan manual` - Analisis pattern manual"
        ),
        inline=False
    )
    
    embed.add_field(
        name="📂 Format File Didukung",
        value=f"`{', '.join(ALLOWED_EXTENSIONS)}`",
        inline=False
    )
    
    embed.add_field(
        name="🚨 Level Bahaya",
        value=(
            "🟢 **AMAN** - Tidak ada ancaman\n"
            "🟡 **MENCURIGAKAN** - Perlu perhatian\n"
            "🟠 **SANGAT MENCURIGAKAN** - Kemungkinan berbahaya\n"
            "🔴 **BAHAYA TINGGI** - Kemungkinan malware"
        ),
        inline=False
    )
    
    # Show available analysts with new priority
    analysts_info = []
    if GEMINI_API_KEYS:
        analysts_info.append(f"🧠 Gemini ({len(GEMINI_API_KEYS)} keys) - Priority 1")
    if OPENAI_API_KEYS:
        analysts_info.append(f"🤖 OpenAI ({len(OPENAI_API_KEYS)} keys) - Priority 2")
    analysts_info.append("🔧 Manual Pattern Matching - Fallback")
    
    embed.add_field(
        name="🤖 Available Analysts (New Priority Order)",
        value="\n".join(f"• {analyst}" for analyst in analysts_info),
        inline=False
    )
    
    embed.set_footer(text="Created by Kotkaaja • Bot akan otomatis fallback ke analyst lain jika terjadi error")
    
    await ctx.reply(embed=embed)

@bot.event
async def on_message(message):
    # Jangan proses message dari bot sendiri atau command
    if message.author == bot.user or message.content.startswith('!'):
        await bot.process_commands(message)  # Tetap proses commands
        return
    
    # Auto-scan jika ada attachment
    if message.attachments:
        await process_analysis(message, message.attachments[0], choice='auto')

# ============================
# JALANKAN BOT
# ============================
if __name__ == "__main__":
    print("🚀 Memulai Lua Security Scanner Bot...")
    print("="*50)
    try:
        bot.run(BOT_TOKEN)
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        exit()
