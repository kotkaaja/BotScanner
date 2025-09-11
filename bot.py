import discord
from discord.ext import commands
import os
import zipfile
import shutil
import re
import json
import asyncio
import aiohttp
from typing import List, Tuple, Dict, Optional
import py7zr
import rarfile
from openai import AsyncOpenAI, RateLimitError
import google.generativeai as genai
import httpx
import time
import itertools
import hashlib
import logging
from logging.handlers import RotatingFileHandler
from urllib.parse import urlparse
import sqlite3
from datetime import datetime, timedelta
import io

# ============================
# KONFIGURASI ENVIRONMENT
# ============================
BOT_TOKEN = os.getenv("BOT_TOKEN")
OPENAI_API_KEYS = os.getenv("OPENAI_API_KEYS", "").split(',')
GEMINI_API_KEYS = os.getenv("GEMINI_API_KEYS", "").split(',')
DEEPSEEK_API_KEYS = os.getenv("DEEPSEEK_API_KEYS", "").split(',')
ALERT_CHANNEL_ID = os.getenv("ALERT_CHANNEL_ID")
ALLOWED_CHANNEL_IDS = os.getenv("ALLOWED_CHANNEL_IDS")
ADMIN_CHANNEL_ID = os.getenv("ADMIN_CHANNEL_ID")  # Untuk notifikasi admin

# Konstanta - Optimized for Railway free tier
ALLOWED_EXTENSIONS = ['.lua', '.txt', '.zip', '.7z', '.rar', '.py', '.js', '.php']
TEMP_DIR = "temp_scan"
MAX_FILE_SIZE_MB = 2  # Max 2MB untuk mencegah overload
MAX_ARCHIVE_FILES = 20  # Max 20 files per archive
COMMAND_COOLDOWN_SECONDS = 30  # Cooldown per user per command
DAILY_LIMIT_PER_USER = 50  # Max 50 scan per user per hari
QUEUE_MAX_SIZE = 5  # Max 5 concurrent operations
CACHE_EXPIRE_HOURS = 24  # Cache expire dalam 24 jam

# Global variables
zip_cooldowns = {}
user_cooldowns = {}
daily_usage = {}
processing_queue = asyncio.Queue(maxsize=QUEUE_MAX_SIZE)
file_cache = {}  # Simple in-memory cache
scan_stats = {"total_scans": 0, "dangerous_files": 0, "safe_files": 0}

# ============================
# LOGGING SETUP
# ============================
def setup_logging():
    """Setup logging dengan rotating file handler"""
    if not os.path.exists("logs"):
        os.makedirs("logs")
    
    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # File handler dengan rotation (max 5MB, keep 3 files)
    file_handler = RotatingFileHandler(
        'logs/bot.log', maxBytes=5*1024*1024, backupCount=3
    )
    file_handler.setFormatter(formatter)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    # Root logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

logger = setup_logging()

# ============================
# DATABASE SETUP (SQLite)
# ============================
def init_database():
    """Initialize SQLite database untuk history dan stats"""
    conn = sqlite3.connect('scanner.db')
    cursor = conn.cursor()
    
    # Table untuk scan history
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            filename TEXT,
            file_hash TEXT,
            danger_level INTEGER,
            analyst TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            channel_id INTEGER
        )
    ''')
    
    # Table untuk daily usage tracking
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS daily_usage (
            user_id INTEGER,
            date TEXT,
            count INTEGER DEFAULT 0,
            PRIMARY KEY (user_id, date)
        )
    ''')
    
    conn.commit()
    conn.close()

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
DEEPSEEK_API_KEYS = [key.strip() for key in DEEPSEEK_API_KEYS if key.strip()]

if not OPENAI_API_KEYS and not GEMINI_API_KEYS and not DEEPSEEK_API_KEYS:
    print("⚠️ WARNING: Tidak ada API key yang tersedia. Bot akan berjalan dalam mode MANUAL saja.")
else:
    print(f"✅ Berhasil memuat {len(DEEPSEEK_API_KEYS)} DeepSeek key(s), {len(GEMINI_API_KEYS)} Gemini key(s), dan {len(OPENAI_API_KEYS)} OpenAI key(s)")

# Validasi channel settings
if ALERT_CHANNEL_ID:
    try:
        ALERT_CHANNEL_ID = int(ALERT_CHANNEL_ID)
    except ValueError:
        print("⚠️ WARNING: ALERT_CHANNEL_ID tidak valid, fitur alert dinonaktifkan")
        ALERT_CHANNEL_ID = None

if ADMIN_CHANNEL_ID:
    try:
        ADMIN_CHANNEL_ID = int(ADMIN_CHANNEL_ID)
    except ValueError:
        print("⚠️ WARNING: ADMIN_CHANNEL_ID tidak valid")
        ADMIN_CHANNEL_ID = None

if ALLOWED_CHANNEL_IDS:
    try:
        ALLOWED_CHANNEL_IDS = [int(cid.strip()) for cid in ALLOWED_CHANNEL_IDS.split(',')]
        print(f"✅ Bot dibatasi pada {len(ALLOWED_CHANNEL_IDS)} channel(s)")
    except ValueError:
        print("❌ FATAL ERROR: ALLOWED_CHANNEL_IDS format tidak valid!")
        exit()

# Initialize database
init_database()

# Inisialisasi key cyclers untuk load balancing
deepseek_key_cycler = itertools.cycle(DEEPSEEK_API_KEYS) if DEEPSEEK_API_KEYS else None
gemini_key_cycler = itertools.cycle(GEMINI_API_KEYS) if GEMINI_API_KEYS else None
openai_key_cycler = itertools.cycle(OPENAI_API_KEYS) if OPENAI_API_KEYS else None

# ============================
# UTILITY FUNCTIONS
# ============================
def get_file_hash(content: str) -> str:
    """Generate SHA256 hash dari file content"""
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

def is_cache_valid(timestamp: float) -> bool:
    """Check apakah cache masih valid"""
    return time.time() - timestamp < (CACHE_EXPIRE_HOURS * 3600)

async def check_daily_limit(user_id: int) -> bool:
    """Check apakah user sudah mencapai daily limit"""
    today = datetime.now().strftime('%Y-%m-%d')
    conn = sqlite3.connect('scanner.db')
    cursor = conn.cursor()
    
    cursor.execute(
        'SELECT count FROM daily_usage WHERE user_id = ? AND date = ?',
        (user_id, today)
    )
    result = cursor.fetchone()
    conn.close()
    
    if result and result[0] >= DAILY_LIMIT_PER_USER:
        return False
    return True

def increment_daily_usage(user_id: int):
    """Increment daily usage count"""
    today = datetime.now().strftime('%Y-%m-%d')
    conn = sqlite3.connect('scanner.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT OR IGNORE INTO daily_usage (user_id, date, count) 
        VALUES (?, ?, 0)
    ''', (user_id, today))
    
    cursor.execute('''
        UPDATE daily_usage SET count = count + 1 
        WHERE user_id = ? AND date = ?
    ''', (user_id, today))
    
    conn.commit()
    conn.close()

def save_scan_history(user_id: int, filename: str, file_hash: str, 
                     danger_level: int, analyst: str, channel_id: int):
    """Save scan result to database"""
    conn = sqlite3.connect('scanner.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO scan_history 
        (user_id, filename, file_hash, danger_level, analyst, channel_id)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (user_id, filename, file_hash, danger_level, analyst, channel_id))
    
    conn.commit()
    conn.close()

async def download_from_url(url: str) -> Tuple[bytes, str]:
    """Download file dari URL dengan size limit"""
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            if response.status != 200:
                raise Exception(f"HTTP {response.status}")
            
            # Check content length
            content_length = response.headers.get('content-length')
            if content_length and int(content_length) > MAX_FILE_SIZE_MB * 1024 * 1024:
                raise Exception(f"File terlalu besar (>{MAX_FILE_SIZE_MB}MB)")
            
            # Download dengan size limit
            content = b""
            async for chunk in response.content.iter_chunked(8192):
                content += chunk
                if len(content) > MAX_FILE_SIZE_MB * 1024 * 1024:
                    raise Exception(f"File terlalu besar (>{MAX_FILE_SIZE_MB}MB)")
            
            # Guess filename from URL
            filename = os.path.basename(urlparse(url).path) or "downloaded_file"
            return content, filename

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
    "eval": {
        "level": DangerLevel.VERY_SUSPICIOUS,
        "description": "Eksekusi kode dinamis - sangat berbahaya di JavaScript/Python"
    },
    "exec": {
        "level": DangerLevel.VERY_SUSPICIOUS,
        "description": "Eksekusi kode dinamis - sangat berbahaya di Python"
    },
    
    # Level SUSPICIOUS - Mencurigakan tapi bisa legitimate
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
    "subprocess": {
        "level": DangerLevel.SUSPICIOUS,
        "description": "Menjalankan subprocess - bisa berbahaya di Python"
    },
    "shell_exec": {
        "level": DangerLevel.SUSPICIOUS,
        "description": "Eksekusi shell command - berbahaya di PHP"
    },
    "sampGetPlayerNickname": {
        "level": DangerLevel.SUSPICIOUS,
        "description": "Mengambil nickname pemain - bisa legitimate untuk fitur game"
    },
    "sampGetCurrentServerAddress": {
        "level": DangerLevel.SUSPICIOUS,
        "description": "Mengambil alamat server - bisa legitimate untuk fitur reconnect"
    }
}

# ============================
# FUNGSI ANALISIS AI
# ============================
AI_PROMPT = """
Anda adalah seorang ahli keamanan siber yang sangat berpengalaman. Analisis skrip berikut dengan teliti.

PENTING: Anda HANYA memberikan deskripsi dan analisis. Level bahaya sudah ditentukan oleh sistem deteksi pattern.

Berikan analisis mendalam mengenai:
1. Tujuan dan fungsi utama script
2. Pola-pola mencurigakan yang ditemukan (jika ada)
3. Potensi risiko keamanan
4. Konteks penggunaan yang mungkin legitimate

Berikut adalah isi skrip yang harus dianalisis:
```
{code_snippet}
```

Berikan jawaban HANYA dalam format JSON yang valid berikut:
{{
    "script_purpose": "Deskripsi singkat dan jelas mengenai tujuan utama skrip ini",
    "analysis_summary": "Penjelasan mendalam mengenai apa yang dilakukan script, potensi risiko, dan konteks penggunaan",
    "confidence_score": <1-100 (tingkat keyakinan analisis Anda)>
}}
"""

async def analyze_with_deepseek(code_snippet: str, api_key: str) -> Dict:
    """Analisis menggunakan DeepSeek API"""
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                "https://api.deepseek.com/chat/completions",
                json={
                    "model": "deepseek-chat",
                    "messages": [
                        {"role": "system", "content": "You are a strict cybersecurity analyst with extensive experience in malware detection."},
                        {"role": "user", "content": AI_PROMPT.format(code_snippet=code_snippet[:3000])}
                    ],
                    "response_format": {"type": "json_object"},
                    "temperature": 0.0,
                    "max_tokens": 400
                },
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                }
            )
            response.raise_for_status()
            return json.loads(response.json()["choices"][0]["message"]["content"])
    except Exception as e:
        logger.error(f"DeepSeek Analysis Error: {e}")
        raise e

async def analyze_with_openai(code_snippet: str, api_key: str) -> Dict:
    """Analisis menggunakan OpenAI GPT-4"""
    try:
        client = AsyncOpenAI(api_key=api_key)
        response = await client.chat.completions.create(
            model="gpt-4o-mini",  # Use cheaper model for Railway free tier
            messages=[
                {"role": "system", "content": "You are a strict cybersecurity analyst with extensive experience in malware detection."},
                {"role": "user", "content": AI_PROMPT.format(code_snippet=code_snippet[:3000])}
            ],
            response_format={"type": "json_object"},
            temperature=0.0,
            max_tokens=400
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        logger.error(f"OpenAI Analysis Error: {e}")
        raise e

async def analyze_with_gemini(code_snippet: str, api_key: str) -> Dict:
    """Analisis menggunakan Google Gemini"""
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-1.5-flash')
        response = await model.generate_content_async(
            AI_PROMPT.format(code_snippet=code_snippet[:3000])
        )
        
        # Bersihkan response dari markdown formatting
        cleaned_response = response.text.strip()
        cleaned_response = re.sub(r'```json\s*', '', cleaned_response)
        cleaned_response = re.sub(r'```\s*$', '', cleaned_response)
        cleaned_response = cleaned_response.strip()
        
        return json.loads(cleaned_response)
    except Exception as e:
        logger.error(f"Gemini Analysis Error: {e}")
        raise e

def analyze_manually(detected_issues: List[Dict]) -> Dict:
    """Analisis manual berdasarkan pola yang terdeteksi"""
    if not detected_issues:
        return {
            "script_purpose": "Tidak ada pola mencurigakan terdeteksi",
            "analysis_summary": "Analisis manual tidak menemukan pola berbahaya yang dikenal dalam database pattern",
            "confidence_score": 85
        }
    
    issue_count = len(detected_issues)
    max_level = max(issue['level'] for issue in detected_issues)
    
    # Generate summary berdasarkan pola yang ditemukan
    dangerous_patterns = [issue for issue in detected_issues if issue['level'] == DangerLevel.DANGEROUS]
    suspicious_patterns = [issue for issue in detected_issues if issue['level'] < DangerLevel.DANGEROUS]
    
    if dangerous_patterns:
        summary = f"Ditemukan {len(dangerous_patterns)} pola berbahaya tingkat TINGGI dan {len(suspicious_patterns)} pola mencurigakan lainnya. Script ini kemungkinan besar adalah malware atau memiliki fungsi berbahaya."
    elif len(detected_issues) >= 5:
        summary = f"Ditemukan {issue_count} pola mencurigakan. Meskipun tidak ada pola berbahaya langsung, kombinasi pola ini perlu investigasi lebih lanjut."
    else:
        summary = f"Ditemukan {issue_count} pola mencurigakan. Mungkin legitimate tapi perlu hati-hati dalam penggunaan."
    
    return {
        "script_purpose": "Analisis manual berdasarkan pattern matching database",
        "analysis_summary": summary,
        "confidence_score": 75
    }

async def get_ai_analysis_with_voting(code_snippet: str, detected_issues: List[Dict], 
                                    choice: str, ctx) -> Tuple[Dict, str, List[Dict]]:
    """
    Advanced AI analysis dengan voting system dan confidence scoring.
    Untuk file danger level 4, gunakan multiple AI untuk validasi.
    """
    max_detected_level = max([issue['level'] for issue in detected_issues], default=0)
    
    # Jika dipilih manual, langsung manual
    if choice == 'manual':
        logger.info("🔧 Menggunakan analisis manual...")
        manual_result = analyze_manually(detected_issues)
        return manual_result, "Manual", [manual_result]
    
    ai_results = []
    
    # Untuk file dengan pattern danger level 4, gunakan multiple AI untuk validasi
    if max_detected_level >= DangerLevel.DANGEROUS:
        logger.info("🚨 File berbahaya terdeteksi, menggunakan multiple AI untuk validasi...")
        await ctx.send("🚨 **Pola berbahaya terdeteksi!** Menggunakan multiple AI untuk validasi...")
        
        # Coba semua AI yang available
        for ai_type, keys, analyzer in [
            ("DeepSeek", DEEPSEEK_API_KEYS, analyze_with_deepseek),
            ("Gemini", GEMINI_API_KEYS, analyze_with_gemini),
            ("OpenAI", OPENAI_API_KEYS, analyze_with_openai)
        ]:
            if keys:
                for i, key in enumerate(keys[:2]):  # Max 2 keys per AI untuk hemat resource
                    try:
                        logger.info(f"   └─ Menggunakan {ai_type} key #{i+1}")
                        result = await analyzer(code_snippet, key)
                        result['ai_type'] = ai_type
                        ai_results.append(result)
                        break
                    except Exception as e:
                        logger.warning(f"   └─ {ai_type} key #{i+1} gagal: {str(e)[:50]}")
                        continue
    
    # Untuk file biasa atau jika tidak ada multiple AI results, gunakan single AI
    if not ai_results:
        # Prioritas: DeepSeek -> Gemini -> OpenAI -> Manual
        for ai_type, keys, analyzer in [
            ("DeepSeek", DEEPSEEK_API_KEYS if choice in ['auto', 'deepseek'] else [], analyze_with_deepseek),
            ("Gemini", GEMINI_API_KEYS if choice in ['auto', 'gemini'] else [], analyze_with_gemini),
            ("OpenAI", OPENAI_API_KEYS if choice in ['auto', 'openai'] else [], analyze_with_openai)
        ]:
            if keys:
                logger.info(f"🤖 Mencoba analisis dengan {ai_type}...")
                for i, key in enumerate(keys):
                    try:
                        logger.info(f"   └─ Menggunakan {ai_type} key #{i+1}")
                        result = await analyzer(code_snippet, key)
                        result['ai_type'] = ai_type
                        return result, ai_type, [result]
                    except Exception as e:
                        error_msg = f"⚠️ {ai_type} key #{i+1} gagal atau limit. Mencoba key berikutnya..."
                        logger.warning(f"   └─ {error_msg}")
                        await ctx.send(error_msg)
                        continue
                logger.warning(f"❌ Semua {ai_type} key gagal atau mencapai limit")
    
    # Jika ada multiple AI results, lakukan voting
    if len(ai_results) > 1:
        # Pilih hasil dengan confidence score tertinggi
        best_result = max(ai_results, key=lambda x: x.get('confidence_score', 50))
        ai_types = [r['ai_type'] for r in ai_results]
        
        # Hitung average confidence
        avg_confidence = sum(r.get('confidence_score', 50) for r in ai_results) / len(ai_results)
        best_result['confidence_score'] = int(avg_confidence)
        
        return best_result, f"Multi-AI ({', '.join(ai_types)})", ai_results
    
    elif len(ai_results) == 1:
        result = ai_results[0]
        return result, result['ai_type'], ai_results
    
    # Fallback ke manual
    logger.info("🔧 Fallback ke analisis manual...")
    await ctx.send("⚠️ Gagal menghubungi semua layanan AI, menggunakan analisis manual.")
    manual_result = analyze_manually(detected_issues)
    return manual_result, "Manual", [manual_result]

# ============================
# FUNGSI UTILITAS FILE
# ============================
def get_file_metadata(file_path: str) -> Dict:
    """Extract basic metadata dari file"""
    try:
        stats = os.stat(file_path)
        return {
            "size": stats.st_size,
            "modified": datetime.fromtimestamp(stats.st_mtime).isoformat(),
            "extension": os.path.splitext(file_path)[1].lower()
        }
    except Exception as e:
        logger.error(f"Error getting file metadata: {e}")
        return {}

def extract_archive(file_path: str, extract_to: str) -> bool:
    """Ekstrak file arsip dengan limits untuk Railway free tier"""
    try:
        file_count = 0
        
        if file_path.endswith('.zip'):
            with zipfile.ZipFile(file_path, 'r') as zip_file:
                for member in zip_file.namelist():
                    if file_count >= MAX_ARCHIVE_FILES:
                        logger.warning(f"Archive memiliki terlalu banyak file (>{MAX_ARCHIVE_FILES})")
                        break
                    if member.endswith(('.lua', '.txt', '.py', '.js', '.php')):
                        zip_file.extract(member, extract_to)
                        file_count += 1
                        
        elif file_path.endswith('.7z'):
            with py7zr.SevenZipFile(file_path, mode='r') as seven_zip:
                for member in seven_zip.getnames():
                    if file_count >= MAX_ARCHIVE_FILES:
                        break
                    if member.endswith(('.lua', '.txt', '.py', '.js', '.php')):
                        seven_zip.extract(member, extract_to)
                        file_count += 1
                        
        elif file_path.endswith('.rar'):
            with rarfile.RarFile(file_path) as rar_file:
                for member in rar_file.namelist():
                    if file_count >= MAX_ARCHIVE_FILES:
                        break
                    if member.endswith(('.lua', '.txt', '.py', '.js', '.php')):
                        rar_file.extract(member, extract_to)
                        file_count += 1
        
        return file_count > 0
        
    except Exception as e:
        logger.error(f"Error mengekstrak {file_path}: {e}")
        return False

async def scan_file_content(file_path: str, choice: str, ctx) -> Tuple[List[Dict], Dict, str, List[Dict]]:
    """Scan konten file untuk pola berbahaya dengan caching"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
        
        # Check cache
        file_hash = get_file_hash(content)
        cache_key = f"{file_hash}_{choice}"
        
        if cache_key in file_cache:
            cache_data = file_cache[cache_key]
            if is_cache_valid(cache_data['timestamp']):
                logger.info(f"Using cached result for {file_path}")
                return cache_data['detected_issues'], cache_data['ai_summary'], cache_data['analyst'], cache_data['ai_results']
        
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
        
        # Tentukan danger level berdasarkan pattern yang terdeteksi
        detected_max_level = max([issue['level'] for issue in detected_issues], default=DangerLevel.SAFE)
        
        # Analisis dengan AI
        ai_summary, analyst, ai_results = await get_ai_analysis_with_voting(content, detected_issues, choice, ctx)
        
        # Override AI danger level dengan pattern detection level jika lebih tinggi
        if detected_max_level >= DangerLevel.DANGEROUS:
            ai_summary['danger_level'] = detected_max_level
            ai_summary['analysis_summary'] = f"[PATTERN DETECTION] Level bahaya ditentukan oleh sistem deteksi pattern. {ai_summary.get('analysis_summary', '')}"
        else:
            ai_summary['danger_level'] = detected_max_level
        
        # Cache hasil
        file_cache[cache_key] = {
            'detected_issues': detected_issues,
            'ai_summary': ai_summary,
            'analyst': analyst,
            'ai_results': ai_results,
            'timestamp': time.time()
        }
        
        return detected_issues, ai_summary, analyst, ai_results
        
    except Exception as e:
        logger.error(f"Error scanning file {file_path}: {e}")
        return [], {}, "Error", []

# ============================
# RATE LIMITING & COOLDOWN
# ============================
def check_user_cooldown(user_id: int, command: str) -> Tuple[bool, int]:
    """Check user cooldown untuk command tertentu"""
    current_time = time.time()
    cooldown_key = f"{user_id}_{command}"
    
    if cooldown_key in user_cooldowns:
        time_left = COMMAND_COOLDOWN_SECONDS - (current_time - user_cooldowns[cooldown_key])
        if time_left > 0:
            return False, int(time_left)
    
    user_cooldowns[cooldown_key] = current_time
    return True, 0

# ============================
# PROGRESS BAR UTILITY
# ============================
def create_progress_bar(current: int, total: int, length: int = 20) -> str:
    """Create progress bar string"""
    if total == 0:
        return "█" * length
    
    filled = int(length * current / total)
    bar = "█" * filled + "▒" * (length - filled)
    percentage = int(100 * current / total)
    return f"[{bar}] {percentage}%"

# ============================
# BOT DISCORD
# ============================
intents = discord.Intents.default()
intents.message_content = True

bot = commands.Bot(command_prefix='!', intents=intents, help_command=None)

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

async def create_scan_report(filename: str, all_issues: List, ai_summaries: List, 
                           analysts: set, scanned_files: List) -> str:
    """Create detailed scan report untuk export"""
    report = f"""
=== LUA SECURITY SCANNER REPORT ===
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
File: {filename}
Total Files Scanned: {len(scanned_files)}
Analysts Used: {', '.join(sorted(analysts))}

=== SCAN RESULTS ===
"""
    
    if ai_summaries:
        best_summary = max(ai_summaries, key=lambda x: x.get('danger_level', 0))
        level_names = {1: "SAFE", 2: "SUSPICIOUS", 3: "VERY_SUSPICIOUS", 4: "DANGEROUS"}
        
        report += f"""
Danger Level: {level_names.get(best_summary.get('danger_level', 1), 'UNKNOWN')}
Script Purpose: {best_summary.get('script_purpose', 'N/A')}
Analysis Summary: {best_summary.get('analysis_summary', 'N/A')}
Confidence Score: {best_summary.get('confidence_score', 'N/A')}%
"""
    
    if all_issues:
        report += f"\n=== DETECTED PATTERNS ({len(all_issues)}) ===\n"
        for i, (filepath, issue) in enumerate(all_issues, 1):
            report += f"{i}. File: {filepath}\n"
            report += f"   Pattern: {issue['pattern']}\n"
            report += f"   Line: {issue['line']}\n"
            report += f"   Description: {issue['description']}\n"
            report += f"   Level: {issue['level']}\n\n"
    
    report += f"\n=== SCANNED FILES ===\n"
    for i, file in enumerate(scanned_files, 1):
        report += f"{i}. {file}\n"
    
    report += "\n=== END OF REPORT ===\n"
    return report

async def process_analysis(ctx, attachment: discord.Attachment = None, choice: str = "auto", url: str = None):
    """Proses analisis file yang diunggah dengan enhanced features"""
    
    # Rate limiting check
    can_proceed, cooldown_time = check_user_cooldown(ctx.author.id, "scan")
    if not can_proceed:
        await ctx.send(f"⏳ **Cooldown aktif!** Tunggu {cooldown_time} detik lagi.")
        return
    
    # Daily limit check
    if not await check_daily_limit(ctx.author.id):
        await ctx.send(f"❌ **Daily limit tercapai!** Anda sudah menggunakan {DAILY_LIMIT_PER_USER} scan hari ini.")
        return
    
    # Channel permission check
    if ALLOWED_CHANNEL_IDS and ctx.channel.id not in ALLOWED_CHANNEL_IDS:
        await ctx.send("❌ Perintah ini tidak dapat digunakan di channel ini.")
        return
    
    # Queue check
    if processing_queue.qsize() >= QUEUE_MAX_SIZE:
        await ctx.send("⏳ **Server sedang sibuk!** Terlalu banyak request bersamaan. Coba lagi nanti.")
        return
    
    # Add to processing queue
    await processing_queue.put(ctx.author.id)
    
    try:
        file_content = None
        filename = None
        
        # Handle URL download
        if url:
            try:
                # Validate URL
                parsed_url = urlparse(url)
                if not parsed_url.scheme in ['http', 'https']:
                    await ctx.send("❌ **URL tidak valid!** Hanya mendukung HTTP/HTTPS.")
                    return
                
                # Check supported domains
                supported_domains = ['mediafire.com', 'drive.google.com', 'dropbox.com', 
                                   'github.com', 'raw.githubusercontent.com']
                if not any(domain in parsed_url.netloc.lower() for domain in supported_domains):
                    await ctx.send(f"❌ **Domain tidak didukung!** Domain yang didukung: {', '.join(supported_domains)}")
                    return
                
                loading_msg = await ctx.send(f"⬇️ Mengunduh file dari URL...")
                file_content, filename = await download_from_url(url)
                
            except Exception as e:
                await ctx.send(f"❌ **Error mengunduh dari URL**: {str(e)}")
                return
        
        # Handle attachment
        elif attachment:
            filename = attachment.filename
            
            # Check file size
            if attachment.size > MAX_FILE_SIZE_MB * 1024 * 1024:
                await ctx.send(f"❌ **File terlalu besar!** Maksimal {MAX_FILE_SIZE_MB}MB.")
                return
            
            # Check file extension
            if not any(filename.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS):
                await ctx.send(
                    f"❌ **Format file tidak didukung**: `{filename}`\n"
                    f"**Format yang didukung**: {', '.join(ALLOWED_EXTENSIONS)}"
                )
                return
            
            loading_msg = await ctx.send(f"⚙️ Menganalisis `{filename}`...")
        
        else:
            await ctx.send("❌ **Tidak ada file atau URL yang diberikan!**")
            return
        
        # Increment daily usage
        increment_daily_usage(ctx.author.id)
        
        # Update stats
        scan_stats["total_scans"] += 1
        
        download_path = os.path.join(TEMP_DIR, filename)
        
        # Save file
        if file_content:
            with open(download_path, 'wb') as f:
                f.write(file_content)
        elif attachment:
            await attachment.save(download_path)
        
        all_issues = []
        scanned_files = []
        all_ai_summaries = []
        all_ai_results = []
        analysts = set()
        
        scan_paths = []
        extract_folder = os.path.join(TEMP_DIR, "extracted")
        
        # Handle archives
        if filename.lower().endswith(('.zip', '.7z', '.rar')):
            progress_msg = await ctx.send("📦 **Mengekstrak arsip...**")
            
            if extract_archive(download_path, extract_folder):
                # Count files first
                total_files = 0
                for root, _, files in os.walk(extract_folder):
                    total_files += sum(1 for file in files if file.endswith(('.lua', '.txt', '.py', '.js', '.php')))
                
                if total_files == 0:
                    await progress_msg.edit(content="❌ **Tidak ada file yang dapat di-scan dalam arsip!**")
                    return
                
                if total_files > MAX_ARCHIVE_FILES:
                    await progress_msg.edit(content=f"⚠️ **Terlalu banyak file!** Hanya akan memproses {MAX_ARCHIVE_FILES} file pertama.")
                    total_files = MAX_ARCHIVE_FILES
                
                # Build scan paths
                file_count = 0
                for root, _, files in os.walk(extract_folder):
                    for file in files:
                        if file_count >= MAX_ARCHIVE_FILES:
                            break
                        if file.endswith(('.lua', '.txt', '.py', '.js', '.php')):
                            file_path = os.path.join(root, file)
                            relative_path = os.path.relpath(file_path, extract_folder)
                            scan_paths.append((file_path, relative_path))
                            file_count += 1
                
                await progress_msg.edit(content=f"📊 **Memproses {total_files} file...**")
            else:
                await loading_msg.edit(content="❌ **Gagal mengekstrak arsip!**")
                return
        else:
            scan_paths.append((download_path, filename))
        
        # Scan all files with progress updates
        total_files = len(scan_paths)
        processed = 0
        
        for file_path, display_name in scan_paths:
            try:
                # Update progress for archives
                if total_files > 1:
                    progress = create_progress_bar(processed, total_files)
                    await loading_msg.edit(content=f"🔍 **Scanning Files** {progress}\n`{display_name}`")
                
                issues, ai_summary, analyst, ai_results = await scan_file_content(file_path, choice, ctx)
                
                scanned_files.append(display_name)
                analysts.add(analyst)
                
                if issues:
                    all_issues.extend([(display_name, issue) for issue in issues])
                
                if ai_summary:
                    all_ai_summaries.append(ai_summary)
                    all_ai_results.extend(ai_results)
                
                processed += 1
                
            except Exception as e:
                logger.error(f"Error processing {display_name}: {e}")
                continue
        
        # Cleanup
        if os.path.exists(extract_folder):
            shutil.rmtree(extract_folder)
        
        # Determine final results
        best_summary = max(all_ai_summaries, key=lambda x: x.get('danger_level', 0), default={})
        max_level = best_summary.get('danger_level', DangerLevel.SAFE)
        
        # Update stats
        if max_level >= DangerLevel.DANGEROUS:
            scan_stats["dangerous_files"] += 1
        elif max_level == DangerLevel.SAFE:
            scan_stats["safe_files"] += 1
        
        # Create embed result
        emoji, color = get_level_emoji_color(max_level)
        embed = discord.Embed(color=color)
        
        level_titles = {
            DangerLevel.SAFE: "✅ AMAN",
            DangerLevel.SUSPICIOUS: "🤔 MENCURIGAKAN", 
            DangerLevel.VERY_SUSPICIOUS: "⚠️ SANGAT MENCURIGAKAN",
            DangerLevel.DANGEROUS: "🚨 BAHAYA TINGGI"
        }
        
        embed.title = f"{emoji} **{level_titles.get(max_level, 'HASIL SCAN')}**"
        embed.description = (
            f"**File:** `{filename}`\n"
            f"**Tujuan Script:** {best_summary.get('script_purpose', 'N/A')}\n"
            f"**Analisis:** {best_summary.get('analysis_summary', 'N/A')[:500]}{'...' if len(best_summary.get('analysis_summary', '')) > 500 else ''}"
        )
        
        # Add confidence score if available
        if best_summary.get('confidence_score'):
            embed.add_field(
                name="🎯 Confidence Score",
                value=f"{best_summary['confidence_score']}%",
                inline=True
            )
        
        # Add AI results summary if multiple AIs used
        if len(all_ai_results) > 1:
            ai_summary_text = ""
            for result in all_ai_results[:3]:  # Max 3 untuk hemat space
                ai_type = result.get('ai_type', 'Unknown')
                confidence = result.get('confidence_score', 'N/A')
                ai_summary_text += f"• **{ai_type}**: {confidence}% confidence\n"
            
            embed.add_field(
                name="🤖 Multi-AI Analysis",
                value=ai_summary_text.strip(),
                inline=True
            )
        
        # Add detected patterns
        if all_issues:
            issues_by_level = {}
            for filepath, issue in all_issues:
                level = issue['level']
                if level not in issues_by_level:
                    issues_by_level[level] = []
                issues_by_level[level].append(f"`{issue['pattern']}` in `{filepath}` (L{issue['line']})")
            
            field_value = ""
            for level in sorted(issues_by_level.keys(), reverse=True):
                level_name = {4: "🔴 DANGEROUS", 3: "🟠 VERY_SUSPICIOUS", 2: "🟡 SUSPICIOUS", 1: "🟢 SAFE"}
                patterns = issues_by_level[level][:5]  # Max 5 per level
                field_value += f"**{level_name.get(level, 'UNKNOWN')}**\n"
                field_value += "\n".join(patterns[:3])  # Max 3 patterns per level untuk hemat space
                if len(patterns) > 3:
                    field_value += f"\n... dan {len(patterns) - 3} lainnya"
                field_value += "\n\n"
            
            if len(all_issues) > 15:
                field_value += f"... Total: {len(all_issues)} pola terdeteksi"
            
            embed.add_field(
                name=f"📝 Pola Terdeteksi ({len(all_issues)})", 
                value=field_value.strip()[:1024], 
                inline=False
            )
        
        # Add file metadata
        metadata = get_file_metadata(download_path)
        if metadata:
            embed.add_field(
                name="📊 File Info",
                value=f"Size: {metadata.get('size', 0):,} bytes\nType: {metadata.get('extension', 'N/A')}",
                inline=True
            )
        
        analyst_text = ", ".join(sorted(list(analysts)))
        embed.set_footer(
            text=f"Dianalisis oleh: {analyst_text} • {len(scanned_files)} file diperiksa\n"
                f"Scan ID: {get_file_hash(str(ctx.author.id) + str(time.time()))[:8]}\n"
                "Created by Kotkaaja"
        )
        
        # Create view with buttons untuk export dan detail
        view = ScanResultView(filename, all_issues, all_ai_summaries, analysts, scanned_files, all_ai_results)
        
        await loading_msg.edit(content=None, embed=embed, view=view)
        
        # Save to database
        file_hash = get_file_hash(str(all_issues) + str(best_summary))
        save_scan_history(ctx.author.id, filename, file_hash, max_level, analyst_text, ctx.channel.id)
        
        # Alert notifications
        if max_level >= DangerLevel.DANGEROUS:
            if ALERT_CHANNEL_ID:
                alert_channel = bot.get_channel(ALERT_CHANNEL_ID)
                if alert_channel:
                    await alert_channel.send(
                        f"🚨 **PERINGATAN KEAMANAN**\n"
                        f"File berbahaya ditemukan oleh {ctx.author.mention} "
                        f"di {ctx.channel.mention}\n"
                        f"File: `{filename}`",
                        embed=embed
                    )
            
            # Admin notification untuk activity mencurigakan
            if ADMIN_CHANNEL_ID:
                admin_channel = bot.get_channel(ADMIN_CHANNEL_ID)
                if admin_channel:
                    await admin_channel.send(
                        f"⚠️ **ADMIN ALERT**\n"
                        f"User: {ctx.author} (`{ctx.author.id}`)\n"
                        f"Channel: {ctx.channel.mention}\n"
                        f"File: `{filename}`\n"
                        f"Danger Level: {max_level}/4\n"
                        f"Patterns: {len(all_issues)}"
                    )
    
    except Exception as e:
        error_msg = f"❌ **Error saat menganalisis**: {str(e)[:200]}"
        logger.error(f"Process Analysis Error: {e}")
        if 'loading_msg' in locals():
            await loading_msg.edit(content=error_msg, embed=None, view=None)
        else:
            await ctx.send(error_msg)
    
    finally:
        # Remove from queue
        try:
            processing_queue.get_nowait()
        except:
            pass
        
        # Cleanup files
        if 'download_path' in locals() and os.path.exists(download_path):
            os.remove(download_path)

# ============================
# DISCORD UI COMPONENTS
# ============================
class ScanResultView(discord.ui.View):
    def __init__(self, filename, all_issues, ai_summaries, analysts, scanned_files, ai_results):
        super().__init__(timeout=300)  # 5 minutes timeout
        self.filename = filename
        self.all_issues = all_issues
        self.ai_summaries = ai_summaries
        self.analysts = analysts
        self.scanned_files = scanned_files
        self.ai_results = ai_results

    @discord.ui.button(label='📄 Export Report', style=discord.ButtonStyle.secondary, emoji='📄')
    async def export_report(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.defer(ephemeral=True)
        
        try:
            report = await create_scan_report(self.filename, self.all_issues, 
                                            self.ai_summaries, self.analysts, self.scanned_files)
            
            # Create file
            file_buffer = io.StringIO(report)
            discord_file = discord.File(file_buffer, filename=f"scan_report_{self.filename}_{int(time.time())}.txt")
            
            await interaction.followup.send("📄 **Scan Report**", file=discord_file, ephemeral=True)
            
        except Exception as e:
            await interaction.followup.send(f"❌ Error creating report: {str(e)}", ephemeral=True)

    @discord.ui.button(label='🔍 Detail Analysis', style=discord.ButtonStyle.primary, emoji='🔍')
    async def detail_analysis(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.defer(ephemeral=True)
        
        embed = discord.Embed(title=f"🔍 **Detail Analysis: {self.filename}**", color=0x3498db)
        
        # AI Results detail
        if self.ai_results:
            ai_detail = ""
            for i, result in enumerate(self.ai_results[:3], 1):
                ai_type = result.get('ai_type', 'Unknown')
                confidence = result.get('confidence_score', 'N/A')
                purpose = result.get('script_purpose', 'N/A')[:100]
                ai_detail += f"**{i}. {ai_type}** (Confidence: {confidence}%)\n"
                ai_detail += f"Purpose: {purpose}\n\n"
            
            embed.add_field(name="🤖 AI Analysis Details", value=ai_detail.strip(), inline=False)
        
        # Pattern details
        if self.all_issues:
            pattern_detail = ""
            for i, (filepath, issue) in enumerate(self.all_issues[:10], 1):
                pattern_detail += f"**{i}.** `{issue['pattern']}` (Level {issue['level']})\n"
                pattern_detail += f"   📁 {filepath} - Line {issue['line']}\n"
                pattern_detail += f"   ℹ️ {issue['description'][:80]}...\n\n"
            
            if len(self.all_issues) > 10:
                pattern_detail += f"... dan {len(self.all_issues) - 10} pola lainnya"
            
            embed.add_field(name="📋 Pattern Details", value=pattern_detail.strip()[:1024], inline=False)
        
        embed.set_footer(text=f"Files: {len(self.scanned_files)} • Analysts: {', '.join(self.analysts)}")
        
        await interaction.followup.send(embed=embed, ephemeral=True)

    @discord.ui.button(label='📊 JSON Export', style=discord.ButtonStyle.success, emoji='📊')
    async def json_export(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.defer(ephemeral=True)
        
        try:
            # Create comprehensive JSON report
            json_data = {
                "scan_info": {
                    "filename": self.filename,
                    "timestamp": datetime.now().isoformat(),
                    "total_files": len(self.scanned_files),
                    "analysts_used": sorted(list(self.analysts))
                },
                "results": {
                    "ai_summaries": self.ai_summaries,
                    "ai_results": self.ai_results,
                    "detected_issues": [
                        {
                            "file": filepath,
                            "pattern": issue['pattern'],
                            "line": issue['line'],
                            "description": issue['description'],
                            "level": issue['level']
                        } for filepath, issue in self.all_issues
                    ]
                },
                "scanned_files": self.scanned_files
            }
            
            json_str = json.dumps(json_data, indent=2, ensure_ascii=False)
            file_buffer = io.StringIO(json_str)
            discord_file = discord.File(file_buffer, filename=f"scan_data_{self.filename}_{int(time.time())}.json")
            
            await interaction.followup.send("📊 **JSON Export**", file=discord_file, ephemeral=True)
            
        except Exception as e:
            await interaction.followup.send(f"❌ Error creating JSON: {str(e)}", ephemeral=True)

# ============================
# EVENTS & COMMANDS
# ============================
@bot.event
async def on_ready():
    logger.info(f'🤖 Bot scanner siap! Login sebagai {bot.user}')
    if not os.path.exists(TEMP_DIR):
        os.makedirs(TEMP_DIR)
    
    available_analysts = []
    if DEEPSEEK_API_KEYS:
        available_analysts.append(f"DeepSeek ({len(DEEPSEEK_API_KEYS)} keys)")
    if GEMINI_API_KEYS:
        available_analysts.append(f"Gemini ({len(GEMINI_API_KEYS)} keys)")
    if OPENAI_API_KEYS:
        available_analysts.append(f"OpenAI ({len(OPENAI_API_KEYS)} keys)")
    available_analysts.append("Manual")
    
    logger.info(f"📊 Available analysts (Prioritas): {', '.join(available_analysts)}")
    
    # Clean old cache entries on startup
    current_time = time.time()
    expired_keys = [key for key, data in file_cache.items() 
                   if not is_cache_valid(data.get('timestamp', 0))]
    for key in expired_keys:
        del file_cache[key]
    
    logger.info(f"🧹 Cleaned {len(expired_keys)} expired cache entries")

@bot.command(name="scan")
async def scan_command(ctx, analyst="auto", *, url=None):
    """
    Memindai file atau URL dengan analis pilihan
    
    Penggunaan:
    !scan [analyst] - lalu upload file
    !scan [analyst] [URL] - untuk download dari URL
    
    Pilihan analyst:
    - auto (default): DeepSeek -> Gemini -> OpenAI -> Manual
    - deepseek: Hanya DeepSeek
    - gemini: Hanya Gemini  
    - openai: Hanya OpenAI
    - manual: Analisis pattern manual
    """
    
    valid_analysts = ["auto", "deepseek", "gemini", "openai", "manual"]
    if analyst.lower() not in valid_analysts:
        await ctx.send(f"❌ **Analyst tidak valid**: `{analyst}`\n"
                      f"**Pilihan yang tersedia**: {', '.join(valid_analysts)}")
        return
    
    # Check if URL provided
    if url:
        await process_analysis(ctx, choice=analyst.lower(), url=url)
        return
    
    # Check for attachment
    if not ctx.message.attachments:
        embed = discord.Embed(
            title="📎 **Upload File atau Berikan URL**",
            description=(
                f"**Analyst dipilih**: `{analyst}`\n"
                f"**Format file**: {', '.join(ALLOWED_EXTENSIONS)}\n"
                f"**Max size**: {MAX_FILE_SIZE_MB}MB\n\n"
                "**URL Support**:\n"
                "• MediaFire, Google Drive, Dropbox\n"
                "• GitHub, Raw GitHub\n\n"
                "**Contoh**:\n"
                "`!scan auto https://example.com/file.lua`"
            ),
            color=0x3498db
        )
        await ctx.send(embed=embed)
        return
    
    await process_analysis(ctx, ctx.message.attachments[0], analyst.lower())

@bot.command(name="history")
async def history_command(ctx, limit=5):
    """Lihat history scan Anda (max 20)"""
    
    # Rate limiting
    can_proceed, cooldown_time = check_user_cooldown(ctx.author.id, "history")
    if not can_proceed:
        await ctx.send(f"⏳ **Cooldown aktif!** Tunggu {cooldown_time} detik lagi.")
        return
    
    limit = min(max(1, limit), 20)  # Clamp between 1-20
    
    conn = sqlite3.connect('scanner.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT filename, danger_level, analyst, timestamp 
        FROM scan_history 
        WHERE user_id = ? 
        ORDER BY timestamp DESC 
        LIMIT ?
    ''', (ctx.author.id, limit))
    
    results = cursor.fetchall()
    conn.close()
    
    if not results:
        await ctx.send("📋 **Tidak ada history scan ditemukan.**")
        return
    
    embed = discord.Embed(
        title=f"📋 **Scan History - {ctx.author.display_name}**",
        color=0x3498db
    )
    
    level_emoji = {1: "🟢", 2: "🟡", 3: "🟠", 4: "🔴"}
    
    history_text = ""
    for filename, level, analyst, timestamp in results:
        emoji = level_emoji.get(level, "❓")
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        time_ago = datetime.now() - dt
        
        if time_ago.days > 0:
            time_str = f"{time_ago.days}d ago"
        elif time_ago.seconds > 3600:
            time_str = f"{time_ago.seconds // 3600}h ago"
        else:
            time_str = f"{time_ago.seconds // 60}m ago"
        
        history_text += f"{emoji} `{filename[:30]}{'...' if len(filename) > 30 else ''}` - {analyst} ({time_str})\n"
    
    embed.description = history_text
    embed.set_footer(text=f"Showing last {len(results)} scans • Use !history [number] for more")
    
    await ctx.send(embed=embed)

@bot.command(name="stats")
async def stats_command(ctx):
    """Lihat statistik bot dan penggunaan Anda"""
    
    # Rate limiting
    can_proceed, cooldown_time = check_user_cooldown(ctx.author.id, "stats")
    if not can_proceed:
        await ctx.send(f"⏳ **Cooldown aktif!** Tunggu {cooldown_time} detik lagi.")
        return
    
    # Get user stats
    today = datetime.now().strftime('%Y-%m-%d')
    conn = sqlite3.connect('scanner.db')
    cursor = conn.cursor()
    
    # User daily usage
    cursor.execute(
        'SELECT count FROM daily_usage WHERE user_id = ? AND date = ?',
        (ctx.author.id, today)
    )
    user_daily = cursor.fetchone()
    user_daily_count = user_daily[0] if user_daily else 0
    
    # User total scans
    cursor.execute(
        'SELECT COUNT(*), MAX(timestamp) FROM scan_history WHERE user_id = ?',
        (ctx.author.id,)
    )
    user_total, last_scan = cursor.fetchone()
    
    # User danger level distribution
    cursor.execute('''
        SELECT danger_level, COUNT(*) 
        FROM scan_history 
        WHERE user_id = ? 
        GROUP BY danger_level
    ''', (ctx.author.id,))
    user_levels = dict(cursor.fetchall())
    
    # Global stats from database
    cursor.execute('SELECT COUNT(*) FROM scan_history')
    total_db_scans = cursor.fetchone()[0]
    
    cursor.execute('''
        SELECT danger_level, COUNT(*) 
        FROM scan_history 
        GROUP BY danger_level
    ''')
    global_levels = dict(cursor.fetchall())
    
    conn.close()
    
    embed = discord.Embed(
        title="📊 **Scanner Statistics**",
        color=0x3498db
    )
    
    # User Stats
    embed.add_field(
        name="👤 Your Stats",
        value=(
            f"**Today**: {user_daily_count}/{DAILY_LIMIT_PER_USER} scans\n"
            f"**Total**: {user_total} scans\n"
            f"**Last Scan**: {last_scan[:16] if last_scan else 'Never'}\n"
            f"**Queue Position**: {processing_queue.qsize()}/{QUEUE_MAX_SIZE}"
        ),
        inline=True
    )
    
    # User danger level distribution
    level_names = {1: "🟢 Safe", 2: "🟡 Suspicious", 3: "🟠 Very Sus", 4: "🔴 Dangerous"}
    user_dist = ""
    for level in [4, 3, 2, 1]:
        count = user_levels.get(level, 0)
        if count > 0:
            user_dist += f"{level_names[level]}: {count}\n"
    
    embed.add_field(
        name="📈 Your File Types",
        value=user_dist or "No scans yet",
        inline=True
    )
    
    # Global stats
    global_dist = ""
    for level in [4, 3, 2, 1]:
        count = global_levels.get(level, 0)
        global_dist += f"{level_names[level]}: {count}\n"
    
    embed.add_field(
        name="🌍 Global Stats",
        value=(
            f"**Total Scans**: {total_db_scans}\n"
            f"**Cache Entries**: {len(file_cache)}\n"
            f"**Uptime**: {int((time.time() - bot.start_time) / 3600)}h\n"
            "\n**Distribution**:\n" + global_dist
        ),
        inline=True
    )
    
    # API Status
    api_status = ""
    if DEEPSEEK_API_KEYS:
        api_status += f"🌊 DeepSeek: {len(DEEPSEEK_API_KEYS)} keys\n"
    if GEMINI_API_KEYS:
        api_status += f"🧠 Gemini: {len(GEMINI_API_KEYS)} keys\n"
    if OPENAI_API_KEYS:
        api_status += f"🤖 OpenAI: {len(OPENAI_API_KEYS)} keys\n"
    
    embed.add_field(
        name="🔑 API Status",
        value=api_status or "Manual only",
        inline=True
    )
    
    # Server stats
    embed.add_field(
        name="🖥️ Server Info",
        value=(
            f"**Max File Size**: {MAX_FILE_SIZE_MB}MB\n"
            f"**Max Archive Files**: {MAX_ARCHIVE_FILES}\n"
            f"**Command Cooldown**: {COMMAND_COOLDOWN_SECONDS}s\n"
            f"**Daily Limit**: {DAILY_LIMIT_PER_USER}"
        ),
        inline=True
    )
    
    embed.set_footer(text="Stats updated in real-time • Created by Kotkaaja")
    
    await ctx.send(embed=embed)

@bot.command(name="help")
async def help_command(ctx):
    """Menampilkan bantuan penggunaan bot"""
    embed = discord.Embed(
        title="🛡️ Lua Security Scanner Bot - Bantuan",
        color=0x3498db
    )
    
    embed.add_field(
        name="🔍 Auto Scan",
        value="Upload file langsung ke channel yang diizinkan untuk scan otomatis dengan prioritas DeepSeek → Gemini → OpenAI → Manual.",
        inline=False
    )
    
    embed.add_field(
        name="⚙️ Commands",
        value=(
            "`!scan` - Scan file dengan analyst auto\n"
            "`!scan [analyst]` - Pilih analyst tertentu\n"
            "`!scan [analyst] [URL]` - Scan dari URL\n"
            "`!history [limit]` - Lihat riwayat scan (max 20)\n"
            "`!stats` - Statistik bot dan penggunaan\n"
            "`!help` - Tampilkan bantuan ini"
        ),
        inline=False
    )
    
    embed.add_field(
        name="🤖 Analysts",
        value=(
            "• `auto` - DeepSeek → Gemini → OpenAI → Manual\n"
            "• `deepseek` - Hanya DeepSeek AI\n"
            "• `gemini` - Hanya Google Gemini\n"
            "• `openai` - Hanya OpenAI GPT\n"
            "• `manual` - Pattern matching saja"
        ),
        inline=False
    )
    
    embed.add_field(
        name="📁 Supported Files",
        value=(
            f"**Extensions**: {', '.join(ALLOWED_EXTENSIONS)}\n"
            f"**Max Size**: {MAX_FILE_SIZE_MB}MB\n"
            f"**Max Archive Files**: {MAX_ARCHIVE_FILES}\n"
            "**URLs**: MediaFire, Google Drive, Dropbox, GitHub"
        ),
        inline=False
    )
    
    embed.add_field(
        name="🚨 Danger Levels",
        value=(
            "🟢 **SAFE** - Tidak ada ancaman\n"
            "🟡 **SUSPICIOUS** - Perlu perhatian\n"
            "🟠 **VERY SUSPICIOUS** - Kemungkinan berbahaya\n"
            "🔴 **DANGEROUS** - Kemungkinan malware"
        ),
        inline=False
    )
    
    embed.add_field(
        name="⏱️ Rate Limits",
        value=(
            f"**Command Cooldown**: {COMMAND_COOLDOWN_SECONDS}s\n"
            f"**Daily Limit**: {DAILY_LIMIT_PER_USER} scans/day\n"
            f"**Queue Limit**: {QUEUE_MAX_SIZE} concurrent\n"
            f"**Cache Duration**: {CACHE_EXPIRE_HOURS}h"
        ),
        inline=False
    )
    
    embed.add_field(
        name="✨ Features",
        value=(
            "• 📄 Export detailed reports (TXT/JSON)\n"
            "• 📊 Real-time progress bars\n"
            "• 🎯 AI confidence scoring\n"
            "• 🗃️ Smart caching system\n"
            "• 📋 Scan history tracking\n"
            "• 🔍 Multi-AI voting for dangerous files"
        ),
        inline=False
    )
    
    embed.set_footer(text="Created by Kotkaaja • Open source security scanner")
    
    await ctx.send(embed=embed)

@bot.command(name="clearcache", hidden=True)
async def clear_cache_command(ctx):
    """Clear bot cache (admin only)"""
    # Replace YOUR_ADMIN_USER_ID dengan user ID Anda
    ADMIN_USER_IDS = [123456789, 987654321]  # Ganti dengan ID admin yang sebenarnya
    
    if ctx.author.id not in ADMIN_USER_IDS:
        await ctx.send("❌ **Access denied.** Admin only command.")
        return
    
    cache_size = len(file_cache)
    file_cache.clear()
    
    await ctx.send(f"🧹 **Cache cleared!** Removed {cache_size} entries.")

@bot.event
async def on_message(message):
    if message.author == bot.user:
        return
    
    # Process commands first
    await bot.process_commands(message)
    
    # Auto-scan untuk attachment
    if ALLOWED_CHANNEL_IDS and message.channel.id not in ALLOWED_CHANNEL_IDS:
        return
        
    if message.attachments and not message.content.startswith('!'):
        # Check rate limit untuk auto-scan
        can_proceed, cooldown_time = check_user_cooldown(message.author.id, "auto_scan")
        if not can_proceed:
            await message.add_reaction("⏳")
            return
        
        # Check daily limit
        if not await check_daily_limit(message.author.id):
            await message.add_reaction("📊")  # Indicate limit reached
            return
        
        # Create context wrapper
        class ContextWrapper:
            def __init__(self, message):
                self.message = message
                self.author = message.author
                self.channel = message.channel
            
            async def send(self, *args, **kwargs):
                return await self.channel.send(*args, **kwargs)
        
        ctx_wrapper = ContextWrapper(message)
        await process_analysis(ctx_wrapper, message.attachments[0], 'auto')

@bot.event
async def on_command_error(ctx, error):
    """Global error handler"""
    if isinstance(error, commands.CommandOnCooldown):
        await ctx.send(f"⏳ **Command on cooldown!** Try again in {error.retry_after:.1f}s")
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(f"❌ **Missing argument**: {error.param}")
    elif isinstance(error, commands.BadArgument):
        await ctx.send(f"❌ **Invalid argument**: {error}")
    elif isinstance(error, commands.CommandNotFound):
        # Ignore unknown commands
        pass
    else:
        logger.error(f"Unhandled error in {ctx.command}: {error}")
        await ctx.send("❌ **An unexpected error occurred.** Please try again later.")

# ============================
# CLEANUP TASKS
# ============================
async def cleanup_task():
    """Background task untuk cleanup cache dan temp files"""
    while True:
        try:
            await asyncio.sleep(3600)  # Run every hour
            
            # Clean expired cache
            current_time = time.time()
            expired_keys = [key for key, data in file_cache.items() 
                           if not is_cache_valid(data.get('timestamp', 0))]
            
            for key in expired_keys:
                del file_cache[key]
            
            if expired_keys:
                logger.info(f"🧹 Cleaned {len(expired_keys)} expired cache entries")
            
            # Clean temp files
            if os.path.exists(TEMP_DIR):
                for root, dirs, files in os.walk(TEMP_DIR):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            # Remove files older than 1 hour
                            if os.path.getctime(file_path) < current_time - 3600:
                                os.remove(file_path)
                        except Exception as e:
                            logger.error(f"Error cleaning temp file {file_path}: {e}")
            
            # Clean old database entries (optional - keep last 30 days)
            conn = sqlite3.connect('scanner.db')
            cursor = conn.cursor()
            
            cutoff_date = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
            cursor.execute('DELETE FROM daily_usage WHERE date < ?', (cutoff_date,))
            
            # Clean old scan history (keep last 1000 per user)
            cursor.execute('''
                DELETE FROM scan_history 
                WHERE id NOT IN (
                    SELECT id FROM scan_history 
                    ORDER BY timestamp DESC 
                    LIMIT 10000
                )
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error in cleanup task: {e}")

# ============================
# JALANKAN BOT
# ============================
if __name__ == "__main__":
    if not BOT_TOKEN:
        print("❌ FATAL ERROR: BOT_TOKEN tidak ada di environment variables.")
    else:
        print("🚀 Memulai Enhanced Lua Security Scanner Bot...")
        print("="*60)
        
        # Store startup time
        bot.start_time = time.time()
        
        try:
            # Start cleanup task
            loop = asyncio.get_event_loop()
            loop.create_task(cleanup_task())
            
            bot.run(BOT_TOKEN)
        except discord.errors.LoginFailure:
            print("❌ FATAL ERROR: Gagal login. Pastikan BOT_TOKEN Anda valid.")
        except KeyboardInterrupt:
            print("🛑 Bot dihentikan oleh user.")
        except Exception as e:
            print(f"❌ FATAL ERROR: Terjadi kesalahan saat menjalankan bot: {e}")
            logger.error(f"Fatal bot error: {e}")
