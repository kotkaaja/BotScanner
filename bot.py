import discord
import os
import zipfile
import shutil
import re
import json
import asyncio
import aiohttp
from typing import List, Tuple, Dict
import py7zr
import rarfile

# --- Konfigurasi ---
BOT_TOKEN = "YOUR_BOT_TOKEN_HERE"  # Ganti dengan token bot Anda
OPENAI_API_KEY = "YOUR_OPENAI_API_KEY"  # Atau gunakan API AI lainnya
ALERT_CHANNEL_ID = 1234567890123456789  # ID Channel untuk alert bahaya tinggi

ALLOWED_EXTENSIONS = ['.lua', '.txt', '.zip', '.7z', '.rar']
TEMP_DIR = "temp_scan"

# Sistem Level Bahaya
class DangerLevel:
    SAFE = 1           # Hijau - Aman
    SUSPICIOUS = 2     # Kuning - Mencurigakan tapi mungkin legitimate
    VERY_SUSPICIOUS = 3 # Oranye - Sangat mencurigakan (obfuscated/encoded)
    DANGEROUS = 4      # Merah - Sangat berbahaya (data theft)

# Pola berbahaya dengan konteks dan level
SUSPICIOUS_PATTERNS = {
    # Level 4 - DANGEROUS (Data Theft & Malicious)
    "discord.com/api/webhooks": {
        "level": DangerLevel.DANGEROUS,
        "description": "Discord webhook - sangat mungkin untuk mencuri data pengguna",
        "keywords": ["webhook", "discord", "api"],
        "context_clues": ["password", "username", "token", "data", "send"]
    },
    "pastebin.com": {
        "level": DangerLevel.DANGEROUS,
        "description": "Upload ke Pastebin - kemungkinan besar untuk mengirim data curian",
        "keywords": ["pastebin"],
        "context_clues": ["post", "upload", "data", "send"]
    },
    "hastebin.com": {
        "level": DangerLevel.DANGEROUS,
        "description": "Upload ke Hastebin - kemungkinan besar untuk mengirim data curian",
        "keywords": ["hastebin"],
        "context_clues": ["post", "upload", "data"]
    },
    
    # Level 3 - VERY SUSPICIOUS (Obfuscated/Encoded)
    "loadstring": {
        "level": DangerLevel.VERY_SUSPICIOUS,
        "description": "Eksekusi kode dinamis - sangat berbahaya jika berisi kode tersembunyi",
        "keywords": ["loadstring"],
        "safe_contexts": ["error handling", "configuration", "template"]
    },
    "LuaObfuscator.com": {
        "level": DangerLevel.VERY_SUSPICIOUS,
        "description": "Kode yang diobfuscate - menyembunyikan fungsi sebenarnya",
        "keywords": ["obfuscator", "obfuscate"]
    },
    "dofile": {
        "level": DangerLevel.VERY_SUSPICIOUS,
        "description": "Menjalankan file eksternal - berbahaya jika file tidak diketahui",
        "keywords": ["dofile"],
        "safe_contexts": ["config", "module", "library"]
    },
    
    # Level 2 - SUSPICIOUS (Might be legitimate)
    "io.open": {
        "level": DangerLevel.SUSPICIOUS,
        "description": "Membuka/membuat file - bisa legitimate untuk konfigurasi",
        "keywords": ["io.open"],
        "safe_contexts": ["config", "save", "log", "data", "settings", "profile"]
    },
    "os.execute": {
        "level": DangerLevel.SUSPICIOUS,
        "description": "Menjalankan perintah sistem - berbahaya jika tidak untuk fungsi legitimate",
        "keywords": ["os.execute"],
        "safe_contexts": ["utility", "tool", "helper"]
    },
    "socket.http": {
        "level": DangerLevel.SUSPICIOUS,
        "description": "Komunikasi HTTP - bisa legitimate untuk API atau update",
        "keywords": ["socket.http"],
        "safe_contexts": ["update", "api", "version", "check"]
    },
    "http.request": {
        "level": DangerLevel.SUSPICIOUS,
        "description": "Request HTTP - bisa legitimate untuk komunikasi API",
        "keywords": ["http.request"],
        "safe_contexts": ["api", "update", "version", "service"]
    },
    "sampGetPlayerNickname": {
        "level": DangerLevel.SUSPICIOUS,
        "description": "Mengambil nickname pemain - bisa legitimate untuk fitur game",
        "keywords": ["sampGetPlayerNickname"],
        "safe_contexts": ["display", "show", "interface", "ui", "feature"]
    },
    "sampGetCurrentServerAddress": {
        "level": DangerLevel.SUSPICIOUS,
        "description": "Mengambil alamat server - bisa legitimate untuk fitur reconnect",
        "keywords": ["sampGetCurrentServerAddress"],
        "safe_contexts": ["reconnect", "display", "info", "feature"]
    },
    "io.popen": {
        "level": DangerLevel.SUSPICIOUS,
        "description": "Membuka proses eksternal - berbahaya jika tidak untuk fungsi legitimate",
        "keywords": ["io.popen"],
        "safe_contexts": ["utility", "tool", "helper"]
    },
    "os.remove": {
        "level": DangerLevel.SUSPICIOUS,
        "description": "Menghapus file - bisa legitimate untuk cleanup",
        "keywords": ["os.remove"],
        "safe_contexts": ["cleanup", "temp", "cache", "old"]
    },
    "os.rename": {
        "level": DangerLevel.SUSPICIOUS,
        "description": "Mengubah nama file - bisa legitimate untuk manajemen file",
        "keywords": ["os.rename"],
        "safe_contexts": ["backup", "organize", "manage"]
    }
}

# --- AI Analysis dengan OpenAI ---
async def analyze_with_ai(code_snippet: str, detected_patterns: List[str]) -> Tuple[int, str]:
    """Menggunakan OpenAI GPT untuk menganalisis konteks kode"""
    try:
        prompt = f"""
        Analyze this Lua code snippet for malicious intent. Focus on context around these detected patterns: {', '.join(detected_patterns)}

        Code snippet:
        ```lua
        {code_snippet[:2000]}  # Limit to 2000 chars to avoid token limit
        ```

        Detected suspicious patterns: {', '.join(detected_patterns)}

        Please analyze:
        1. Is this usage legitimate (config files, game features, utilities)?
        2. Are there signs of data theft (sending personal info, passwords, player data)?
        3. Is the code obfuscated or trying to hide its purpose?
        4. Context around suspicious functions - are they used safely?
        5. Look for combinations that indicate malicious intent (e.g., sampGetPlayerNickname + webhook)

        Respond with a JSON object:
        {{
            "danger_level": 1-4,
            "is_legitimate": true/false,
            "confidence": 0-100,
            "reason": "detailed explanation of your analysis",
            "red_flags": ["list", "of", "concerning", "patterns"],
            "safe_indicators": ["list", "of", "legitimate", "usage", "signs"]
        }}

        Danger levels:
        1 = Safe (legitimate usage)
        2 = Suspicious but likely safe (needs monitoring)
        3 = Very suspicious (obfuscated, potentially malicious)
        4 = Dangerous (clear signs of data theft or malicious activity)
        """
        
        response = openai_client.chat.completions.create(
            model="gpt-4o-mini",  # Using gpt-4o-mini as it's more cost-effective
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert analyzing Lua scripts for malicious behavior. Focus on identifying data theft, malware, and obfuscated code."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=800,
            temperature=0.1
        )
        
        ai_response = response.choices[0].message.content
        
        # Try to parse JSON response
        try:
            analysis = json.loads(ai_response)
            return analysis.get('danger_level', 2), analysis.get('reason', 'AI analysis completed')
        except json.JSONDecodeError:
            # Fallback to simple parsing
            if 'danger_level": 4' in ai_response or 'dangerous' in ai_response.lower():
                return 4, "AI detected dangerous patterns"
            elif 'danger_level": 3' in ai_response or 'very suspicious' in ai_response.lower():
                return 3, "AI detected very suspicious patterns"
            elif 'danger_level": 1' in ai_response or 'legitimate' in ai_response.lower():
                return 1, "AI confirmed legitimate usage"
            else:
                return 2, "AI analysis inconclusive"
        
    except Exception as e:
        print(f"AI Analysis error: {e}")
        return await simple_ai_analysis(code_snippet, detected_patterns)

async def simple_ai_analysis(code_snippet: str, detected_patterns: List[str]) -> Tuple[int, str]:
    """Fallback analisis sederhana berdasarkan konteks jika OpenAI gagal"""
    code_lower = code_snippet.lower()
    
    # Check untuk indikasi data theft dengan kombinasi berbahaya
    high_risk_combinations = [
        ["sampgetplayernickname", "webhook"],
        ["sampgetplayernickname", "http.request"],
        ["sampgetcurrentserveraddress", "webhook"],
        ["password", "webhook"],
        ["username", "sendtodiscordembed"],
        ["player", "data", "http"]
    ]
    
    danger_score = 0
    
    # Check kombinasi berbahaya
    for combo in high_risk_combinations:
        if all(pattern in code_lower for pattern in combo):
            danger_score += 3
    
    # Check untuk indikasi data theft
    data_theft_indicators = [
        "password", "pass", "login", "username", "token", 
        "webhook", "send", "post", "upload", "steal", "data"
    ]
    
    # Check untuk legitimate usage
    legitimate_indicators = [
        "config", "setting", "save", "load", "profile", 
        "log", "temp", "cache", "backup", "feature", "display", "show"
    ]
    
    # Hitung skor
    theft_score = sum(1 for indicator in data_theft_indicators if indicator in code_lower)
    legit_score = sum(1 for indicator in legitimate_indicators if indicator in code_lower)
    
    # Tambah skor bahaya
    danger_score += theft_score
    
    # Analisis obfuscation
    if any(pattern in code_lower for pattern in ["obfuscator", "loadstring", "eval"]):
        danger_score += 2
    
    # Tentukan level berdasarkan skor
    if danger_score >= 5 or theft_score >= 3:
        return 4, f"High probability of data theft (danger score: {danger_score})"
    elif danger_score >= 3 or "obfuscator" in code_lower:
        return 3, f"Code appears obfuscated or highly suspicious (danger score: {danger_score})"
    elif legit_score > theft_score and danger_score < 2:
        return 1, f"Appears legitimate (legit indicators: {legit_score}, danger score: {danger_score})"
    else:
        return 2, f"Suspicious but context unclear (danger score: {danger_score})"

# --- Fungsi utilitas untuk ekstraksi file ---
def extract_archive(file_path: str, extract_to: str) -> bool:
    """Extract berbagai format archive"""
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

# --- Fungsi scanner yang ditingkatkan ---
async def scan_file_content(file_path: str) -> Tuple[List[Dict], str]:
    """Scan file dan analisis dengan AI"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        detected_issues = []
        detected_patterns = []
        
        for pattern, info in SUSPICIOUS_PATTERNS.items():
            if re.search(pattern, content, re.IGNORECASE):
                detected_patterns.append(pattern)
                
                # Extract context around the pattern
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
        
        if detected_issues:
            # Analisis dengan AI
            ai_level, ai_reason = await analyze_with_ai(content, detected_patterns)
            
            # Adjust level berdasarkan AI analysis
            max_level = max(issue['level'] for issue in detected_issues)
            final_level = max(max_level, ai_level)
            
            return detected_issues, content
        
        return [], content
        
    except Exception as e:
        print(f"Error scanning file {file_path}: {e}")
        return [], ""

# --- Bot Discord ---
intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)

def get_level_emoji_color(level: int) -> Tuple[str, int]:
    """Return emoji and color for danger level"""
    if level == DangerLevel.SAFE:
        return "🟢", 0x00FF00
    elif level == DangerLevel.SUSPICIOUS:
        return "🟡", 0xFFFF00
    elif level == DangerLevel.VERY_SUSPICIOUS:
        return "🟠", 0xFF8C00
    else:  # DANGEROUS
        return "🔴", 0xFF0000

@client.event
async def on_ready():
    print(f'🤖 Bot scanner siap! Logged in as {client.user}')
    if not os.path.exists(TEMP_DIR):
        os.makedirs(TEMP_DIR)

@client.event
async def on_message(message):
    if message.author == client.user or not message.attachments:
        return

    attachment = message.attachments[0]
    file_extension = os.path.splitext(attachment.filename)[1].lower()

    if file_extension not in ALLOWED_EXTENSIONS:
        supported_formats = ", ".join(ALLOWED_EXTENSIONS)
        await message.channel.send(
            f"❌ **Format File Tidak Didukung**\n"
            f"📁 File: `{attachment.filename}`\n"
            f"✅ Format yang didukung: `{supported_formats}`\n"
            f"💡 Silakan konversi file Anda ke salah satu format yang didukung."
        )
        return

    # Download file
    download_path = os.path.join(TEMP_DIR, attachment.filename)
    await attachment.save(download_path)
    
    all_issues = []
    scanned_files = []
    
    try:
        # Handle archive files
        if file_extension in ['.zip', '.7z', '.rar']:
            extract_folder = os.path.join(TEMP_DIR, "extracted")
            
            if extract_archive(download_path, extract_folder):
                for root, _, files in os.walk(extract_folder):
                    for file in files:
                        if file.endswith(('.lua', '.txt')):
                            file_path = os.path.join(root, file)
                            issues, content = await scan_file_content(file_path)
                            if issues:
                                relative_path = os.path.relpath(file_path, extract_folder)
                                scanned_files.append(relative_path)
                                all_issues.extend([(relative_path, issue) for issue in issues])
                            else:
                                relative_path = os.path.relpath(file_path, extract_folder)
                                scanned_files.append(relative_path)
                
                shutil.rmtree(extract_folder)
            else:
                await message.channel.send(f"⚠️ Gagal mengekstrak file `{attachment.filename}`. File mungkin rusak atau terproteksi.")
                os.remove(download_path)
                return
        else:
            # Handle single file
            issues, content = await scan_file_content(download_path)
            scanned_files.append(attachment.filename)
            if issues:
                all_issues.extend([(attachment.filename, issue) for issue in issues])

        # Tentukan level bahaya tertinggi
        max_level = DangerLevel.SAFE
        if all_issues:
            max_level = max(issue[1]['level'] for issue in all_issues)

        # Buat laporan berdasarkan level
        emoji, color = get_level_emoji_color(max_level)
        
        embed = discord.Embed(
            title=f"{emoji} Hasil Scan: `{attachment.filename}`",
            color=color
        )
        
        if max_level == DangerLevel.SAFE:
            embed.description = "✅ **File Aman** - Tidak ditemukan pola berbahaya"
            embed.add_field(
                name="📊 Files Scanned", 
                value=f"{len(scanned_files)} file(s)", 
                inline=True
            )
        else:
            # Group issues by level
            issues_by_level = {}
            for filepath, issue in all_issues:
                level = issue['level']
                if level not in issues_by_level:
                    issues_by_level[level] = []
                issues_by_level[level].append((filepath, issue))
            
            # Build report
            description = ""
            if max_level == DangerLevel.DANGEROUS:
                description = "🚨 **BAHAYA TINGGI** - File mengandung kode berbahaya yang dapat mencuri data!"
            elif max_level == DangerLevel.VERY_SUSPICIOUS:
                description = "⚠️ **SANGAT MENCURIGAKAN** - File mengandung kode tersembunyi atau ter-obfuscate"
            elif max_level == DangerLevel.SUSPICIOUS:
                description = "🤔 **MENCURIGAKAN** - File menggunakan fungsi berisiko tapi mungkin legitimate"
            
            embed.description = description
            
            # Add details for each level
            for level in sorted(issues_by_level.keys(), reverse=True):
                level_emoji, _ = get_level_emoji_color(level)
                issues = issues_by_level[level]
                
                field_value = ""
                for filepath, issue in issues[:3]:  # Limit to 3 per level
                    field_value += f"📁 `{filepath}` (Line {issue['line']})\n"
                    field_value += f"🔍 Pattern: `{issue['pattern']}`\n"
                    field_value += f"💡 {issue['description']}\n\n"
                
                if len(issues) > 3:
                    field_value += f"... dan {len(issues) - 3} issue lainnya\n"
                
                level_names = {
                    DangerLevel.DANGEROUS: "Sangat Berbahaya",
                    DangerLevel.VERY_SUSPICIOUS: "Sangat Mencurigakan", 
                    DangerLevel.SUSPICIOUS: "Mencurigakan"
                }
                
                embed.add_field(
                    name=f"{level_emoji} {level_names.get(level, 'Unknown')}",
                    value=field_value,
                    inline=False
                )
        
        # Add footer
        embed.set_footer(text=f"Scanned by Lua Security Bot • {len(scanned_files)} files analyzed")
        
        await message.channel.send(embed=embed)
        
        # Send alert to dedicated channel for high-risk files
        if max_level >= DangerLevel.DANGEROUS and ALERT_CHANNEL_ID:
            try:
                alert_channel = client.get_channel(ALERT_CHANNEL_ID)
                if alert_channel:
                    alert_embed = discord.Embed(
                        title="🚨 HIGH RISK FILE DETECTED",
                        description=f"User {message.author.mention} uploaded a dangerous file: `{attachment.filename}`",
                        color=0xFF0000
                    )
                    await alert_channel.send(embed=alert_embed)
            except Exception as e:
                print(f"Failed to send alert: {e}")

    except Exception as e:
        await message.channel.send(f"❌ Error scanning file: {str(e)}")
    finally:
        # Cleanup
        if os.path.exists(download_path):
            os.remove(download_path)

# Run bot
if __name__ == "__main__":
    if BOT_TOKEN == "YOUR_BOT_TOKEN_HERE":
        print("⚠️ Please set your BOT_TOKEN in the configuration section!")
    else:
        client.run(BOT_TOKEN)