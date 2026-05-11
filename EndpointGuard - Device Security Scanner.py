import psutil
import socket
import json
import logging
import datetime
import os
import platform

logging.basicConfig(level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

SUSPICIOUS_PROCESSES = [
    'keylogger', 'spyware', 'trojan', 'malware',
    'botnet', 'backdoor', 'rootkit', 'worm',
    'cryptominer', 'ransomware'
]

SUSPICIOUS_PORTS = [4444, 1337, 31337, 6667, 
                    6666, 9999, 8888, 2222]

def scan_processes():
    logger.info("Scanning running processes...")
    suspicious = []
    all_processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'status']):
        try:
            info = proc.info
            all_processes.append(info)
            name_lower = info['name'].lower()
            for threat in SUSPICIOUS_PROCESSES:
                if threat in name_lower:
                    suspicious.append({
                        "pid": info['pid'],
                        "name": info['name'],
                        "reason": f"Matches known threat: {threat}",
                        "risk": "HIGH"
                    })
                    logger.warning(f"SUSPICIOUS: {info['name']} (PID {info['pid']})")
        except Exception:
            pass
    logger.info(f"Total processes scanned: {len(all_processes)}")
    logger.info(f"Suspicious processes found: {len(suspicious)}")
    return all_processes, suspicious

def scan_network():
    logger.info("Scanning network connections...")
    try:
        connections = psutil.net_connections(kind='inet')
        suspicious = []
        all_connections = []
        for conn in connections:
            try:
                if conn.raddr:
                    entry = {
                        "local": str(conn.laddr),
                        "remote": str(conn.raddr),
                        "status": conn.status,
                        "pid": conn.pid
                    }
                    all_connections.append(entry)
                    if conn.raddr.port in SUSPICIOUS_PORTS:
                        suspicious.append(entry)
            except Exception:
                pass
        return all_connections, suspicious
    except PermissionError:
        logger.warning("Network scan skipped - Android permission restricted")
        return [], []

def scan_startup():
    logger.info("Scanning startup programs...")
    startup_items = []
    system = platform.system()
    if system == "Windows":
        import winreg
        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    startup_items.append({
                        "name": name,
                        "path": value,
                        "system": "Windows Registry"
                    })
                    i += 1
                except OSError:
                    break
        except Exception as e:
            logger.error(f"Could not read registry: {e}")
    elif system == "Linux":
        startup_paths = [
            "/etc/init.d/",
            os.path.expanduser("~/.config/autostart/")
        ]
        for path in startup_paths:
            if os.path.exists(path):
                for f in os.listdir(path):
                    startup_items.append({
                        "name": f,
                        "path": os.path.join(path, f),
                        "system": "Linux Startup"
                    })
    logger.info(f"Startup items found: {len(startup_items)}")
    return startup_items

def generate_report(processes, suspicious_procs,
                   connections, suspicious_conns,
                   startup_items):
    report = {
        "scan_time": datetime.datetime.now().isoformat(),
        "system": platform.system(),
        "hostname": socket.gethostname(),
        "summary": {
            "total_processes": len(processes),
            "suspicious_processes": len(suspicious_procs),
            "total_connections": len(connections),
            "suspicious_connections": len(suspicious_conns),
            "startup_items": len(startup_items)
        },
        "suspicious_processes": suspicious_procs,
        "suspicious_connections": suspicious_conns,
        "startup_items": startup_items,
        "threat_level": "HIGH" if (
            suspicious_procs or suspicious_conns
        ) else "LOW"
    }
    filename = f"endpoint_scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w') as f:
        json.dump(report, f, indent=2)
    logger.info(f"Report saved to {filename}")
    return report

print(f"{'='*50}")
print(f"  Endpoint Security Scanner")
print(f"  System: {platform.system()}")
print(f"  Time: {datetime.datetime.now()}")
print(f"{'='*50}")

processes, suspicious_procs = scan_processes()
connections, suspicious_conns = scan_network()
startup_items = scan_startup()
report = generate_report(
    processes, suspicious_procs,
    connections, suspicious_conns,
    startup_items
)

print(f"\n{'='*50}")
print(f"  SCAN SUMMARY")
print(f"{'='*50}")
print(f"  Processes Scanned : {report['summary']['total_processes']}")
print(f"  Suspicious Found  : {report['summary']['suspicious_processes']}")
print(f"  Network Connections: {report['summary']['total_connections']}")
print(f"  Suspicious Connections: {report['summary']['suspicious_connections']}")
print(f"  Startup Items     : {report['summary']['startup_items']}")
print(f"  Threat Level      : {report['threat_level']}")
print(f"{'='*50}")