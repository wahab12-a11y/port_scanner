#!/usr/bin/env python3
\"\"\"W4R-LOCK Port Scanner (professional starter)

Usage examples:
  python3 port_scanner.py --target 127.0.0.1
  python3 port_scanner.py --target example.com --ports 1-1024 --threads 200 --grab --output results.json --csv results.csv

Notes: Defensive/educational use only.
\"\"\"
import argparse, socket, threading, queue, json, time, csv, subprocess, shutil, os
from typing import List

DEFAULT_PORTS = [21,22,23,25,53,80,110,139,143,389,443,445,3306,3389,5900,8080]

PORT_SERVICES = {
    21: 'ftp',22:'ssh',23:'telnet',25:'smtp',53:'dns',80:'http',110:'pop3',139:'netbios-ssn',
    143:'imap',389:'ldap',443:'https',445:'microsoft-ds',3306:'mysql',3389:'rdp',5900:'vnc',8080:'http-proxy'
}

BANNER_KEYWORDS = {
    'ssh': ['ssh-'],
    'http': ['http/','server:','nginx','apache'],
    'ftp': ['ftp'],
    'mysql': ['mysql'],
    'smb': ['smb','samba','microsoft'],
    'rdp': ['rdp']
}

def parse_ports(ports_str: str) -> List[int]:
    ports = set()
    for part in ports_str.split(','):
        part = part.strip()
        if '-' in part:
            a,b = part.split('-',1)
            ports.update(range(int(a), int(b)+1))
        else:
            if part:
                ports.add(int(part))
    return sorted(p for p in ports if 1<=p<=65535)

def grab_banner(host: str, port: int, timeout: float=1.0) -> str:
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((host, port))
        try:
            data = s.recv(4096)
            return data.decode(errors='ignore').strip()
        except Exception:
            return ""
        finally:
            s.close()
    except Exception:
        return ""

def detect_service(port:int, banner:str) -> str:
    if port in PORT_SERVICES:
        return PORT_SERVICES[port]
    low = (banner or "").lower()
    for svc, keys in BANNER_KEYWORDS.items():
        for k in keys:
            if k.lower() in low:
                return svc
    return "unknown"

class Scanner:
    def __init__(self, target: str, ports: List[int], threads: int=100, timeout: float=1.0, grab: bool=False):
        self.target = target
        self.ports = ports
        self.threads = max(1, min(threads, 1000))
        self.timeout = timeout
        self.grab = grab
        self.q = queue.Queue()
        self.lock = threading.Lock()
        self.results = []

    def worker(self):
        while True:
            try:
                port = self.q.get_nowait()
            except queue.Empty:
                return
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            try:
                res = sock.connect_ex((self.target, port))
                if res == 0:
                    banner = ""
                    if self.grab:
                        banner = grab_banner(self.target, port, timeout=0.8)
                    svc = detect_service(port, banner)
                    with self.lock:
                        self.results.append({"port": port, "service": svc, "banner": banner})
                sock.close()
            except Exception:
                sock.close()
            finally:
                self.q.task_done()

    def run(self):
        for p in self.ports:
            self.q.put(p)
        threads = []
        for _ in range(min(self.threads, len(self.ports))):
            t = threading.Thread(target=self.worker, daemon=True)
            t.start()
            threads.append(t)
        start = time.time()
        self.q.join()
        duration = time.time() - start
        return {"target": self.target, "scanned_ports": len(self.ports), "open_ports": sorted(self.results, key=lambda x: x['port']), "duration_s": duration}

def run_nmap(target: str, ports: str) -> str:
    if not shutil.which('nmap'):
        return "nmap-not-installed"
    try:
        args = ['nmap','-sV','-p',ports,target]
        proc = subprocess.run(args, capture_output=True, text=True, timeout=180)
        return proc.stdout
    except Exception as e:
        return f"nmap-error: {e}"

def save_results_json(data, path):
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)

def save_results_csv(data, path):
    with open(path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['target','port','service','banner'])
        for entry in data:
            target = entry.get('target')
            for p in entry.get('open_ports', []):
                writer.writerow([target, p.get('port'), p.get('service'), p.get('banner')])

def main():
    parser = argparse.ArgumentParser(description="W4R-LOCK Port Scanner (professional starter)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--target", help="Single hostname or IP to scan")
    group.add_argument("--targets", help="File with hosts to scan (one per line)")
    parser.add_argument("--ports", default=",".join(str(p) for p in DEFAULT_PORTS),
                        help="Ports to scan (e.g. '22,80,443' or '1-1024')")
    parser.add_argument("--threads", type=int, default=100, help="Number of concurrent threads (default 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds (default 1.0)")
    parser.add_argument("--grab", action="store_true", help="Attempt to grab service banners for open ports")
    parser.add_argument("--nmap", action="store_true", help="Run nmap -sV for discovered ports (requires nmap installed)")
    parser.add_argument("--output", default="results.json", help="Write results to JSON file")
    parser.add_argument("--csv", help="Write results to CSV file (optional)")
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    all_results = []
    targets = []
    if args.target:
        targets = [args.target.strip()]
    else:
        with open(args.targets, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]

    for t in targets:
        print(f"[+] Scanning {t} ({len(ports)} ports) with {args.threads} threads...")
        s = Scanner(t, ports, threads=args.threads, timeout=args.timeout, grab=args.grab)
        result = s.run()
        print(f"[+] Done: {len(result['open_ports'])} open ports found in {result['duration_s']:.2f}s")
        for op in result['open_ports']:
            port = op['port']
            svc = op.get('service')
            banner = op.get('banner')
            if banner:
                print(f"    - {port} open (service: {svc}, banner: {banner[:120]})")
            else:
                print(f"    - {port} open (service: {svc})")
        all_results.append(result)

        if args.nmap and result['open_ports']:
            ports_csv = ",".join(str(x['port']) for x in result['open_ports'])
            print("[*] Running nmap -sV for detected ports...")
            nmap_out = run_nmap(t, ports_csv)
            print(nmap_out[:800])

    save_results_json(all_results, args.output)
    if args.csv:
        save_results_csv(all_results, args.csv)
    print(f"[+] Results written to {args.output}")
    # write latest results to a static file used by dashboard
    try:
        import shutil as _sh; _sh.copy(args.output, os.path.join('dashboard','latest_results.json'))
    except Exception:
        pass

if __name__ == '__main__':
    main()
