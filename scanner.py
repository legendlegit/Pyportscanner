#!/usr/bin/env python3

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Optional, Dict, Any
from datetime import datetime


def parse_ports(ports_str: str) -> List[int]:
    """
    Parse a port string like:
    "80", "80,443,8080", "1-1024", "22,80,8000-8100"
    into a sorted list of unique ints.
    """
    ports = set()

    for part in ports_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            start = int(start_str)
            end = int(end_str)
            if start > end:
                start, end = end, start
            for p in range(start, end + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)

    return sorted(ports)


def resolve_target(target: str) -> str:
    """
    Resolve a hostname or IP string to an IP address.
    Returns the original string if resolution fails.
    """
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return target


def scan_port(host: str, port: int, timeout: float) -> Tuple[int, bool, Optional[str]]:
    """
    Scan a single TCP port.

    Returns (port, is_open, banner_or_None).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    banner = None
    try:
        result = sock.connect_ex((host, port))
        if result == 0:
            # Port open. Optional: try to grab a short banner.
            try:
                sock.sendall(b"\r\n")
                sock.settimeout(1.0)
                data = sock.recv(1024)
                if data:
                    banner = data.decode(errors="ignore").strip()
            except Exception:
                banner = None
            return port, True, banner
        else:
            return port, False, None
    except Exception:
        return port, False, None
    finally:
        sock.close()


def scan_host(
    target: str,
    ports: List[int],
    timeout: float,
    threads: int,
) -> Dict[str, Any]:
    """
    Scan all ports for a single target.

    Returns a dict with:
    - target, resolved_ip, results: list of {port, open, banner}
    """
    resolved_ip = resolve_target(target)
    results = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_port = {
            executor.submit(scan_port, resolved_ip, port, timeout): port
            for port in ports
        }

        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                p, is_open, banner = future.result()
            except Exception:
                p, is_open, banner = port, False, None
            results.append(
                {
                    "port": p,
                    "open": is_open,
                    "banner": banner,
                }
            )

    results.sort(key=lambda x: x["port"])

    return {
        "target": target,
        "resolved_ip": resolved_ip,
        "results": results,
    }


def scan_multiple_hosts(
    targets: List[str],
    ports: List[int],
    timeout: float,
    threads: int,
) -> Dict[str, Any]:
    """
    Scan multiple targets sequentially (each with its own threadpool).
    """
    scan_started = datetime.utcnow().isoformat() + "Z"
    all_results = []

    for t in targets:
        host_result = scan_host(t, ports, timeout, threads)
        all_results.append(host_result)

    scan_finished = datetime.utcnow().isoformat() + "Z"

    return {
        "started_at": scan_started,
        "finished_at": scan_finished,
        "targets": all_results,
    }
