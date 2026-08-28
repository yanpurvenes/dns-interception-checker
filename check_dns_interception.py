#!/usr/bin/env python3
"""
check_dns_interception.py — Детектор вмешательства ТСПУ (РКН) и провайдеров в DNS-запросы.

Проверяет 3 ключевых протокола:
  1. UDP :53  — открытый DNS (проверка на инъекции ТСПУ, ложный NXDOMAIN, флаг AA, подмену IP).
  2. DoT :853 — DNS-over-TLS (прямой TLS-туннель на порт 853 с проверкой блокировки порта/SNI).
  3. DoH :443 — DNS-over-HTTPS (RFC 8484 через HTTP/2 на веб-порт 443).

Сигнатуры детекции:
  • Флаг AA (Authoritative Answer) в NXDOMAIN от рекурсивного резолвера.
  • Ложный NXDOMAIN / SERVFAIL для реально существующих доменов.
  • Подмена IP-адресов на заглушки (127.0.0.1, 0.0.0.0, 195.82.146.120 и т.д.).
  • Сравнение открытого UDP:53 с зашифрованными каналами DoT:853 и DoH:443.
  • Тест тотального перехвата порта 53 (запрос на фиктивный IP 192.0.2.1).
  • Детекция гонки пакетов (инъекция фальшивки + приход оригинального ответа).
"""

import sys
import os
import time
import socket
import struct
import ssl
import json
import argparse
import random
import subprocess
import urllib.request
import urllib.parse
import concurrent.futures
from typing import List, Dict, Tuple, Optional, Any

# ============================ ЦВЕТА И СТИЛИ ============================
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BLUE = "\033[94m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

# ============================ КОНФИГУРАЦИЯ СЕРВЕРОВ ============================
DEFAULT_SERVERS = [
    {
        "name": "Google DNS",
        "ip": "8.8.8.8",
        "dot_host": "dns.google",
        "doh_url": "https://dns.google/dns-query",
    },
    {
        "name": "Cloudflare DNS",
        "ip": "1.1.1.1",
        "dot_host": "one.one.one.one",
        "doh_url": "https://cloudflare-dns.com/dns-query",
    },
    {
        "name": "Quad9 DNS",
        "ip": "9.9.9.9",
        "dot_host": "dns.quad9.net",
        "doh_url": "https://dns.quad9.net/dns-query",
    },
    {
        "name": "NextDNS",
        "ip": "45.90.28.0",
        "dot_host": "dns.nextdns.io",
        "doh_url": "https://dns.nextdns.io/dns-query",
    },
    {
        "name": "AdGuard DNS",
        "ip": "94.140.14.14",
        "dot_host": "dns.adguard-dns.com",
        "doh_url": "https://dns.adguard-dns.com/dns-query",
    },
    {
        "name": "Yandex DNS (RU)",
        "ip": "77.88.8.8",
        "dot_host": "common.dot.dns.yandex.net",
        "doh_url": "https://common.dot.dns.yandex.net/dns-query",
    },
]

# ============================ БАЗА ДОМЕНОВ ============================
# Категории доменов для детального тестирования
DOMAIN_DATABASE = [
    # --- Соцсети и мессенджеры ---
    ("instagram.com", "Социальные сети", "social"),
    ("facebook.com", "Социальные сети", "social"),
    ("x.com", "Социальные сети", "social"),
    ("twitter.com", "Социальные сети", "social"),
    ("threads.net", "Социальные сети", "social"),
    ("linkedin.com", "Социальные сети", "social"),
    ("discord.com", "Мессенджеры", "social"),

    # --- Видео, Музыка и Стриминг ---
    ("youtube.com", "Видео / Стриминг", "streaming"),
    ("vimeo.com", "Видео / Стриминг", "streaming"),
    ("dailymotion.com", "Видео / Стриминг", "streaming"),
    ("soundcloud.com", "Музыка / Стриминг", "streaming"),

    # --- Торренты, Трекеры и Библиотеки ---
    ("rutracker.org", "Торренты / Трекеры", "torrents"),
    ("flibusta.is", "Библиотеки", "torrents"),
    ("rutor.info", "Торренты / Трекеры", "torrents"),
    ("kinozal.tv", "Торренты / Трекеры", "torrents"),
    ("nnmclub.to", "Торренты / Трекеры", "torrents"),
    ("lostfilm.tv", "Торренты / Сериалы", "torrents"),

    # --- СМИ и Новостные издания ---
    ("meduza.io", "СМИ / Новости", "media"),
    ("zona.media", "СМИ / Новости", "media"),
    ("novayagazeta.eu", "СМИ / Новости", "media"),
    ("dw.com", "СМИ / Новости", "media"),
    ("bbc.com", "СМИ / Новости", "media"),
    ("svoboda.org", "СМИ / Новости", "media"),
    ("currenttime.tv", "СМИ / Новости", "media"),
    ("theins.ru", "СМИ / Новости", "media"),
    ("holod.media", "СМИ / Новости", "media"),
    ("istories.media", "СМИ / Новости", "media"),
    ("republic.ru", "СМИ / Новости", "media"),
    ("moscowtimes.ru", "СМИ / Новости", "media"),

    # --- VPN, Proxy, Анонимайзеры и Форумы обхода ---
    ("ntc.party", "Форум обхода ТСПУ", "vpn"),
    ("torproject.org", "Анонимизация / Tor", "vpn"),
    ("proton.me", "VPN / Защита почты", "vpn"),
    ("protonvpn.com", "VPN сервис", "vpn"),
    ("mullvad.net", "VPN сервис", "vpn"),
    ("amnezia.org", "VPN протоколы", "vpn"),
    ("v2ray.com", "VPN / Прокси протоколы", "vpn"),
    ("shadowsocks.org", "VPN / Прокси протоколы", "vpn"),

    # --- Сервисы, Архивы и Платформы ---
    ("archive.org", "Веб-Архив", "services"),
    ("patreon.com", "Краудфандинг", "services"),
    ("notion.so", "Рабочее пространство", "services"),

    # --- Контрольные домены (Легальные / Не блокируемые в РФ) ---
    ("google.com", "Контрольный (Чистый)", "control"),
    ("wikipedia.org", "Контрольный (Чистый)", "control"),
    ("github.com", "Контрольный (Чистый)", "control"),
    ("yandex.ru", "Контрольный (Чистый)", "control"),
    ("habr.com", "Контрольный (Чистый)", "control"),
    ("vk.com", "Контрольный (Чистый)", "control"),
]

# Стандартный набор (топ 18 самых показательных доменов)
DEFAULT_SELECTED_DOMAINS = [
    "youtube.com",
    "rutracker.org",
    "instagram.com",
    "facebook.com",
    "x.com",
    "twitter.com",
    "threads.net",
    "discord.com",
    "meduza.io",
    "zona.media",
    "dw.com",
    "bbc.com",
    "ntc.party",
    "torproject.org",
    "proton.me",
    "mullvad.net",
    "flibusta.is",
    "archive.org",
    "google.com",
    "wikipedia.org",
    "github.com",
]

BOGON_IPS = {
    "127.0.0.1", "0.0.0.0", "10.0.0.0", "10.254.254.254", 
    "195.82.146.120", "195.82.146.121", "80.80.80.80"
}

RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


# ============================ DNS ПАРСИНГ ============================

def build_dns_query(domain: str, tx_id: Optional[int] = None, qtype: int = 1, edns: bool = True) -> bytes:
    """Создает бинарный DNS-пакет запроса с опциональным EDNS0."""
    if tx_id is None:
        tx_id = random.randint(1, 65535)
    # RD = 1 (Recursion Desired) -> 0x0100
    arcount = 1 if edns else 0
    header = struct.pack("!HHHHHH", tx_id, 0x0100, 1, 0, 0, arcount)
    
    qname = b""
    for part in domain.strip(".").split("."):
        encoded = part.encode("utf-8")
        qname += struct.pack("!B", len(encoded)) + encoded
    qname += b"\x00"
    question = qname + struct.pack("!HH", qtype, 1)  # QType, Class IN (1)
    
    additional = b""
    if edns:
        # OPT pseudo-record: Name 0x00, Type 41 (OPT), UDP size 1232, RCODE 0, Version 0, Flags 0, RDLENGTH 0
        additional = struct.pack("!BHHIH", 0, 41, 1232, 0, 0)
        
    return header + question + additional


def parse_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Парсит доменное имя с учетом сжатия (pointers 0xC0)."""
    parts = []
    visited = set()
    orig_offset = offset
    jumped = False
    
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            ptr = struct.unpack("!H", data[offset:offset+2])[0] & 0x3FFF
            if ptr in visited:
                break
            visited.add(ptr)
            if not jumped:
                orig_offset = offset + 2
                jumped = True
            offset = ptr
        elif length > 0:
            offset += 1
            if offset + length <= len(data):
                parts.append(data[offset:offset+length].decode("utf-8", "replace"))
                offset += length
            else:
                break
        else:
            offset += 1
            break
            
    name = ".".join(parts)
    next_offset = orig_offset if jumped else offset
    return name, next_offset


def parse_dns_response(data: bytes) -> Optional[Dict[str, Any]]:
    """Детально разбирает бинарный ответ DNS."""
    if len(data) < 12:
        return None
    tx_id, flags_raw, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    
    qr = (flags_raw >> 15) & 1
    opcode = (flags_raw >> 11) & 0xF
    aa = (flags_raw >> 10) & 1
    tc = (flags_raw >> 9) & 1
    rd = (flags_raw >> 8) & 1
    ra = (flags_raw >> 7) & 1
    ad = (flags_raw >> 5) & 1
    cd = (flags_raw >> 4) & 1
    rcode = flags_raw & 0xF
    
    flags_list = []
    if qr: flags_list.append("qr")
    if aa: flags_list.append("aa")
    if tc: flags_list.append("tc")
    if rd: flags_list.append("rd")
    if ra: flags_list.append("ra")
    if ad: flags_list.append("ad")
    if cd: flags_list.append("cd")
    
    offset = 12
    questions = []
    for _ in range(qdcount):
        if offset >= len(data): break
        qname, offset = parse_name(data, offset)
        if offset + 4 <= len(data):
            qtype, qclass = struct.unpack("!HH", data[offset:offset+4])
            offset += 4
            questions.append({"name": qname, "type": qtype, "class": qclass})
            
    answers = []
    ips = []
    min_ttl = 999999
    for _ in range(ancount):
        if offset >= len(data): break
        aname, offset = parse_name(data, offset)
        if offset + 10 <= len(data):
            atype, aclass, attl, ardlen = struct.unpack("!HHIH", data[offset:offset+10])
            offset += 10
            rdata_raw = data[offset:offset+ardlen]
            val = None
            if atype == 1 and ardlen == 4:  # A record
                val = socket.inet_ntoa(rdata_raw)
                ips.append(val)
                min_ttl = min(min_ttl, attl)
            elif atype == 28 and ardlen == 16:  # AAAA record
                val = socket.inet_ntop(socket.AF_INET6, rdata_raw)
                ips.append(val)
                min_ttl = min(min_ttl, attl)
            elif atype == 5:  # CNAME
                val, _ = parse_name(data, offset)
            offset += ardlen
            answers.append({"name": aname, "type": atype, "ttl": attl, "value": val})
            
    return {
        "tx_id": tx_id,
        "flags_raw": flags_raw,
        "flags": flags_list,
        "qr": bool(qr),
        "aa": bool(aa),
        "tc": bool(tc),
        "rd": bool(rd),
        "ra": bool(ra),
        "ad": bool(ad),
        "cd": bool(cd),
        "opcode": opcode,
        "rcode": rcode,
        "rcode_str": RCODE_NAMES.get(rcode, f"RCODE_{rcode}"),
        "qdcount": qdcount,
        "ancount": ancount,
        "nscount": nscount,
        "arcount": arcount,
        "questions": questions,
        "answers": answers,
        "ips": ips,
        "ttl": min_ttl if ips else 0,
        "raw_len": len(data),
    }


# ============================ СЕТЕВЫЕ ЗАПРОСЫ ============================

def query_udp_53(domain: str, server_ip: str, timeout: float = 2.0, capture_all: bool = False) -> Tuple[bool, List[Dict[str, Any]], float, str]:
    """Отправляет стандартный UDP DNS запрос на порт 53."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    tx_id = random.randint(10000, 60000)
    query = build_dns_query(domain, tx_id=tx_id)
    
    t0 = time.perf_counter()
    responses = []
    err = ""
    try:
        sock.sendto(query, (server_ip, 53))
        first_wait = timeout
        while True:
            t_rem = first_wait - (time.perf_counter() - t0)
            if t_rem <= 0:
                break
            sock.settimeout(0.35 if (responses and capture_all) else t_rem)
            try:
                data, addr = sock.recvfrom(2048)
                el = (time.perf_counter() - t0) * 1000
                parsed = parse_dns_response(data)
                if parsed and parsed["tx_id"] == tx_id:
                    parsed["elapsed_ms"] = el
                    parsed["src_addr"] = addr
                    responses.append(parsed)
                    if not capture_all:
                        break
            except (socket.timeout, TimeoutError):
                break
    except Exception as e:
        err = str(e)
    finally:
        sock.close()
        
    elapsed = (time.perf_counter() - t0) * 1000
    return len(responses) > 0, responses, elapsed, err


def query_dot_853(domain: str, server_ip: str, dot_host: str, timeout: float = 2.5) -> Tuple[bool, Optional[Dict[str, Any]], float, str]:
    """Отправляет зашифрованный DNS-over-TLS (DoT) запрос на порт 853."""
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.settimeout(timeout)
    
    ctx = ssl.create_default_context()
    tls_sock = ctx.wrap_socket(raw_sock, server_hostname=dot_host)
    
    tx_id = random.randint(10000, 60000)
    query = build_dns_query(domain, tx_id=tx_id)
    
    t0 = time.perf_counter()
    try:
        tls_sock.connect((server_ip, 853))
        tls_sock.sendall(struct.pack("!H", len(query)) + query)
        
        len_prefix = tls_sock.recv(2)
        if len(len_prefix) < 2:
            return False, None, (time.perf_counter() - t0) * 1000, "Empty DoT response"
        resp_len = struct.unpack("!H", len_prefix)[0]
        
        data = b""
        while len(data) < resp_len:
            chunk = tls_sock.recv(resp_len - len(data))
            if not chunk:
                break
            data += chunk
            
        el = (time.perf_counter() - t0) * 1000
        parsed = parse_dns_response(data)
        if parsed:
            parsed["elapsed_ms"] = el
        return True, parsed, el, ""
    except socket.timeout:
        el = (time.perf_counter() - t0) * 1000
        return False, None, el, "DoT:853 Таймаут"
    except ssl.SSLError as e:
        el = (time.perf_counter() - t0) * 1000
        return False, None, el, f"TLS Err: {str(e)[:15]}"
    except Exception as e:
        el = (time.perf_counter() - t0) * 1000
        return False, None, el, str(e)[:18]
    finally:
        try:
            tls_sock.close()
        except Exception:
            pass


def query_doh_443(domain: str, server_ip: str, doh_url: str, timeout: float = 3.0) -> Tuple[bool, Optional[Dict[str, Any]], float, str]:
    """Отправляет защищенный DNS-over-HTTPS (DoH) запрос по RFC 8484 (HTTPS :443) через HTTP/2."""
    tx_id = random.randint(10000, 60000)
    wire_query = build_dns_query(domain, tx_id=tx_id)
    b64 = base64_url_encode(wire_query)
    
    sep = "&" if "?" in doh_url else "?"
    target_url = f"{doh_url}{sep}dns={b64}"
    
    parsed_url = urllib.parse.urlparse(doh_url)
    host = parsed_url.hostname or server_ip
    port = parsed_url.port or 443
    
    cmd = [
        "curl", "-s",
        "--http2",
        "--max-time", str(timeout),
        "-H", "accept: application/dns-message",
        "-H", "user-agent: TSPU-DNS-Detector/1.0",
    ]
    if host and not host.replace(".", "").isdigit():
        cmd.extend(["--resolve", f"{host}:{port}:{server_ip}"])
    cmd.append(target_url)
    
    t0 = time.perf_counter()
    try:
        res = subprocess.run(cmd, capture_output=True, timeout=timeout + 1.5)
        el = (time.perf_counter() - t0) * 1000
        if res.returncode == 0 and len(res.stdout) >= 12:
            parsed = parse_dns_response(res.stdout)
            if parsed:
                parsed["elapsed_ms"] = el
                return True, parsed, el, ""
        elif res.returncode != 0:
            return False, None, el, f"curl code {res.returncode}"
    except Exception:
        pass
        
    # Fallback to pure Python urllib
    try:
        req = urllib.request.Request(
            target_url,
            headers={
                "Accept": "application/dns-message",
                "User-Agent": "TSPU-DNS-Detector/1.0",
            }
        )
        ctx = ssl.create_default_context()
        t0 = time.perf_counter()
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            data = resp.read()
            el = (time.perf_counter() - t0) * 1000
            parsed = parse_dns_response(data)
            if parsed:
                parsed["elapsed_ms"] = el
            return True, parsed, el, ""
    except Exception as e:
        el = (time.perf_counter() - t0) * 1000
        return False, None, el, str(e)


def base64_url_encode(data: bytes) -> str:
    """Кодирует байты в Base64URL без padding (RFC 8484)."""
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# ============================ АНАЛИЗАТОР СИГНАТУР ============================

class InterceptionVerdict:
    CLEAN = "CLEAN"
    SPOOFED_NXDOMAIN_AA = "SPOOFED_NXDOMAIN_AA"      # Поддельный NXDOMAIN с флагом AA от рекурсивного DNS
    FALSE_NXDOMAIN = "FALSE_NXDOMAIN"                # Ложный NXDOMAIN (домен существует в DoH/DoT, но UDP дал NXDOMAIN)
    BOGON_REDIRECT = "BOGON_REDIRECT"                # Подмена A-записи на 127.0.0.1 / заглушку
    PORT53_HIJACKED = "PORT53_HIJACKED"              # Перехват любого UDP:53 запроса (даже на несуществующий IP)
    PACKET_RACING = "PACKET_RACING"                  # Получено 2 ответа: инъекция ТСПУ + реальный ответ
    BLOCKED_TIMEOUT = "BLOCKED_TIMEOUT"              # UDP:53 сброшен/заблокирован, при этом DoH/DoT работает
    UNKNOWN_ERROR = "UNKNOWN_ERROR"


def analyze_test_case(
    domain: str,
    server: Dict[str, str],
    udp_res: Tuple[bool, List[Dict[str, Any]], float, str],
    dot_res: Tuple[bool, Optional[Dict[str, Any]], float, str],
    doh_res: Tuple[bool, Optional[Dict[str, Any]], float, str],
) -> Dict[str, Any]:
    """Комплексный анализ ответов по UDP:53, DoT:853 и DoH:443."""
    udp_ok, udp_packets, udp_elapsed, udp_err = udp_res
    dot_ok, dot_parsed, dot_elapsed, dot_err = dot_res
    doh_ok, doh_parsed, doh_elapsed, doh_err = doh_res
    
    findings = []
    verdict = InterceptionVerdict.CLEAN
    severity = "NONE"  # NONE, WARNING, CRITICAL
    
    secure_parsed = doh_parsed if (doh_ok and doh_parsed) else dot_parsed
    secure_ok = doh_ok or dot_ok

    if not udp_ok:
        if secure_ok and secure_parsed and secure_parsed.get("rcode") == 0:
            verdict = InterceptionVerdict.BLOCKED_TIMEOUT
            severity = "CRITICAL"
            findings.append("UDP:53 полностью заблокирован (таймаут/сброс), тогда как защищенный канал отдал реальные IP.")
        else:
            verdict = InterceptionVerdict.UNKNOWN_ERROR
            severity = "WARNING"
            findings.append(f"UDP:53 таймаут/ошибка: {udp_err or 'Нет ответа'}")
        return {
            "verdict": verdict,
            "severity": severity,
            "findings": findings,
            "udp": None,
            "dot": dot_parsed,
            "doh": doh_parsed,
        }

    first_pkt = udp_packets[0]
    udp_rcode = first_pkt.get("rcode")
    udp_flags = first_pkt.get("flags", [])
    udp_aa = first_pkt.get("aa", False)
    udp_ips = first_pkt.get("ips", [])
    
    # 1. Проверка на Packet Racing (2+ пакета)
    if len(udp_packets) > 1:
        verdict = InterceptionVerdict.PACKET_RACING
        severity = "CRITICAL"
        p1, p2 = udp_packets[0], udp_packets[1]
        findings.append(
            f"ОБНАРУЖЕНА ГОНКА ПАКЕТОВ: Получено {len(udp_packets)} ответа на 1 запрос!\n"
            f"   • Пакет #1 ({p1.get('elapsed_ms', 0):.1f}мс): rcode={p1.get('rcode_str')}, flags={p1.get('flags')}\n"
            f"   • Пакет #2 ({p2.get('elapsed_ms', 0):.1f}мс): rcode={p2.get('rcode_str')}, flags={p2.get('flags')}, ips={p2.get('ips')}"
        )

    # 2. Проверка сигнатуры AA + NXDOMAIN от публичного рекурсивного резолвера
    if udp_aa and udp_rcode == 3:
        verdict = InterceptionVerdict.SPOOFED_NXDOMAIN_AA
        severity = "CRITICAL"
        findings.append(
            f"ФАЛЬШИВКА ТСПУ: Публичный резолвер {server['ip']} вернул NXDOMAIN с флагом AA (Authoritative Answer).\n"
            f"   Флаги: [{' '.join(udp_flags)}]. Рекурсивные DNS никогда не выставляют AA для чужих доменов!"
        )
    elif udp_aa and udp_rcode == 0 and not any(k in server["name"].lower() for k in ["authoritative"]):
        verdict = InterceptionVerdict.SPOOFED_NXDOMAIN_AA
        severity = "CRITICAL"
        findings.append(
            f"ПОДОЗРИТЕЛЬНЫЙ ФЛАГ AA: Резолвер {server['ip']} вернул флаг AA [{' '.join(udp_flags)}]."
        )

    # 3. Подмена на Bogon IP (127.0.0.1, заглушка РКН)
    bogon_match = [ip for ip in udp_ips if ip in BOGON_IPS or ip.startswith("127.") or ip.startswith("10.")]
    if bogon_match:
        verdict = InterceptionVerdict.BOGON_REDIRECT
        severity = "CRITICAL"
        findings.append(f"ПОДМЕНА IP: Запрос вернул IP-заглушку провайдера/РКН: {', '.join(bogon_match)}")

    # 4. Ложный NXDOMAIN (сравнение с DoH / DoT)
    if udp_rcode == 3 and secure_ok and secure_parsed and secure_parsed.get("rcode") == 0:
        if verdict != InterceptionVerdict.SPOOFED_NXDOMAIN_AA:
            verdict = InterceptionVerdict.FALSE_NXDOMAIN
            severity = "CRITICAL"
        ref_ips = secure_parsed.get("ips", [])
        findings.append(
            f"ЛОЖНЫЙ NXDOMAIN: Открытый UDP:53 вернул 'домен не существует' (NXDOMAIN),\n"
            f"   хотя зашифрованный канал вернул реальные IP: {', '.join(ref_ips[:3])}"
        )

    # 5. Чистый ответ
    if not findings:
        verdict = InterceptionVerdict.CLEAN
        severity = "NONE"
        findings.append("Ответ чистый, сигнатур подделки или инъекций не обнаружено.")

    return {
        "verdict": verdict,
        "severity": severity,
        "findings": findings,
        "udp": first_pkt,
        "dot": dot_parsed,
        "doh": doh_parsed,
    }


def probe_dummy_ip_hijack() -> Dict[str, Any]:
    """Проверяет тотальный перехват порта 53 на фиктивные IP."""
    dummy_ips = ["192.0.2.53", "198.51.100.53"]
    hijacked = False
    details = []
    
    for ip in dummy_ips:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.2)
        tx_id = random.randint(1000, 9999)
        query = build_dns_query("youtube.com", tx_id=tx_id)
        t0 = time.perf_counter()
        try:
            sock.sendto(query, (ip, 53))
            data, addr = sock.recvfrom(2048)
            el = (time.perf_counter() - t0) * 1000
            parsed = parse_dns_response(data)
            hijacked = True
            details.append({
                "ip": ip,
                "responded": True,
                "elapsed_ms": el,
                "flags": parsed.get("flags") if parsed else [],
                "rcode": parsed.get("rcode_str") if parsed else "UNKNOWN",
                "ips": parsed.get("ips") if parsed else [],
            })
        except (socket.timeout, TimeoutError):
            details.append({"ip": ip, "responded": False})
        except Exception as e:
            details.append({"ip": ip, "responded": False, "error": str(e)})
        finally:
            sock.close()
            
    return {
        "hijacked": hijacked,
        "details": details
    }


# ============================ ВИЗУАЛИЗАЦИЯ И ВЫВОД ============================

def print_banner():
    print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║                     ДЕТЕКТОР ВМЕШАТЕЛЬСТВА И СПУФИНГА DNS (ТСПУ РКН / DPI)                                   ║{RESET}")
    print(f"{BOLD}{CYAN}║                     Комплексный анализ: UDP :53  |  DoT :853 (TLS)  |  DoH :443 (HTTPS)                      ║{RESET}")
    print(f"{BOLD}{CYAN}╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════╝{RESET}\n")


def print_dummy_probe_result(res: Dict[str, Any]):
    print(f"{BOLD}{BLUE}▶ ПРОВЕРКА ТОТАЛЬНОГО ПЕРЕХВАТА ПОРТА 53 (Запрос на фиктивный IP 192.0.2.1):{RESET}")
    if res["hijacked"]:
        print(f"  {RED}{BOLD}🚨 ВНИМАНИЕ: ТОТАЛЬНЫЙ ПЕРЕХВАТ ПОРТА 53 ОБНАРУЖЕН!{RESET}")
        print(f"  {RED}   Провайдер/ТСПУ перехватывает ЛЮБОЙ DNS-запрос на порт 53, даже если сервер не существует.{RESET}")
        for d in res["details"]:
            if d.get("responded"):
                print(f"     • {d['ip']}: получен ответ за {d['elapsed_ms']:.1f}мс | rcode={d['rcode']} | flags={d['flags']}")
    else:
        print(f"  {GREEN}✔ Чисто: Фиктивный IP 192.0.2.1 не ответил (порт 53 не заворачивается поголовно в прозрачный прокси).{RESET}")
    print()


def print_dig_verbose(domain: str, server_ip: str, parsed: Optional[Dict[str, Any]], elapsed_ms: float):
    """Выводит детальный дамп пакета в стиле утилиты dig."""
    if not parsed:
        print(f"  {DIM};; <<>> No packet received from {server_ip} for {domain} <<>>{RESET}")
        return
    flags_str = " ".join(parsed.get("flags", []))
    print(f"  {DIM};; ->>HEADER<<- opcode: {parsed.get('opcode', 0)}, status: {parsed.get('rcode_str')}, id: {parsed.get('tx_id')}{RESET}")
    print(f"  {DIM};; flags: {flags_str}; QUERY: {parsed.get('qdcount')}, ANSWER: {parsed.get('ancount')}, AUTHORITY: {parsed.get('nscount')}, ADDITIONAL: {parsed.get('arcount')}{RESET}")
    if parsed.get("answers"):
        print(f"  {DIM};; ANSWER SECTION:{RESET}")
        for ans in parsed["answers"]:
            print(f"  {DIM}; {ans.get('name')}.\t{ans.get('ttl')}\tIN\tA\t{ans.get('value')}{RESET}")
    print(f"  {DIM};; Query time: {elapsed_ms:.1f} msec | SERVER: {server_ip}#53{RESET}\n")


def format_udp_column(parsed: Optional[Dict[str, Any]], ok: bool, elapsed: float, err: str) -> str:
    if not ok:
        return f"{RED}❌ Таймаут / Блок{RESET}"
    
    rcode = parsed.get("rcode_str", "")
    ips = parsed.get("ips", [])
    aa = parsed.get("aa", False)
    
    if aa and rcode == "NXDOMAIN":
        return f"{RED}{BOLD}🚨 NXDOMAIN [aa!]{RESET} {DIM}({elapsed:2.0f}мс){RESET}"
    elif any(ip in BOGON_IPS for ip in ips):
        return f"{RED}{BOLD}🚨 ПОДМЕНА: {ips[0]}{RESET}"
    elif rcode == "NXDOMAIN":
        return f"{YELLOW}NXDOMAIN{RESET} {DIM}({elapsed:2.0f}мс){RESET}"
    elif ips:
        return f"{GREEN}{ips[0]:<15}{RESET} {DIM}({elapsed:2.0f}мс){RESET}"
    else:
        return f"{YELLOW}{rcode}{RESET} {DIM}({elapsed:2.0f}мс){RESET}"


def format_dot_column(parsed: Optional[Dict[str, Any]], ok: bool, elapsed: float, err: str) -> str:
    if not ok:
        err_short = err[:14] if err else "Блок / Err"
        return f"{RED}❌ {err_short}{RESET}"
    rcode = parsed.get("rcode_str", "")
    ips = parsed.get("ips", [])
    if ips:
        return f"{GREEN}🔒 {ips[0]:<14}{RESET} {DIM}({elapsed:2.0f}мс){RESET}"
    return f"{YELLOW}🔒 {rcode}{RESET} {DIM}({elapsed:2.0f}мс){RESET}"


def format_doh_column(parsed: Optional[Dict[str, Any]], ok: bool, elapsed: float, err: str) -> str:
    if not ok:
        err_short = err[:14] if err else "Ошибка DoH"
        return f"{RED}❌ {err_short}{RESET}"
    rcode = parsed.get("rcode_str", "")
    ips = parsed.get("ips", [])
    if ips:
        return f"{GREEN}🌐 {ips[0]:<14}{RESET} {DIM}({elapsed:2.0f}мс){RESET}"
    return f"{YELLOW}🌐 {rcode}{RESET} {DIM}({elapsed:2.0f}мс){RESET}"


def format_verdict_badge(verdict: str) -> str:
    if verdict == InterceptionVerdict.CLEAN:
        return f"{GREEN}🟢 ЧИСТО{RESET}"
    elif verdict == InterceptionVerdict.SPOOFED_NXDOMAIN_AA:
        return f"{RED}{BOLD}🚨 ТСПУ СПУФИНГ (AA){RESET}"
    elif verdict == InterceptionVerdict.BOGON_REDIRECT:
        return f"{RED}{BOLD}🚨 ПОДМЕНА НА ЗАГЛУШКУ{RESET}"
    elif verdict == InterceptionVerdict.FALSE_NXDOMAIN:
        return f"{RED}{BOLD}🚨 ЛОЖНЫЙ NXDOMAIN{RESET}"
    elif verdict == InterceptionVerdict.PACKET_RACING:
        return f"{RED}{BOLD}🚨 ГОНКА ПАКЕТОВ{RESET}"
    elif verdict == InterceptionVerdict.BLOCKED_TIMEOUT:
        return f"{RED}❌ БЛОКИРОВКА UDP:53{RESET}"
    else:
        return f"{YELLOW}⚠️ НЕИЗВЕСТНО{RESET}"


# ============================ ПАРАЛЛЕЛЬНОЕ ВЫПОЛНЕНИЕ ============================

def execute_single_domain_test(
    domain_item: Tuple[str, str, str],
    server: Dict[str, str],
    check_racing: bool = True
) -> Dict[str, Any]:
    """Выполняет проверку одного домена на одном сервере по всем 3 протоколам."""
    domain, d_desc, d_cat = domain_item
    s_ip = server["ip"]
    s_dot = server.get("dot_host", s_ip)
    s_doh = server["doh_url"]

    # Выполняем 3 запроса (UDP, DoT, DoH)
    udp_res = query_udp_53(domain, s_ip, timeout=2.0, capture_all=check_racing)
    dot_res = query_dot_853(domain, s_ip, s_dot, timeout=2.5)
    doh_res = query_doh_443(domain, s_ip, s_doh, timeout=3.0)

    analysis = analyze_test_case(domain, server, udp_res, dot_res, doh_res)

    return {
        "domain": domain,
        "domain_desc": d_desc,
        "domain_category": d_cat,
        "server": server,
        "udp_res": udp_res,
        "dot_res": dot_res,
        "doh_res": doh_res,
        "analysis": analysis,
    }


def run_diagnostics(
    servers: List[Dict[str, str]],
    domains: List[Tuple[str, str, str]],
    check_racing: bool = True,
    as_json: bool = False,
    verbose: bool = False,
    workers: int = 10
) -> Dict[str, Any]:
    
    if not as_json:
        print_banner()
        dummy_res = probe_dummy_ip_hijack()
        print_dummy_probe_result(dummy_res)
    else:
        dummy_res = probe_dummy_ip_hijack()

    all_results = []
    total_checks = 0
    total_intercepted = 0

    for srv in servers:
        s_name = srv["name"]
        s_ip = srv["ip"]
        s_dot = srv.get("dot_host", s_ip)
        s_doh = srv["doh_url"]

        if not as_json:
            print(f"{BOLD}{MAGENTA}▶ Сервер: {s_name} ({s_ip}){RESET} | DoT: {s_dot} | DoH: {s_doh}")
            print(f"  {'Домен':<18} | {'Категория':<16} | {'UDP :53 (Открытый)':<26} | {'DoT :853 (TLS)':<26} | {'DoH :443 (HTTPS)':<26} | {'Вердикт':<20}")
            print("  " + "─" * 138)

        # Параллельное тестирование доменов для данного сервера для ускорения работы
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_dom = {
                executor.submit(execute_single_domain_test, d_item, srv, check_racing): d_item
                for d_item in domains
            }
            
            # Собираем результаты в исходном порядке доменов
            domain_order_map = {d_item[0]: idx for idx, d_item in enumerate(domains)}
            server_results = [None] * len(domains)

            for future in concurrent.futures.as_completed(future_to_dom):
                res = future.result()
                dom_idx = domain_order_map[res["domain"]]
                server_results[dom_idx] = res

        for res in server_results:
            if not res:
                continue
            total_checks += 1
            domain = res["domain"]
            d_desc = res["domain_desc"]
            analysis = res["analysis"]
            verdict = analysis["verdict"]
            udp_res = res["udp_res"]
            dot_res = res["dot_res"]
            doh_res = res["doh_res"]

            if verdict != InterceptionVerdict.CLEAN:
                total_intercepted += 1

            res_entry = {
                "server": srv,
                "domain": domain,
                "domain_desc": d_desc,
                "domain_category": res["domain_category"],
                "udp_ok": udp_res[0],
                "udp_elapsed_ms": udp_res[2],
                "udp_packet": analysis["udp"],
                "dot_ok": dot_res[0],
                "dot_elapsed_ms": dot_res[2],
                "dot_packet": analysis["dot"],
                "doh_ok": doh_res[0],
                "doh_elapsed_ms": doh_res[2],
                "doh_packet": analysis["doh"],
                "verdict": verdict,
                "severity": analysis["severity"],
                "findings": analysis["findings"],
            }
            all_results.append(res_entry)

            if not as_json:
                udp_str = format_udp_column(analysis["udp"], udp_res[0], udp_res[2], udp_res[3])
                dot_str = format_dot_column(analysis["dot"], dot_res[0], dot_res[2], dot_res[3])
                doh_str = format_doh_column(analysis["doh"], doh_res[0], doh_res[2], doh_res[3])
                v_badge = format_verdict_badge(verdict)
                print(f"  {domain:<18} | {d_desc:<16} | {udp_str:<36} | {dot_str:<36} | {doh_str:<36} | {v_badge}")
                
                if verbose and analysis["udp"]:
                    print_dig_verbose(domain, s_ip, analysis["udp"], udp_res[2])

                if analysis["severity"] == "CRITICAL":
                    for f in analysis["findings"]:
                        for line in f.split("\n"):
                            print(f"    {RED}↳ {line}{RESET}")

        if not as_json:
            print()

    # Сводный отчет
    summary = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "dummy_probe": dummy_res,
        "total_checks": total_checks,
        "total_intercepted": total_intercepted,
        "clean": total_intercepted == 0,
        "results": all_results,
    }

    if as_json:
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        return summary

    print_summary_conclusion(summary)
    return summary


def print_summary_conclusion(summary: Dict[str, Any]):
    print(f"{BOLD}{CYAN}╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║                                          ИТОГОВЫЙ АНАЛИЗ И ВЫВОДЫ                                            ║{RESET}")
    print(f"{BOLD}{CYAN}╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════╝{RESET}\n")

    total = summary["total_checks"]
    bad = summary["total_intercepted"]
    
    if bad == 0 and not summary["dummy_probe"]["hijacked"]:
        print(f"{GREEN}{BOLD}🟢 ВМЕШАТЕЛЬСТВО В DNS НЕ ОБНАРУЖЕНО.{RESET}")
        print(f"   Все проверенные открытые UDP:53 запросы дошли до оригинальных серверов без подмены флагов и IP.\n")
    else:
        print(f"{RED}{BOLD}🚨 ОБНАРУЖЕНО ВМЕШАТЕЛЬСТВО ТСПУ / СПУФИНГ DNS ({bad} из {total} тестов скомпрометированы)!{RESET}\n")
        print(f"{BOLD}Ключевые маркеры и почему это именно ТСПУ (РКН):{RESET}")
        print(f"1. {BOLD}Флаг AA (Authoritative Answer) в NXDOMAIN от 8.8.8.8 / 1.1.1.1:{RESET}")
        print(f"   Google и Cloudflare — это рекурсивные резолверы. Они {RED}{BOLD}никогда не ставят флаг AA{RESET} для сторонних доменов.")
        print(f"   Появление флага 'aa' в ответе `flags: qr aa rd ra` со статусом `NXDOMAIN` на 100% подтверждает,")
        print(f"   что ответ сгенерирован и инжектирован оборудованием ТСПУ/DPI прямо на канале провайдера.")
        print(f"2. {BOLD}Расхождение между UDP:53 и защищенными каналами (DoT:853 / DoH:443):{RESET}")
        print(f"   В то время как открытый порт 53 возвращает NXDOMAIN или заглушку, зашифрованный DoT (порт 853) и DoH (порт 443)")
        print(f"   успешно возвращают валидные A/AAAA записи от настоящих серверов Google/Cloudflare.")
        print(f"3. {BOLD}Рекомендации для обхода (в Keenetic / роутере / системе):{RESET}")
        print(f"   • {BOLD}DoT (DNS-over-TLS){RESET}: Рекомендуется для роутеров (например, Keenetic с замочком) — высокая скорость, прямой TLS.")
        print(f"   • {BOLD}DoH (DNS-over-HTTPS){RESET}: Максимальная устойчивость к блокировкам (трафик неотличим от обычного HTTPS веб-серфинга).")
        print(f"   • Заблокируйте открытый порт UDP/TCP 53 на роутере в пользу DoT/DoH.\n")


# ============================ CLI ENTRYPOINT ============================

def main():
    parser = argparse.ArgumentParser(
        description="Детектор вмешательства ТСПУ (РКН) и провайдеров в DNS-запросы (UDP:53 | DoT:853 | DoH:443)"
    )
    parser.add_argument(
        "-d", "--domain", action="append", help="Проверить конкретный домен (можно указывать несколько раз)"
    )
    parser.add_argument(
        "-s", "--server", action="append", help="Проверить конкретный IP DNS-сервера (например: 8.8.8.8)"
    )
    parser.add_argument(
        "-f", "--full", action="store_true", help="Проверить ПОЛНУЮ базу (40+ запрещенных и контрольных доменов)"
    )
    parser.add_argument(
        "-c", "--category", choices=["social", "media", "torrents", "vpn", "streaming", "services", "control"],
        help="Проверить только выбранную категорию доменов"
    )
    parser.add_argument(
        "-q", "--quick", action="store_true", help="Быстрый тест (только Google 8.8.8.8 и Cloudflare 1.1.1.1 на топ-доменах)"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Подробный вывод в стиле dig (заголовки, флаги, секции)"
    )
    parser.add_argument(
        "-w", "--workers", type=int, default=12, help="Количество параллельных потоков (по умолчанию 12)"
    )
    parser.add_argument(
        "--json", action="store_true", help="Вывод в формате JSON"
    )
    parser.add_argument(
        "--no-race", action="store_true", help="Отключить проверку гонки пакетов"
    )
    
    args = parser.parse_args()

    # Выбор серверов
    if args.server:
        servers = []
        for s_ip in args.server:
            match = next((s for s in DEFAULT_SERVERS if s["ip"] == s_ip), None)
            if match:
                servers.append(match)
            else:
                servers.append({
                    "name": f"Custom ({s_ip})",
                    "ip": s_ip,
                    "dot_host": s_ip,
                    "doh_url": f"https://{s_ip}/dns-query",
                })
    elif args.quick:
        servers = DEFAULT_SERVERS[:2]  # Google & Cloudflare
    else:
        servers = DEFAULT_SERVERS

    # Выбор доменов
    if args.domain:
        domains = [(d, "Пользовательский", "custom") for d in args.domain]
    elif args.category:
        domains = [item for item in DOMAIN_DATABASE if item[2] == args.category]
    elif args.full:
        domains = DOMAIN_DATABASE
    elif args.quick:
        domains = [
            ("youtube.com", "Видео / Стриминг", "streaming"),
            ("rutracker.org", "Торренты", "torrents"),
            ("instagram.com", "Соцсети", "social"),
            ("google.com", "Контрольный", "control"),
        ]
    else:
        # Стандартный расширенный список (топ-20)
        selected_set = set(DEFAULT_SELECTED_DOMAINS)
        domains = [item for item in DOMAIN_DATABASE if item[0] in selected_set]

    run_diagnostics(
        servers=servers,
        domains=domains,
        check_racing=not args.no_race,
        as_json=args.json,
        verbose=args.verbose,
        workers=args.workers
    )


if __name__ == "__main__":
    main()
