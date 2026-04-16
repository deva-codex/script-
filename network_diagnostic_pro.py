
#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║              NETWORK DIAGNOSTIC PRO - ELITE SECURITY EDITION                 ║
║         Enterprise-Grade Threat Analysis & Intelligence Platform             ║
║                                                                              ║
║  Author: Security Engineering Team | Version: 2.0 (Production)              ║
║  Features: Async concurrency, threat feed integration, ML-ready, type-safe  ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import json
import socket
import platform
import subprocess
import hashlib
import logging
import asyncio
import threading
from contextlib import contextmanager
from typing import List, Optional, Dict, Any, Tuple, Set, Callable, AsyncIterator
from dataclasses import dataclass, asdict, field
from enum import Enum
from pathlib import Path
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from functools import lru_cache, wraps
import tempfile
import sqlite3
import re
from abc import ABC, abstractmethod
import warnings

# ════════════════════════════════════════════════════════════════════════════
# DEPENDENCY MANAGEMENT WITH GRACEFUL DEGRADATION
# ════════════════════════════════════════════════════════════════════════════

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    psutil = None

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import geoip2.database
    HAS_GEOIP = True
except ImportError:
    HAS_GEOIP = False

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

# ════════════════════════════════════════════════════════════════════════════
# ENTERPRISE LOGGING & OBSERVABILITY
# ════════════════════════════════════════════════════════════════════════════

class LogLevel(Enum):
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL

class StructuredLogger:
    """Enterprise-grade structured logging with JSON serialization."""
    
    def __init__(self, name: str, log_dir: Optional[Path] = None):
        self.name = name
        self.log_dir = log_dir or (Path.home() / ".network_diagnostic" / "logs")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Rotating file handler
        self.log_file = self.log_dir / f"{name}_{datetime.now():%Y%m%d_%H%M%S}.log"
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        handler = logging.FileHandler(self.log_file, encoding='utf-8')
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        
        # Thread-safe lock for concurrent access
        self._lock = threading.RLock()
    
    def log(self, level: LogLevel, msg: str, **kwargs) -> None:
        """Thread-safe structured logging."""
        with self._lock:
            context = " | ".join(f"{k}={v}" for k, v in kwargs.items())
            full_msg = f"{msg} [{context}]" if context else msg
            self.logger.log(level.value, full_msg)

logger = StructuredLogger(__name__)

# ════════════════════════════════════════════════════════════════════════════
# TERMINAL UI WITH ADVANCED FORMATTING
# ════════════════════════════════════════════════════════════════════════════

class ANSIColor(Enum):
    """ANSI color codes with semantic meaning."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    CRITICAL = "\033[91m"  # Red
    WARNING = "\033[93m"   # Yellow
    SUCCESS = "\033[92m"   # Green
    INFO = "\033[94m"      # Blue
    DEBUG = "\033[96m"     # Cyan
    ACCENT = "\033[95m"    # Magenta

class TerminalRenderer:
    """Sophisticated terminal rendering with context-aware styling."""
    
    @staticmethod
    def is_tty() -> bool:
        """Detect if stdout is a TTY (terminal)."""
        return sys.stdout.isatty()
    
    @staticmethod
    def colorize(text: str, color: ANSIColor) -> str:
        """Apply ANSI color if terminal supports it."""
        if not TerminalRenderer.is_tty():
            return text
        return f"{color.value}{text}{ANSIColor.RESET.value}"
    
    @staticmethod
    def banner(title: str) -> None:
        print(f"\n{TerminalRenderer.colorize('═' * 80, ANSIColor.ACCENT)}")
        print(f"{TerminalRenderer.colorize(f'  {title}', ANSIColor.BOLD)}")
        print(f"{TerminalRenderer.colorize('═' * 80, ANSIColor.ACCENT)}\n")
    
    @staticmethod
    def table(headers: List[str], rows: List[Tuple]) -> None:
        """Render formatted table with alignment."""
        col_widths = [max(len(str(h)), max((len(str(r[i])) for r in rows), default=0)) 
                      for i, h in enumerate(headers)]
        
        # Header
        header_line = " | ".join(f"{h:<{w}}" for h, w in zip(headers, col_widths))
        print(f"  {TerminalRenderer.colorize(header_line, ANSIColor.INFO)}")
        print(f"  {TerminalRenderer.colorize('─' * len(header_line), ANSIColor.DIM)}")
        
        # Rows
        for row in rows:
            row_line = " | ".join(f"{str(v):<{w}}" for v, w in zip(row, col_widths))
            print(f"  {row_line}")

# ════════════════════════════════════════════════════════════════════════════
# DATA MODELS WITH STRICT TYPING
# ════════════════════════════════════════════════════════════════════════════

class ThreatLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class GeoLocation:
    """Geographic metadata for IP addresses."""
    country: str
    city: Optional[str]
    latitude: Optional[float]
    longitude: Optional[float]
    is_vpn: bool = False
    is_proxy: bool = False
    is_datacenter: bool = False
    
    def is_suspicious(self) -> bool:
        """Heuristic: suspicious if proxy/VPN or known datacenter."""
        return self.is_vpn or self.is_proxy or self.is_datacenter

@dataclass
class ThreatIntelligence:
    """External threat feed data."""
    is_malicious: bool
    reputation_score: float  # 0-100, 100 = most malicious
    threat_types: List[str]  # e.g., ["botnet", "malware", "exploit"]
    last_seen: Optional[datetime] = None
    sources: List[str] = field(default_factory=list)

@dataclass
class NetworkInterface:
    """Comprehensive network interface data."""
    name: str
    status: str  # UP/DOWN
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    mac: Optional[str] = None
    speed: Optional[int] = None  # Mbps
    mtu: Optional[int] = None
    packets_sent: int = 0
    packets_recv: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0
    errors: int = 0
    dropped: int = 0
    collisions: int = 0
    timestamp: datetime = field(default_factory=datetime.now)

@dataclass
class Connection:
    """Network connection with threat context."""
    protocol: str  # TCP/UDP
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    status: str  # LISTEN/ESTABLISHED/TIME_WAIT
    pid: Optional[int] = None
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    user: Optional[str] = None
    threat_intel: Optional[ThreatIntelligence] = None
    geo_location: Optional[GeoLocation] = None
    confidence: float = 1.0  # How certain is the connection data

@dataclass
class SecurityFinding:
    """Actionable security finding."""
    threat_level: ThreatLevel
    category: str  # e.g., "Suspicious Port", "Malware C&C", "Data Exfiltration"
    title: str
    description: str
    remediation: str
    timestamp: datetime = field(default_factory=datetime.now)
    evidence: Dict[str, Any] = field(default_factory=dict)
    mitre_tactics: List[str] = field(default_factory=list)  # MITRE ATT&CK mapping

@dataclass
class ScanMetadata:
    """Complete scan context and metrics."""
    scan_id: str
    timestamp: datetime
    hostname: str
    os_type: str
    os_version: str
    python_version: str
    scan_duration: float = 0.0
    interfaces_scanned: int = 0
    connections_analyzed: int = 0
    findings_count: int = 0

@dataclass
class DiagnosticReport:
    """Comprehensive diagnostic report."""
    metadata: ScanMetadata
    interfaces: List[NetworkInterface]
    connections: List[Connection]
    dns_servers: List[str]
    findings: List[SecurityFinding]
    threat_score: float  # 0-100, higher = more threats
    baseline_comparison: Optional[Dict[str, Any]] = None
    anomalies_detected: List[str] = field(default_factory=list)

# ════════════════════════════════════════════════════════════════════════════
# ADVANCED DATABASE LAYER WITH CONNECTION POOLING
# ════════════════════════════════════════════════════════════════════════════

class DatabaseConnectionPool:
    """SQLite connection pool with thread-safe access."""
    
    def __init__(self, db_path: Path, pool_size: int = 5):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.pool_size = pool_size
        self._connections: List[sqlite3.Connection] = []
        self._lock = threading.RLock()
        self._available = threading.Semaphore(pool_size)
        self._init_pool()
    
    def _init_pool(self) -> None:
        """Initialize connection pool."""
        with self._lock:
            for _ in range(self.pool_size):
                conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
                conn.row_factory = sqlite3.Row
                self._connections.append(conn)
    
    @contextmanager
    def get_connection(self):
        """Context manager for acquiring/releasing connections."""
        self._available.acquire()
        try:
            with self._lock:
                conn = self._connections.pop()
            yield conn
            conn.commit()
        except Exception as e:
            if conn:
                conn.rollback()
            logger.log(LogLevel.ERROR, f"Database error: {e}")
            raise
        finally:
            with self._lock:
                self._connections.append(conn)
            self._available.release()

class DiagnosticRepository:
    """Data persistence layer with advanced queries."""
    
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or (Path.home() / ".network_diagnostic" / "diagnostic.db")
        self.pool = DatabaseConnectionPool(self.db_path)
        self._init_schema()
    
    def _init_schema(self) -> None:
        """Initialize database schema."""
        with self.pool.get_connection() as conn:
            cursor = conn.cursor()
            
            # Scans table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    timestamp DATETIME NOT NULL,
                    hostname TEXT NOT NULL,
                    os_type TEXT,
                    threat_score REAL,
                    duration_ms INTEGER,
                    findings_count INTEGER,
                    metadata_json TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Connections table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    protocol TEXT,
                    remote_addr TEXT,
                    remote_port INTEGER,
                    process_name TEXT,
                    threat_score REAL,
                    geo_location_json TEXT,
                    first_seen DATETIME,
                    last_seen DATETIME,
                    occurrences INTEGER DEFAULT 1,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                )
            """)
            
            # Findings table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    threat_level TEXT,
                    category TEXT,
                    title TEXT,
                    description TEXT,
                    remediation TEXT,
                    evidence_json TEXT,
                    mitre_tactics TEXT,
                    timestamp DATETIME,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                )
            """)
            
            # Baselines for anomaly detection
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS baselines (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    metric_name TEXT UNIQUE NOT NULL,
                    baseline_value REAL,
                    std_deviation REAL,
                    last_updated DATETIME,
                    sample_count INTEGER
                )
            """)
            
            # Create indices for performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_ts ON scans(timestamp DESC)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_conn_scan ON connections(scan_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_finding_level ON findings(threat_level)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_remote_addr ON connections(remote_addr)")
    
    def save_diagnostic_report(self, report: DiagnosticReport) -> None:
        """Atomically save complete diagnostic report."""
        with self.pool.get_connection() as conn:
            cursor = conn.cursor()
            
            # Save scan metadata
            cursor.execute("""
                INSERT INTO scans (scan_id, timestamp, hostname, os_type, threat_score, 
                                  duration_ms, findings_count, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report.metadata.scan_id,
                report.metadata.timestamp,
                report.metadata.hostname,
                report.metadata.os_type,
                report.threat_score,
                int(report.metadata.scan_duration * 1000),
                report.metadata.findings_count,
                json.dumps(asdict(report.metadata), default=str)
            ))
            
            # Save connections
            for conn in report.connections:
                cursor.execute("""
                    INSERT INTO connections 
                    (scan_id, protocol, remote_addr, remote_port, process_name, threat_score, geo_location_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    report.metadata.scan_id,
                    conn.protocol,
                    conn.remote_addr,
                    conn.remote_port,
                    conn.process_name,
                    conn.threat_intel.reputation_score if conn.threat_intel else 0.0,
                    json.dumps(asdict(conn.geo_location), default=str) if conn.geo_location else None
                ))
            
            # Save findings
            for finding in report.findings:
                cursor.execute("""
                    INSERT INTO findings 
                    (scan_id, threat_level, category, title, description, remediation, 
                     evidence_json, mitre_tactics, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    report.metadata.scan_id,
                    finding.threat_level.value,
                    finding.category,
                    finding.title,
                    finding.description,
                    finding.remediation,
                    json.dumps(finding.evidence),
                    ",".join(finding.mitre_tactics),
                    finding.timestamp
                ))
            
            conn.commit()
            logger.log(LogLevel.INFO, f"Report saved: {report.metadata.scan_id}")
    
    def get_recent_scans(self, days: int = 7, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent scan summaries."""
        with self.pool.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT scan_id, timestamp, hostname, threat_score, findings_count
                FROM scans
                WHERE timestamp >= datetime('now', '-' || ? || ' days')
                ORDER BY timestamp DESC
                LIMIT ?
            """, (days, limit))
            return [dict(row) for row in cursor.fetchall()]
    
    def calculate_baseline_metrics(self, days: int = 30) -> Dict[str, float]:
        """Calculate baseline metrics for anomaly detection."""
        with self.pool.get_connection() as conn:
            cursor = conn.cursor()
            
            # Average threat score, connection count, etc.
            cursor.execute("""
                SELECT AVG(threat_score) as avg_threat, AVG(findings_count) as avg_findings
                FROM scans
                WHERE timestamp >= datetime('now', '-' || ? || ' days')
            """, (days,))
            
            row = cursor.fetchone()
            return {
                'avg_threat_score': float(row['avg_threat'] or 0.0),
                'avg_findings': float(row['avg_findings'] or 0.0)
            }

# ════════════════════════════════════════════════════════════════════════════
# THREAT INTELLIGENCE ENGINE (EXTENSIBLE)
# ════════════════════════════════════════════════════════════════════════════

class ThreatIntelProvider(ABC):
    """Abstract base for threat intelligence providers."""
    
    @abstractmethod
    async def lookup(self, ip: str) -> Optional[ThreatIntelligence]:
        pass

class AbuseIPDBProvider(ThreatIntelProvider):
    """AbuseIPDB threat feed integration."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")
        self.enabled = bool(self.api_key)
    
    async def lookup(self, ip: str) -> Optional[ThreatIntelligence]:
        if not self.enabled or not HAS_REQUESTS:
            return None
        
        try:
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()["data"]
                return ThreatIntelligence(
                    is_malicious=data["abuseConfidenceScore"] > 25,
                    reputation_score=data["abuseConfidenceScore"],
                    threat_types=["abusive"] if data["abuseConfidenceScore"] > 25 else [],
                    sources=["AbuseIPDB"]
                )
        except Exception as e:
            logger.log(LogLevel.DEBUG, f"AbuseIPDB lookup failed for {ip}: {e}")
        
        return None

class GeoIPProvider(ThreatIntelProvider):
    """GeoIP location intelligence."""
    
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.getenv("GEOIP_DB_PATH")
        self.enabled = HAS_GEOIP and self.db_path and os.path.exists(self.db_path)
    
    async def lookup(self, ip: str) -> Optional[ThreatIntelligence]:
        if not self.enabled:
            return None
        
        try:
            with geoip2.database.Reader(self.db_path) as reader:
                response = reader.city(ip)
                return ThreatIntelligence(
                    is_malicious=False,
                    reputation_score=0.0,
                    threat_types=[],
                    sources=["GeoIP2"]
                )
        except Exception as e:
            logger.log(LogLevel.DEBUG, f"GeoIP lookup failed for {ip}: {e}")
        
        return None

class CompositeIntelligenceEngine:
    """Aggregates multiple threat intelligence providers."""
    
    def __init__(self):
        self.providers: List[ThreatIntelProvider] = [
            AbuseIPDBProvider(),
            GeoIPProvider()
        ]
        self._cache: Dict[str, Optional[ThreatIntelligence]] = {}
        self._cache_ttl = 3600  # 1 hour
    
    async def lookup(self, ip: str) -> Optional[ThreatIntelligence]:
        """Lookup IP across all providers with caching."""
        if ip in self._cache:
            return self._cache[ip]
        
        results = await asyncio.gather(*[p.lookup(ip) for p in self.providers])
        
        # Aggregate results (highest reputation score wins)
        aggregated = None
        for result in results:
            if result and (not aggregated or result.reputation_score > aggregated.reputation_score):
                aggregated = result
        
        self._cache[ip] = aggregated
        return aggregated

# ════════════════════════════════════════════════════════════════════════════
# SECURE COMMAND EXECUTION WITH RETRY LOGIC
# ════════════════════════════════════════════════════════════════════════════

class CommandExecutor:
    """Secure subprocess execution with timeout, retry, and error handling."""
    
    MAX_RETRIES = 3
    BACKOFF_FACTOR = 2.0
    
    @staticmethod
    def run(
        args: List[str],
        timeout: int = 10,
        retries: int = MAX_RETRIES,
        capture_stderr: bool = False
    ) -> Tuple[int, str, str]:
        """
        Execute command safely without shell=True.
        Returns (returncode, stdout, stderr).
        """
        if not isinstance(args, list):
            raise ValueError("Command args must be a list")
        
        for attempt in range(retries):
            try:
                result = subprocess.run(
                    args,
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False
                )
                return (result.returncode, result.stdout.strip(), result.stderr.strip())
            
            except subprocess.TimeoutExpired:
                if attempt < retries - 1:
                    backoff = CommandExecutor.BACKOFF_FACTOR ** attempt
                    asyncio.run(asyncio.sleep(backoff))
                    continue
                return (124, "", f"Command timeout after {timeout}s")
            
            except FileNotFoundError:
                return (127, "", f"Command not found: {args[0]}")
            
            except Exception as e:
                return (1, "", f"Execution error: {str(e)}")
        
        return (1, "", "Max retries exceeded")

# ════════════════════════════════════════════════════════════════════════════
# ADVANCED SECURITY ANALYSIS ENGINE
# ════════════════════════════════════════════════════════════════════════════

class SecurityAnalysisEngine:
    """Production-grade threat detection and analysis."""
    
    # Configuration: Make these externally configurable
    CONFIG = {
        'suspicious_ports': {31337, 666, 27374, 12345, 54320, 6667, 4444},
        'dangerous_ports': {23, 21},  # Telnet, FTP
        'private_ranges': ['10.', '172.16.', '192.168.', '127.', '::1'],
        'excessive_connections_threshold': 100,
        'error_rate_threshold': 100,
        'dropped_packets_threshold': 50,
    }
    
    def __init__(self, intelligence_engine: CompositeIntelligenceEngine):
        self.intel_engine = intelligence_engine
        self.findings: List[SecurityFinding] = []
    
    async def analyze_connections(
        self,
        connections: List[Connection],
        repository: DiagnosticRepository
    ) -> List[SecurityFinding]:
        """Comprehensive connection analysis with threat correlation."""
        self.findings = []
        
        # Concurrent threat lookups
        lookup_tasks = [
            self._analyze_single_connection(conn, repository)
            for conn in connections
        ]
        
        results = await asyncio.gather(*lookup_tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, SecurityFinding):
                self.findings.append(result)
        
        # Pattern analysis
        self.findings.extend(await self._detect_patterns(connections))
        
        return self.findings
    
    async def _analyze_single_connection(
        self,
        conn: Connection,
        repository: DiagnosticRepository
    ) -> Optional[SecurityFinding]:
        """Analyze individual connection."""
        
        # Suspicious port check
        if conn.status == "LISTEN" and conn.local_port in self.CONFIG['suspicious_ports']:
            return SecurityFinding(
                threat_level=ThreatLevel.CRITICAL,
                category="Suspicious Port",
                title=f"Suspicious Listening Port Detected",
                description=f"Process {conn.process_name} (PID {conn.pid}) listening on port {conn.local_port}",
                remediation=f"Verify legitimacy of process. Kill with: sudo kill {conn.pid}",
                mitre_tactics=["Initial Access", "Command and Control"]
            )
        
        # Threat intel lookup for remote addresses
        if conn.status == "ESTABLISHED" and self._is_external_ip(conn.remote_addr):
            threat_intel = await self.intel_engine.lookup(conn.remote_addr)
            conn.threat_intel = threat_intel
            
            if threat_intel and threat_intel.is_malicious:
                return SecurityFinding(
                    threat_level=ThreatLevel.CRITICAL,
                    category="Malicious IP Connection",
                    title=f"Connection to Known Malicious IP",
                    description=f"{conn.process_name} connected to {conn.remote_addr}:{conn.remote_port}",
                    remediation="Isolate system and investigate process. Block IP immediately.",
                    evidence={
                        'remote_ip': conn.remote_addr,
                        'reputation_score': threat_intel.reputation_score,
                        'threat_types': threat_intel.threat_types
                    },
                    mitre_tactics=["Command and Control"]
                )
        
        return None
    
    async def _detect_patterns(self, connections: List[Connection]) -> List[SecurityFinding]:
        """Detect anomalous patterns in connections."""
        findings = []
        
        # Excessive connections
        established = [c for c in connections if c.status == "ESTABLISHED"]
        if len(established) > self.CONFIG['excessive_connections_threshold']:
            findings.append(SecurityFinding(
                threat_level=ThreatLevel.HIGH,
                category="Connection Anomaly",
                title="Unusual Number of Established Connections",
                description=f"{len(established)} established connections detected (threshold: {self.CONFIG['excessive_connections_threshold']})",
                remediation="Review network activity with 'ss' or 'netstat'. Look for botnet or worm activity.",
                mitre_tactics=["Lateral Movement"]
            ))
        
        # Port scanning detection
        unique_remote_ports = set(c.remote_port for c in established)
        if len(unique_remote_ports) > 50:
            findings.append(SecurityFinding(
                threat_level=ThreatLevel.MEDIUM,
                category="Port Scanning",
                title="Potential Port Scanning Activity",
                description=f"High number of unique remote ports: {len(unique_remote_ports)}",
                remediation="Verify if this is legitimate network activity.",
                mitre_tactics=["Reconnaissance"]
            ))
        
        return findings
    
    def _is_external_ip(self, ip: str) -> bool:
        """Check if IP is external (not private range)."""
        return not any(ip.startswith(r) for r in self.CONFIG['private_ranges'])
    
    async def analyze_interfaces(self, interfaces: List[NetworkInterface]) -> List[SecurityFinding]:
        """Analyze network interface health."""
        findings = []
        
        for iface in interfaces:
            if iface.errors > self.CONFIG['error_rate_threshold']:
                findings.append(SecurityFinding(
                    threat_level=ThreatLevel.MEDIUM,
                    category="Interface Health",
                    title=f"High Error Rate on {iface.name}",
                    description=f"{iface.errors} transmission errors detected",
                    remediation="Check cable connections, drivers, and firmware updates",
                    evidence={'interface': iface.name, 'errors': iface.errors}
                ))
            
            if iface.dropped > self.CONFIG['dropped_packets_threshold']:
                findings.append(SecurityFinding(
                    threat_level=ThreatLevel.MEDIUM,
                    category="Network Quality",
                    title=f"Dropped Packets on {iface.name}",
                    description=f"{iface.dropped} packets dropped",
                    remediation="May indicate network congestion or buffer issues",
                    evidence={'interface': iface.name, 'dropped': iface.dropped}
                ))
        
        return findings

# ════════════════════════════════════════════════════════════════════════════
# CORE ASYNC DIAGNOSTIC ENGINE
# ════════════════════════════════════════════════════════════════════════════

class AsyncNetworkDiagnostics:
    """High-performance async network diagnostics."""
    
    def __init__(self):
        self.repository = DiagnosticRepository()
        self.intel_engine = CompositeIntelligenceEngine()
        self.analysis_engine = SecurityAnalysisEngine(self.intel_engine)
    
    async def execute_full_scan(self) -> DiagnosticReport:
        """Execute complete network diagnostic scan concurrently."""
        scan_start = datetime.now()
        scan_id = self._generate_scan_id()
        
        logger.log(LogLevel.INFO, f"Starting diagnostic scan: {scan_id}")
        
        # Concurrent data gathering
        metadata_task = asyncio.create_task(self._gather_system_info(scan_id))
        interfaces_task = asyncio.create_task(self._gather_network_interfaces())
        connections_task = asyncio.create_task(self._gather_connections())
        dns_task = asyncio.create_task(self._gather_dns_servers())
        
        metadata, interfaces, connections, dns_servers = await asyncio.gather(
            metadata_task, interfaces_task, connections_task, dns_task
        )
        
        # Analysis phase
        interface_findings = await self.analysis_engine.analyze_interfaces(interfaces)
        connection_findings = await self.analysis_engine.analyze_connections(connections, self.repository)
        
        all_findings = interface_findings + connection_findings
        threat_score = self._calculate_threat_score(all_findings)
        
        # Build report
        report = DiagnosticReport(
            metadata=metadata,
            interfaces=interfaces,
            connections=connections,
            dns_servers=dns_servers,
            findings=all_findings,
            threat_score=threat_score
        )
        
        # Persist
        self.repository.save_diagnostic_report(report)
        
        scan_duration = (datetime.now() - scan_start).total_seconds()
        logger.log(
            LogLevel.INFO,
            f"Scan complete: {scan_id}",
            duration_sec=scan_duration,
            findings=len(all_findings)
        )
        
        return report
    
    async def _gather_system_info(self, scan_id: str) -> ScanMetadata:
        """Gather system metadata."""
        return ScanMetadata(
            scan_id=scan_id,
            timestamp=datetime.now(),
            hostname=socket.gethostname(),
            os_type=platform.system(),
            os_version=platform.release(),
            python_version=platform.python_version()
        )
    
    async def _gather_network_interfaces(self) -> List[NetworkInterface]:
        """Gather network interface statistics."""
        if not HAS_PSUTIL:
            logger.log(LogLevel.WARNING, "psutil not available")
            return []
        
        interfaces = []
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            io_ctrs = psutil.net_io_counters(pernic=True)
            
            for iface_name in sorted(addrs.keys()):
                iface = NetworkInterface(
                    name=iface_name,
                    status="UP" if stats[iface_name].isup else "DOWN",
                    speed=stats[iface_name].speed,
                    mtu=stats[iface_name].mtu
                )
                
                for addr in addrs[iface_name]:
                    if addr.family == socket.AF_INET:
                        iface.ipv4 = addr.address
                    elif addr.family == socket.AF_INET6:
                        iface.ipv6 = addr.address
                
                if iface_name in io_ctrs:
                    io = io_ctrs[iface_name]
                    iface.bytes_sent = io.bytes_sent
                    iface.bytes_recv = io.bytes_recv
                    iface.errors = io.errin + io.errout
                    iface.dropped = io.dropin + io.dropout
                
                interfaces.append(iface)
        
        except Exception as e:
            logger.log(LogLevel.ERROR, f"Interface gathering failed: {e}")
        
        return interfaces
    
    async def _gather_connections(self) -> List[Connection]:
        """Gather active network connections."""
        if not HAS_PSUTIL:
            return []
        
        connections = []
        try:
            psutil_conns = psutil.net_connections(kind="inet")
            
            for pc in psutil_conns[:500]:  # Limit to prevent resource exhaustion
                conn = Connection(
                    protocol="TCP" if pc.type == socket.SOCK_STREAM else "UDP",
                    local_addr=pc.laddr.ip if hasattr(pc.laddr, 'ip') else pc.laddr[0],
                    local_port=pc.laddr.port if hasattr(pc.laddr, 'port') else pc.laddr[1],
                    remote_addr=pc.raddr.ip if hasattr(pc.raddr, 'ip') else (pc.raddr[0] if pc.raddr else ""),
                    remote_port=pc.raddr.port if hasattr(pc.raddr, 'port') else (pc.raddr[1] if pc.raddr else 0),
                    status=pc.status,
                    pid=pc.pid
                )
                
                if pc.pid:
                    try:
                        proc = psutil.Process(pc.pid)
                        conn.process_name = proc.name()
                        conn.process_path = proc.exe()
                        conn.user = proc.username()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                connections.append(conn)
        
        except psutil.AccessDenied:
            logger.log(LogLevel.WARNING, "Access denied for connection enumeration (need root)")
        except Exception as e:
            logger.log(LogLevel.ERROR, f"Connection gathering failed: {e}")
        
        return connections
    
    async def _gather_dns_servers(self) -> List[str]:
        """Gather DNS configuration."""
        dns_servers = []
        os_type = platform.system()
        
        try:
            if os_type == "Darwin":
                rc, out, err = CommandExecutor.run(["scutil", "--dns"])
                dns_servers.extend(re.findall(r"nameserver\[[\d]+\]\s*:\s*([\d.]+)", out))
            
            elif os_type == "Linux":
                for path in ("/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"):
                    if os.path.exists(path):
                        try:
                            with open(path, 'r') as f:
                                for line in f:
                                    if line.startswith("nameserver"):
                                        dns_servers.append(line.split()[-1])
                            break
                        except Exception:
                            pass
            
            elif os_type == "Windows":
                rc, out, err = CommandExecutor.run([
                    "powershell", "-NoProfile", "-Command",
                    "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses"
                ])
                dns_servers.extend(out.strip().split('\n'))
        
        except Exception as e:
            logger.log(LogLevel.DEBUG, f"DNS gathering failed: {e}")
        
        return [d.strip() for d in dns_servers if d.strip()]
    
    def _generate_scan_id(self) -> str:
        """Generate unique scan identifier."""
        timestamp = datetime.now().isoformat()
        hash_input = f"{socket.gethostname()}_{timestamp}".encode()
        return hashlib.sha256(hash_input).hexdigest()[:16]
    
    def _calculate_threat_score(self, findings: List[SecurityFinding]) -> float:
        """Calculate overall threat score (0-100)."""
        if not findings:
            return 0.0
        
        score = 0.0
        weights = {
            ThreatLevel.CRITICAL: 25,
            ThreatLevel.HIGH: 15,
            ThreatLevel.MEDIUM: 8,
            ThreatLevel.LOW: 3,
            ThreatLevel.INFO: 1
        }
        
        for finding in findings:
            score += weights.get(finding.threat_level, 0)
        
        return min(100.0, score)

# ════════════════════════════════════════════════════════════════════════════
# REPORT GENERATION (MULTI-FORMAT)
# ════════════════════════════════════════════════════════════════════════════

class ReportGenerator:
    """Generate comprehensive diagnostic reports in multiple formats."""
    
    @staticmethod
    def generate_console_report(report: DiagnosticReport) -> None:
        """Render report to console with color coding."""
        TerminalRenderer.banner(f"NETWORK DIAGNOSTIC REPORT - {report.metadata.scan_id}")
        
        # System info
        print(f"  Hostname: {report.metadata.hostname}")
        print(f"  OS: {report.metadata.os_type} {report.metadata.os_version}")
        print(f"  Scan Duration: {report.metadata.scan_duration:.2f}s")
        print(f"  Threat Score: {TerminalRenderer.colorize(f'{report.threat_score:.1f}/100', ANSIColor.CRITICAL)}\n")
        
        # Findings summary
        critical = len([f for f in report.findings if f.threat_level == ThreatLevel.CRITICAL])
        high = len([f for f in report.findings if f.threat_level == ThreatLevel.HIGH])
        print(f"  Findings: {critical} Critical, {high} High, {len(report.findings) - critical - high} Other\n")
        
        # Detailed findings
        if report.findings:
            TerminalRenderer.banner("SECURITY FINDINGS")
            for finding in report.findings:
                color_map = {
                    ThreatLevel.CRITICAL: ANSIColor.CRITICAL,
                    ThreatLevel.HIGH: ANSIColor.WARNING,
                    ThreatLevel.MEDIUM: ANSIColor.INFO,
                    ThreatLevel.LOW: ANSIColor.SUCCESS,
                    ThreatLevel.INFO: ANSIColor.DEBUG
                }
                
                print(f"  [{TerminalRenderer.colorize(finding.threat_level.value, color_map[finding.threat_level])}] {finding.title}")
                print(f"    Category: {finding.category}")
                print(f"    Description: {finding.description}")
                print(f"    Remediation: {finding.remediation}")
                print()
    
    @staticmethod
    def generate_json_report(report: DiagnosticReport, output_path: Optional[Path] = None) -> Path:
        """Export report as JSON."""
        if output_path is None:
            report_dir = Path.home() / ".network_diagnostic" / "reports"
            report_dir.mkdir(parents=True, exist_ok=True)
            output_path = report_dir / f"report_{report.metadata.scan_id}.json"
        
        json_data = {
            'metadata': asdict(report.metadata, dict_factory=lambda x: {k: str(v) if isinstance(v, datetime) else v for k, v in x}),
            'threat_score': report.threat_score,
            'interfaces': [asdict(i) for i in report.interfaces],
            'connections': [asdict(c) for c in report.connections[:50]],  # Limit for file size
            'dns_servers': report.dns_servers,
            'findings': [asdict(f) for f in report.findings],
        }
        
        with open(output_path, 'w') as f:
            json.dump(json_data, f, indent=2, default=str)
        
        logger.log(LogLevel.INFO, f"JSON report saved: {output_path}")
        return output_path

# ════════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ════════════════════════════════════════════════════════════════════════════

async def main():
    """Main entry point."""
    print(TerminalRenderer.colorize("═" * 80, ANSIColor.ACCENT))
    print(TerminalRenderer.colorize("🔍 NETWORK DIAGNOSTIC PRO - ELITE EDITION", ANSIColor.BOLD))
    print(TerminalRenderer.colorize("═" * 80, ANSIColor.ACCENT))
    
    diagnostics = AsyncNetworkDiagnostics()
    
    try:
        report = await diagnostics.execute_full_scan()
        
        # Output
        ReportGenerator.generate_console_report(report)
        json_path = ReportGenerator.generate_json_report(report)
        
        print(f"\n{TerminalRenderer.colorize(f'✓ Report saved: {json_path}', ANSIColor.SUCCESS)}")
    
    except KeyboardInterrupt:
        print(f"\n{TerminalRenderer.colorize('Scan interrupted by user', ANSIColor.WARNING)}")
    
    except Exception as e:
        print(f"\n{TerminalRenderer.colorize(f'✗ Scan failed: {e}', ANSIColor.CRITICAL)}")
        logger.log(LogLevel.ERROR, f"Scan failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
