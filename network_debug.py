#!/usr/bin/env python3
"""
Network Debug Tool for Linux Wi-Fi Performance Optimization
===========================================================

A comprehensive CLI-based tool for diagnosing Wi-Fi bottlenecks and optimizing
network performance on Linux systems.

Version: 1.0.0
License: MIT
Python: 3.7+

Features:
- Network speed testing with iperf3/speedtest fallback
- Signal strength and quality analysis
- Driver and configuration validation
- Smart performance recommendations
- Advanced logging and JSON export
- Cross-distribution support (Ubuntu, Pop!_OS, Arch, Fedora, Alpine)
"""

import argparse
import json
import logging
import os
import re
import subprocess
import sys
import time
import tempfile
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import urllib.request
import urllib.error
import configparser
import ipaddress
import socket
import shutil
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import yaml
import importlib
import pkgutil

# Tool version
VERSION = "1.0.0"

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    
    # Extended color palette for severity levels
    BRIGHT_RED = '\033[1;31m'
    BRIGHT_GREEN = '\033[1;32m'
    BRIGHT_YELLOW = '\033[1;33m'
    BRIGHT_BLUE = '\033[1;34m'
    BRIGHT_CYAN = '\033[1;36m'
    
    # Background colors for emphasis
    BG_RED = '\033[41m'
    BG_YELLOW = '\033[43m'
    BG_GREEN = '\033[42m'
    BG_BLUE = '\033[44m'

class Severity(Enum):
    """Severity levels for diagnostic findings"""
    CRITICAL = "CRITICAL"
    WARNING = "WARNING"
    INFO = "INFO"
    SUCCESS = "SUCCESS"

# Severity icons (text-based, no emojis)
class SeverityIcons:
    CRITICAL = "[!]"
    WARNING = "[⚠]"
    INFO = "[i]"
    SUCCESS = "[✓]"

class ColorManager:
    """Manages color output based on terminal capabilities and user preferences"""
    
    def __init__(self):
        self.colors_enabled = self._should_use_colors()
    
    def _should_use_colors(self) -> bool:
        """Determine if colors should be used based on terminal and environment"""
        # Check NO_COLOR environment variable (per no-color.org)
        if os.environ.get('NO_COLOR'):
            return False
        
        # Check if stdout is a TTY
        if not sys.stdout.isatty():
            return False
        
        # Check TERM environment variable
        term = os.environ.get('TERM', '')
        if term in ['dumb', 'unknown']:
            return False
        
        return True
    
    def set_colors_enabled(self, enabled: bool):
        """Override color settings (for --no-color flag)"""
        self.colors_enabled = enabled
    
    def colorize(self, text: str, severity: Severity) -> str:
        """Apply color coding based on severity"""
        if not self.colors_enabled:
            return text
        
        color_map = {
            Severity.CRITICAL: f"{Colors.BRIGHT_RED}{Colors.BOLD}",
            Severity.WARNING: f"{Colors.BRIGHT_YELLOW}{Colors.BOLD}",
            Severity.INFO: f"{Colors.BRIGHT_CYAN}",
            Severity.SUCCESS: f"{Colors.BRIGHT_GREEN}{Colors.BOLD}"
        }
        
        color = color_map.get(severity, Colors.WHITE)
        return f"{color}{text}{Colors.RESET}"
    
    def color(self, color_code: str, text: str) -> str:
        """Apply specific color if colors are enabled"""
        if not self.colors_enabled:
            return text
        return f"{color_code}{text}{Colors.RESET}"
    
    def get_severity_display(self, severity: Severity) -> str:
        """Get colored severity icon and text"""
        icon_map = {
            Severity.CRITICAL: SeverityIcons.CRITICAL,
            Severity.WARNING: SeverityIcons.WARNING,
            Severity.INFO: SeverityIcons.INFO,
            Severity.SUCCESS: SeverityIcons.SUCCESS
        }
        
        icon = icon_map.get(severity, SeverityIcons.INFO)
        if self.colors_enabled:
            return self.colorize(f"{icon} {severity.value}", severity)
        else:
            return f"{icon} {severity.value}"

@dataclass
class NetworkInterface:
    """Network interface information"""
    name: str
    type: str
    driver: str
    state: str
    mac_address: str
    mtu: int
    speed: Optional[str] = None
    duplex: Optional[str] = None

@dataclass
class WifiInfo:
    """Wi-Fi specific information"""
    interface: str
    ssid: str
    frequency: Optional[float] = None
    channel: Optional[int] = None
    signal_dbm: Optional[int] = None
    bitrate: Optional[str] = None
    tx_power: Optional[int] = None
    mode: Optional[str] = None
    security: Optional[str] = None
    country_code: Optional[str] = None

@dataclass
class SpeedTestResult:
    """Speed test results"""
    download_mbps: float
    upload_mbps: float
    ping_ms: float
    server: str
    timestamp: str
    test_method: str

@dataclass
class DiagnosticResult:
    """Diagnostic finding"""
    category: str
    severity: Severity
    message: str
    recommendation: Optional[str] = None
    technical_details: Optional[str] = None

@dataclass
class SystemConfig:
    """System configuration data"""
    sysctl_params: Dict[str, str]
    network_manager_configs: Dict[str, Dict[str, str]]
    dns_config: Dict[str, str]
    firewall_rules: List[str]
    driver_params: Dict[str, Dict[str, str]]
    interface_settings: Dict[str, Dict[str, str]]

@dataclass
class OptimizationRule:
    """Performance optimization rule"""
    name: str
    category: str
    severity: Severity
    description: str
    current_value: Optional[str]
    recommended_value: str
    rationale: str
    fix_command: str
    impact: str
    safe_to_auto_apply: bool = False

@dataclass
class BenchmarkResult:
    """Network benchmark measurements"""
    timestamp: str
    download_mbps: float
    upload_mbps: float
    ping_ms: float
    tcp_retransmissions: int
    dns_latency_ms: float
    test_method: str

@dataclass
class BenchmarkComparison:
    """Before/after benchmark comparison"""
    before: BenchmarkResult
    after: BenchmarkResult
    improvements: Dict[str, str]
    regressions: Dict[str, str]
    overall_improvement: float

@dataclass
class NetworkOptimization:
    """Network optimization analysis"""
    timestamp: str
    hostname: str
    system_config: SystemConfig
    optimization_rules: List[OptimizationRule]
    performance_score: float
    bottlenecks: List[str]
    recommendations_by_category: Dict[str, List[OptimizationRule]]

@dataclass
class NetworkDiagnostic:
    """Complete network diagnostic data"""
    timestamp: str
    hostname: str
    distribution: str
    kernel_version: str
    interfaces: List[NetworkInterface]
    wifi_info: Optional[WifiInfo]
    speed_test: Optional[SpeedTestResult]
    findings: List[DiagnosticResult]
    system_info: Dict[str, str]
    optimization_analysis: Optional[NetworkOptimization] = None

class NetworkDebugger:
    """Main network debugging class"""
    
    def __init__(self, verbose: bool = False, no_color: bool = False, dry_run: bool = False, 
                 skip_rules: Optional[List[str]] = None, config_file: Optional[str] = None):
        self.verbose = verbose
        self.dry_run = dry_run
        self.logger = self._setup_logging()
        self.findings: List[DiagnosticResult] = []
        self.color_manager = ColorManager()
        
        # Override color settings if --no-color flag is used
        if no_color:
            self.color_manager.set_colors_enabled(False)
        
        # Initialize rule registry
        self.rule_registry = RuleRegistry(self.logger)
        self.rule_registry.load_rules()
        
        # Load configuration file if provided
        if config_file:
            self.rule_registry.load_config(config_file)
        
        # Disable rules specified via CLI
        if skip_rules:
            for rule in skip_rules:
                self.rule_registry.disable_rule(rule)
    
    def _setup_logging(self) -> logging.Logger:
        """Configure logging"""
        logger = logging.getLogger('network_debug')
        logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def _run_command(self, cmd: Union[str, List[str]], 
                    timeout: int = 30, 
                    check: bool = False) -> Tuple[int, str, str]:
        """Execute system command with timeout and error handling"""
        try:
            if isinstance(cmd, str):
                cmd = cmd.split()
            
            self.logger.debug(f"Executing command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=timeout,
                check=check
            )
            
            self.logger.debug(f"Command exit code: {result.returncode}")
            if result.stdout:
                self.logger.debug(f"Command stdout: {result.stdout[:500]}...")
            if result.stderr:
                self.logger.debug(f"Command stderr: {result.stderr[:500]}...")
                
            return result.returncode, result.stdout, result.stderr
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"Command timed out after {timeout}s: {' '.join(cmd)}")
            return -1, "", f"Command timed out after {timeout}s"
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command failed: {' '.join(cmd)}, error: {e}")
            return e.returncode, e.stdout, e.stderr
        except FileNotFoundError as e:
            # Common for missing optional tools, log as debug instead of error
            if any(tool in ' '.join(cmd) for tool in ['iw', 'dig', 'nft', 'nslookup', 'iwconfig']):
                self.logger.debug(f"Optional tool not found: {' '.join(cmd)}")
            else:
                self.logger.error(f"Required command not found: {' '.join(cmd)}")
            return -1, "", str(e)
        except Exception as e:
            self.logger.error(f"Unexpected error running command: {e}")
            return -1, "", str(e)
    
    def _get_severity_counts(self) -> Dict[Severity, int]:
        """Get count of findings by severity level"""
        counts = {severity: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts
    
    def _print_diagnostic_summary(self):
        """Print diagnostic summary with severity counts"""
        counts = self._get_severity_counts()
        
        # Build summary parts
        summary_parts = []
        if counts[Severity.CRITICAL] > 0:
            summary_parts.append(f"{counts[Severity.CRITICAL]} Critical")
        if counts[Severity.WARNING] > 0:
            summary_parts.append(f"{counts[Severity.WARNING]} Warning{'s' if counts[Severity.WARNING] > 1 else ''}")
        if counts[Severity.INFO] > 0:
            summary_parts.append(f"{counts[Severity.INFO]} Info")
        if counts[Severity.SUCCESS] > 0:
            summary_parts.append(f"{counts[Severity.SUCCESS]} Success")
        
        if summary_parts:
            summary_text = f"Summary: {', '.join(summary_parts)}"
            print(f"\n{self.color_manager.color(Colors.BOLD, summary_text)}")
        else:
            print(f"\n{self.color_manager.color(Colors.BOLD, 'Summary: No findings')}")
    
    def _print_context_summary(self):
        """Print summary of what checks were performed and skipped"""
        # Check system capabilities
        has_wifi = self._get_wifi_interface() is not None
        has_systemd = self._is_systemd_active()
        has_internet = self._check_internet_connectivity()
        
        # Check available tools
        tools = {
            'nmcli': shutil.which('nmcli') is not None,
            'iw': shutil.which('iw') is not None,
            'iwlist': shutil.which('iwlist') is not None,
            'dig': shutil.which('dig') is not None,
            'nslookup': shutil.which('nslookup') is not None,
            'ethtool': shutil.which('ethtool') is not None,
            'rfkill': shutil.which('rfkill') is not None
        }
        
        print(f"\n{self.color_manager.color(Colors.BOLD, 'System Context:')}")
        
        # Wireless capability
        wifi_status = self.color_manager.color(Colors.BRIGHT_GREEN, "✓ Available") if has_wifi else self.color_manager.color(Colors.YELLOW, "✗ Not detected")
        print(f"  Wi-Fi interface: {wifi_status}")
        
        # Internet connectivity
        internet_status = self.color_manager.color(Colors.BRIGHT_GREEN, "✓ Connected") if has_internet else self.color_manager.color(Colors.YELLOW, "✗ No connectivity")
        print(f"  Internet access: {internet_status}")
        
        # Init system
        init_system = "systemd" if has_systemd else "Other (OpenRC/SysV/etc.)"
        init_color = Colors.BRIGHT_GREEN if has_systemd else Colors.BRIGHT_CYAN
        print(f"  Init system: {self.color_manager.color(init_color, init_system)}")
        
        # Tool availability summary
        available_tools = [tool for tool, available in tools.items() if available]
        missing_tools = [tool for tool, available in tools.items() if not available]
        
        if available_tools:
            tools_text = self.color_manager.color(Colors.BRIGHT_GREEN, f"✓ {len(available_tools)}/{'7'} tools available")
            print(f"  Network tools: {tools_text}")
            if self.verbose:
                print(f"    Available: {', '.join(available_tools)}")
                if missing_tools:
                    print(f"    Missing: {', '.join(missing_tools)}")
        else:
            tools_text = self.color_manager.color(Colors.YELLOW, "⚠ Limited toolset")
            print(f"  Network tools: {tools_text}")
        
        # Limitations summary
        limitations = []
        if not has_wifi:
            limitations.append("Wi-Fi optimizations skipped")
        if not has_internet:
            limitations.append("Internet-dependent checks skipped")
        if not tools['nmcli'] and not tools['iwlist']:
            limitations.append("Wi-Fi scanning limited")
        if not tools['dig'] and not tools['nslookup']:
            limitations.append("DNS latency testing skipped")
        
        if limitations:
            print(f"  Limitations: {self.color_manager.color(Colors.YELLOW, '; '.join(limitations))}")
        else:
            print(f"  {self.color_manager.color(Colors.BRIGHT_GREEN, '✓ Full diagnostic capability')}")
    
    def _add_finding(self, category: str, severity: Severity, message: str,
                    recommendation: Optional[str] = None,
                    technical_details: Optional[str] = None):
        """Add a diagnostic finding"""
        finding = DiagnosticResult(
            category=category,
            severity=severity,
            message=message,
            recommendation=recommendation,
            technical_details=technical_details
        )
        self.findings.append(finding)
    
    def _detect_distribution(self) -> str:
        """Detect Linux distribution"""
        try:
            with open('/etc/os-release', 'r') as f:
                content = f.read()
                if 'Ubuntu' in content:
                    return 'Ubuntu'
                elif 'Pop!_OS' in content:
                    return 'Pop!_OS'
                elif 'Arch' in content:
                    return 'Arch'
                elif 'Fedora' in content:
                    return 'Fedora'
                elif 'Alpine' in content:
                    return 'Alpine'
                else:
                    # Try to extract NAME field
                    for line in content.split('\n'):
                        if line.startswith('NAME='):
                            return line.split('=')[1].strip('"')
        except:
            pass
        
        return 'Unknown'
    
    def _get_kernel_version(self) -> str:
        """Get kernel version"""
        code, stdout, _ = self._run_command(['uname', '-r'])
        return stdout.strip() if code == 0 else 'Unknown'
    
    def _get_network_interfaces(self) -> List[NetworkInterface]:
        """Get network interface information"""
        interfaces = []
        
        # Get basic interface info
        code, stdout, _ = self._run_command(['ip', 'link', 'show'])
        if code != 0:
            return interfaces
        
        for line in stdout.split('\n'):
            if ': ' in line and 'state' in line.lower():
                parts = line.split()
                if len(parts) >= 2:
                    iface_name = parts[1].rstrip(':')
                    
                    # Skip loopback and docker interfaces
                    if iface_name.startswith(('lo', 'docker', 'br-')):
                        continue
                    
                    # Determine interface type with smart detection
                    iface_type = 'unknown'
                    if self._is_wireless_interface(iface_name):
                        iface_type = 'wifi'
                    elif 'en' in iface_name or 'eth' in iface_name:
                        iface_type = 'ethernet'
                    # Could add more detection for other types (bridge, tun, etc.)
                    
                    # Get more detailed info
                    driver = self._get_interface_driver(iface_name)
                    state = self._get_interface_state(iface_name)
                    mac = self._get_interface_mac(iface_name)
                    mtu = self._get_interface_mtu(iface_name)
                    
                    interfaces.append(NetworkInterface(
                        name=iface_name,
                        type=iface_type,
                        driver=driver,
                        state=state,
                        mac_address=mac,
                        mtu=mtu
                    ))
        
        return interfaces
    
    def _get_interface_driver(self, interface: str) -> str:
        """Get driver for network interface"""
        try:
            driver_path = f"/sys/class/net/{interface}/device/driver"
            if os.path.exists(driver_path):
                driver_link = os.readlink(driver_path)
                return os.path.basename(driver_link)
        except:
            pass
        return 'unknown'
    
    def _get_interface_state(self, interface: str) -> str:
        """Get interface state"""
        code, stdout, _ = self._run_command(['ip', 'link', 'show', interface])
        if code == 0 and 'state' in stdout.lower():
            for part in stdout.split():
                if part.upper() in ['UP', 'DOWN', 'UNKNOWN']:
                    return part.upper()
        return 'UNKNOWN'
    
    def _get_interface_mac(self, interface: str) -> str:
        """Get MAC address for interface"""
        try:
            with open(f'/sys/class/net/{interface}/address', 'r') as f:
                return f.read().strip()
        except:
            return 'unknown'
    
    def _get_interface_mtu(self, interface: str) -> int:
        """Get MTU for interface"""
        try:
            with open(f'/sys/class/net/{interface}/mtu', 'r') as f:
                return int(f.read().strip())
        except:
            return 0
    
    def _is_wireless_interface(self, interface: str) -> bool:
        """Verify if an interface is truly wireless"""
        try:
            # Check for wireless directory in sysfs (most reliable method)
            wireless_path = f'/sys/class/net/{interface}/wireless'
            if os.path.exists(wireless_path):
                self.logger.debug(f"Interface {interface} confirmed wireless via sysfs")
                return True
            
            # Fallback: check with iw dev if available
            if shutil.which('iw'):
                code, stdout, _ = self._run_command(['iw', 'dev'])
                if code == 0:
                    # Look for the interface in iw dev output
                    current_interface = None
                    for line in stdout.split('\n'):
                        line = line.strip()
                        if line.startswith('Interface '):
                            current_interface = line.split()[1]
                        elif current_interface == interface and 'type managed' in line:
                            self.logger.debug(f"Interface {interface} confirmed wireless via iw dev")
                            return True
            
            # Final fallback: check iwconfig
            if shutil.which('iwconfig'):
                code, stdout, _ = self._run_command(['iwconfig', interface])
                if code == 0 and 'IEEE 802.11' in stdout:
                    self.logger.debug(f"Interface {interface} confirmed wireless via iwconfig")
                    return True
            
            self.logger.debug(f"Interface {interface} not confirmed as wireless")
            return False
            
        except Exception as e:
            self.logger.debug(f"Error checking wireless capability for {interface}: {e}")
            return False
    
    def _get_wifi_interface(self) -> Optional[str]:
        """Get the primary Wi-Fi interface with proper wireless verification"""
        potential_interfaces = []
        
        # Check all network interfaces
        try:
            net_path = Path('/sys/class/net')
            if net_path.exists():
                for iface_path in net_path.iterdir():
                    if iface_path.is_dir():
                        iface_name = iface_path.name
                        # Skip obvious non-wireless interfaces
                        if iface_name.startswith(('lo', 'docker', 'br-', 'veth', 'tun', 'tap')):
                            continue
                        potential_interfaces.append(iface_name)
        except Exception as e:
            self.logger.debug(f"Error scanning /sys/class/net: {e}")
        
        # Verify each potential interface
        for interface in potential_interfaces:
            if self._is_wireless_interface(interface):
                return interface
        
        # If no interfaces found via sysfs, try iwconfig as last resort
        if shutil.which('iwconfig'):
            code, stdout, _ = self._run_command(['iwconfig'])
            if code == 0:
                for line in stdout.split('\n'):
                    if 'IEEE 802.11' in line and 'no wireless extensions' not in line.lower():
                        iface_name = line.split()[0]
                        if self._is_wireless_interface(iface_name):
                            return iface_name
        
        self.logger.debug("No wireless interfaces found")
        return None
    
    def _get_wifi_info(self) -> Optional[WifiInfo]:
        """Get detailed Wi-Fi information"""
        wifi_iface = self._get_wifi_interface()
        if not wifi_iface:
            return None
        
        wifi_info = WifiInfo(interface=wifi_iface, ssid='')
        
        # Get connection info from iwconfig
        code, stdout, _ = self._run_command(['iwconfig', wifi_iface])
        if code == 0:
            for line in stdout.split('\n'):
                if 'ESSID:' in line:
                    match = re.search(r'ESSID:"([^"]*)"', line)
                    if match:
                        wifi_info.ssid = match.group(1)
                elif 'Frequency:' in line:
                    match = re.search(r'Frequency:([0-9.]+)', line)
                    if match:
                        wifi_info.frequency = float(match.group(1))
                elif 'Bit Rate=' in line:
                    match = re.search(r'Bit Rate=([0-9.]+\s*[MG]b/s)', line)
                    if match:
                        wifi_info.bitrate = match.group(1)
                elif 'Signal level=' in line:
                    match = re.search(r'Signal level=(-?\d+)', line)
                    if match:
                        wifi_info.signal_dbm = int(match.group(1))
        
        # Get additional info from iw
        code, stdout, _ = self._run_command(['iw', wifi_iface, 'info'])
        if code == 0:
            for line in stdout.split('\n'):
                if 'channel' in line.lower():
                    match = re.search(r'channel\s+(\d+)', line)
                    if match:
                        wifi_info.channel = int(match.group(1))
                elif 'txpower' in line.lower():
                    match = re.search(r'txpower\s+([0-9.]+)', line)
                    if match:
                        wifi_info.tx_power = int(float(match.group(1)))
        
        # Get country code
        code, stdout, _ = self._run_command(['iw', 'reg', 'get'])
        if code == 0:
            match = re.search(r'country\s+([A-Z]{2})', stdout)
            if match:
                wifi_info.country_code = match.group(1)
        
        return wifi_info
    
    def _test_speed_iperf3(self) -> Optional[SpeedTestResult]:
        """Test network speed using iperf3"""
        # Try to find a public iperf3 server
        servers = [
            'iperf.he.net',
            'ping.online.net',
            'speedtest.serverius.net'
        ]
        
        for server in servers:
            self.logger.info(f"Testing speed with iperf3 server: {server}")
            
            # Test download
            code, stdout, _ = self._run_command([
                'iperf3', '-c', server, '-J', '-t', '10'
            ], timeout=60)
            
            if code == 0:
                try:
                    result = json.loads(stdout)
                    download_bps = result['end']['sum_received']['bits_per_second']
                    download_mbps = download_bps / 1_000_000
                    
                    # Test upload
                    code, stdout, _ = self._run_command([
                        'iperf3', '-c', server, '-J', '-t', '10', '-R'
                    ], timeout=60)
                    
                    if code == 0:
                        result = json.loads(stdout)
                        upload_bps = result['end']['sum_sent']['bits_per_second']
                        upload_mbps = upload_bps / 1_000_000
                        
                        return SpeedTestResult(
                            download_mbps=download_mbps,
                            upload_mbps=upload_mbps,
                            ping_ms=0.0,  # iperf3 doesn't provide ping
                            server=server,
                            timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
                            test_method='iperf3'
                        )
                except (json.JSONDecodeError, KeyError) as e:
                    self.logger.debug(f"Failed to parse iperf3 output: {e}")
                    continue
        
        return None
    
    def _test_speed_speedtest(self) -> Optional[SpeedTestResult]:
        """Test network speed using speedtest-cli"""
        code, stdout, _ = self._run_command([
            'speedtest-cli', '--json'
        ], timeout=120)
        
        if code == 0:
            try:
                result = json.loads(stdout)
                return SpeedTestResult(
                    download_mbps=result['download'] / 1_000_000,
                    upload_mbps=result['upload'] / 1_000_000,
                    ping_ms=result['ping'],
                    server=result['server']['name'],
                    timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
                    test_method='speedtest-cli'
                )
            except (json.JSONDecodeError, KeyError) as e:
                self.logger.debug(f"Failed to parse speedtest-cli output: {e}")
        
        return None
    
    def _check_dns_latency(self) -> Optional[float]:
        """Check DNS resolution latency with smart tool detection"""
        # Check internet connectivity first
        if not self._check_internet_connectivity():
            self.logger.info("Skipping DNS latency check — no internet connectivity")
            return None
        
        # Check for available DNS tools
        has_dig = shutil.which('dig')
        has_nslookup = shutil.which('nslookup')
        
        if not has_dig and not has_nslookup:
            self.logger.info("Skipping DNS latency check — neither dig nor nslookup available")
            return None
        
        # Use dig if available (more precise timing)
        if has_dig:
            code, stdout, _ = self._run_command([
                'dig', '+stats', 'google.com'
            ])
            
            if code == 0:
                for line in stdout.split('\n'):
                    if 'Query time:' in line:
                        match = re.search(r'Query time:\s*(\d+)', line)
                        if match:
                            latency = float(match.group(1))
                            self.logger.debug(f"DNS latency measured with dig: {latency}ms")
                            return latency
        
        # Fallback to nslookup with manual timing
        elif has_nslookup:
            start_time = time.time()
            code, stdout, _ = self._run_command(['nslookup', 'google.com'])
            latency = (time.time() - start_time) * 1000
            
            if code == 0:
                self.logger.debug(f"DNS latency measured with nslookup: {latency:.1f}ms")
                return latency
        
        return None
    
    def _check_tcp_retransmissions(self) -> Dict[str, int]:
        """Check TCP retransmission statistics"""
        stats = {}
        
        try:
            with open('/proc/net/netstat', 'r') as f:
                content = f.read()
                
            for line in content.split('\n'):
                if line.startswith('TcpExt:'):
                    if 'TCPRetransSegs' in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part == 'TCPRetransSegs' and i + 1 < len(parts):
                                stats['retransmissions'] = int(parts[i + 1])
                                break
        except:
            pass
        
        return stats
    
    def _check_driver_issues(self, interfaces: List[NetworkInterface]):
        """Check for known driver issues"""
        for interface in interfaces:
            if interface.type == 'wifi':
                driver = interface.driver
                
                # Check for known problematic drivers
                if driver in ['rtl8192ce', 'rtl8723be']:
                    self._add_finding(
                        'driver',
                        Severity.WARNING,
                        f"Known issues with {driver} driver",
                        f"Consider using alternative driver or kernel parameters: "
                        f"echo 'options {driver} swenc=1 ips=0' >> /etc/modprobe.d/{driver}.conf"
                    )
                
                # Check power management settings
                self._check_power_management(interface.name)
    
    def _check_power_management(self, interface: str):
        """Check Wi-Fi power management settings"""
        if not shutil.which('iw'):
            self.logger.debug("iw not available, skipping power management check")
            return
        
        code, stdout, _ = self._run_command(['iw', interface, 'get', 'power_save'])
        if code == 0 and 'Power save: on' in stdout:
            self._add_finding(
                'power_management',
                Severity.WARNING,
                f"Power saving enabled on {interface}",
                f"Disable power saving for better performance: "
                f"iw {interface} set power_save off"
            )
    
    def _check_rfkill_status(self):
        """Check if Wi-Fi is blocked by rfkill"""
        if not shutil.which('rfkill'):
            self.logger.debug("rfkill not available, skipping rfkill check")
            return
        
        code, stdout, _ = self._run_command(['rfkill', 'list'])
        if code == 0:
            for line in stdout.split('\n'):
                if 'wlan' in line.lower() or 'wireless' in line.lower():
                    if 'blocked: yes' in line.lower():
                        self._add_finding(
                            'rfkill',
                            Severity.CRITICAL,
                            "Wi-Fi is blocked by rfkill",
                            "Unblock Wi-Fi: rfkill unblock wifi"
                        )
    
    def _check_channel_congestion(self):
        """Check for Wi-Fi channel congestion with smart context awareness"""
        # First check if we have a wireless interface
        wifi_iface = self._get_wifi_interface()
        if not wifi_iface:
            self.logger.info("Skipping channel congestion check — no wireless interfaces detected")
            return
        
        if not shutil.which('nmcli'):
            self.logger.info("Skipping channel congestion check — nmcli not available")
            return
        
        code, stdout, _ = self._run_command(['nmcli', 'dev', 'wifi', 'list'])
        if code == 0:
            channels = {}
            networks_found = 0
            
            for line in stdout.split('\n')[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 3 and parts[0] != '--':  # Valid network entry
                    try:
                        channel = int(parts[2])
                        channels[channel] = channels.get(channel, 0) + 1
                        networks_found += 1
                    except ValueError:
                        continue
            
            if networks_found == 0:
                self.logger.info("Skipping channel congestion check — no Wi-Fi networks detected in scan")
                return
            
            self.logger.debug(f"Found {networks_found} Wi-Fi networks across {len(channels)} channels")
            
            # Check for overcrowded channels
            congested_channels = []
            for channel, count in channels.items():
                if count > 3:
                    congested_channels.append((channel, count))
            
            if congested_channels:
                for channel, count in congested_channels:
                    self._add_finding(
                        'channel_congestion',
                        Severity.WARNING,
                        f"Channel {channel} has {count} networks (congested)",
                        f"Consider switching to a less congested channel"
                    )
            else:
                self.logger.debug("No channel congestion detected")
        else:
            self.logger.info("Skipping channel congestion check — nmcli wifi scan failed")
    
    def _scan_for_5ghz_networks(self, current_ssid: str) -> bool:
        """Scan for available 5GHz networks, preferably matching current SSID"""
        found_5ghz = False
        same_ssid_5ghz = False
        
        # Try nmcli first (most reliable)
        if shutil.which('nmcli'):
            self.logger.debug("Scanning for 5GHz networks with nmcli")
            code, stdout, _ = self._run_command(['nmcli', 'dev', 'wifi', 'list'])
            if code == 0:
                for line in stdout.split('\n')[1:]:  # Skip header
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 4:
                            try:
                                # Extract SSID and frequency
                                ssid = parts[1] if parts[1] != '--' else ''
                                freq_str = parts[3] if len(parts) > 3 else ''
                                
                                # Check if frequency indicates 5GHz (5000+ MHz)
                                if freq_str.isdigit() and int(freq_str) >= 5000:
                                    found_5ghz = True
                                    if ssid == current_ssid:
                                        same_ssid_5ghz = True
                                        self.logger.debug(f"Found 5GHz network for current SSID: {ssid}")
                                        break
                            except (ValueError, IndexError):
                                continue
        
        # Fallback to iwlist scan if nmcli not available
        elif shutil.which('iwlist'):
            wifi_iface = self._get_wifi_interface()
            if wifi_iface:
                self.logger.debug("Scanning for 5GHz networks with iwlist")
                code, stdout, _ = self._run_command(['iwlist', wifi_iface, 'scan'])
                if code == 0:
                    current_ssid_block = False
                    current_freq = None
                    
                    for line in stdout.split('\n'):
                        line = line.strip()
                        if 'ESSID:' in line:
                            essid = line.split('ESSID:')[1].strip('"')
                            if essid == current_ssid:
                                current_ssid_block = True
                            else:
                                current_ssid_block = False
                        elif 'Frequency:' in line:
                            freq_match = re.search(r'Frequency:([0-9.]+)', line)
                            if freq_match:
                                freq_ghz = float(freq_match.group(1))
                                if freq_ghz >= 5.0:
                                    found_5ghz = True
                                    if current_ssid_block:
                                        same_ssid_5ghz = True
                                        self.logger.debug(f"Found 5GHz network for current SSID via iwlist")
                                        break
        else:
            self.logger.debug("Neither nmcli nor iwlist available for 5GHz scanning")
            return False
        
        if not found_5ghz:
            self.logger.info("No 5GHz networks detected in scan")
        elif same_ssid_5ghz:
            self.logger.info(f"5GHz variant of current SSID '{current_ssid}' detected")
        else:
            self.logger.info("5GHz networks detected but not for current SSID")
        
        return same_ssid_5ghz
    
    def _check_band_usage(self, wifi_info: WifiInfo):
        """Check if using optimal Wi-Fi band with smart 5GHz detection"""
        if wifi_info.frequency:
            if wifi_info.frequency < 3.0:  # 2.4GHz
                self.logger.debug(f"Connected to 2.4GHz band ({wifi_info.frequency:.1f} GHz)")
                
                # Check if tools for 5GHz scanning are available
                if not shutil.which('nmcli') and not shutil.which('iwlist'):
                    self.logger.info("Skipping 5GHz band check — neither nmcli nor iwlist available")
                    return
                
                # Scan for 5GHz networks
                if self._scan_for_5ghz_networks(wifi_info.ssid):
                    self._add_finding(
                        'band_usage',
                        Severity.WARNING,
                        f"Connected to 2.4GHz band, 5GHz variant of '{wifi_info.ssid}' available",
                        f"Switch to 5GHz band for better performance"
                    )
                else:
                    self.logger.info(f"Skipping 5GHz suggestion — no 5GHz variant of '{wifi_info.ssid}' detected")
    
    def _suggest_tcp_tuning(self):
        """Suggest TCP tuning parameters"""
        suggestions = [
            "net.core.rmem_max = 134217728",
            "net.core.wmem_max = 134217728",
            "net.ipv4.tcp_rmem = 4096 87380 134217728",
            "net.ipv4.tcp_wmem = 4096 65536 134217728",
            "net.ipv4.tcp_window_scaling = 1",
            "net.ipv4.tcp_timestamps = 1",
            "net.ipv4.tcp_sack = 1"
        ]
        
        self._add_finding(
            'tcp_tuning',
            Severity.INFO,
            "TCP tuning can improve performance",
            f"Add to /etc/sysctl.conf:\n" + "\n".join(suggestions)
        )

    def _crawl_sysctl_config(self) -> Dict[str, str]:
        """Crawl current sysctl parameters"""
        sysctl_params = {}
        
        # Get all current sysctl values
        code, stdout, _ = self._run_command(['sysctl', '-a'], timeout=60)
        if code == 0:
            for line in stdout.split('\n'):
                if '=' in line:
                    try:
                        key, value = line.split('=', 1)
                        sysctl_params[key.strip()] = value.strip()
                    except ValueError:
                        continue
        
        # Also read /etc/sysctl.conf if it exists
        try:
            with open('/etc/sysctl.conf', 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        sysctl_params[f"config_{key.strip()}"] = value.strip()
        except (FileNotFoundError, IOError):
            pass
        
        return sysctl_params

    def _crawl_network_manager_configs(self) -> Dict[str, Dict[str, str]]:
        """Crawl NetworkManager connection configurations"""
        configs = {}
        
        # Skip if NetworkManager is not available (e.g., in Alpine/minimal containers)
        if not shutil.which('nmcli'):
            self.logger.debug("NetworkManager not available, skipping config crawl")
            return configs
        
        nm_path = Path('/etc/NetworkManager/system-connections')
        
        if nm_path.exists():
            for config_file in nm_path.glob('*.nmconnection'):
                try:
                    parser = configparser.ConfigParser()
                    parser.read(config_file)
                    
                    config_data = {}
                    for section in parser.sections():
                        for key, value in parser.items(section):
                            config_data[f"{section}.{key}"] = value
                    
                    configs[config_file.stem] = config_data
                except Exception as e:
                    self.logger.debug(f"Failed to parse {config_file}: {e}")
        
        return configs

    def _crawl_dns_config(self) -> Dict[str, str]:
        """Crawl DNS configuration"""
        dns_config = {}
        
        # Check /etc/resolv.conf
        try:
            with open('/etc/resolv.conf', 'r') as f:
                content = f.read()
                dns_config['resolv_conf_raw'] = content
                
                nameservers = []
                for line in content.split('\n'):
                    if line.strip().startswith('nameserver'):
                        nameservers.append(line.split()[1])
                dns_config['nameservers'] = ','.join(nameservers)
        except (FileNotFoundError, IOError):
            pass
        
        # Check systemd-resolved status
        code, stdout, _ = self._run_command(['resolvectl', 'status'])
        if code == 0:
            dns_config['resolvectl_status'] = stdout
        
        # Check if systemd-resolved is active
        code, stdout, _ = self._run_command(['systemctl', 'is-active', 'systemd-resolved'])
        if code == 0:
            dns_config['systemd_resolved_active'] = stdout.strip()
        
        return dns_config

    def _crawl_firewall_rules(self) -> List[str]:
        """Crawl firewall rules that might impact performance"""
        rules = []
        
        # Check iptables
        for table in ['filter', 'nat', 'mangle']:
            code, stdout, _ = self._run_command(['iptables', '-t', table, '-L', '-n'])
            if code == 0:
                rule_count = len(stdout.split('\n'))
                rules.append(f"iptables_{table}: {rule_count} rules")
        
        # Check nftables
        code, stdout, _ = self._run_command(['nft', 'list', 'ruleset'])
        if code == 0:
            line_count = len(stdout.split('\n'))
            rules.append(f"nftables: {line_count} lines")
        
        return rules

    def _crawl_driver_params(self) -> Dict[str, Dict[str, str]]:
        """Crawl driver parameters"""
        driver_params = {}
        
        # Check modprobe configs
        modprobe_dirs = ['/etc/modprobe.d', '/usr/lib/modprobe.d']
        for mod_dir in modprobe_dirs:
            if Path(mod_dir).exists():
                for config_file in Path(mod_dir).glob('*.conf'):
                    try:
                        with open(config_file, 'r') as f:
                            content = f.read()
                            driver_params[config_file.stem] = {'content': content}
                    except (FileNotFoundError, IOError):
                        pass
        
        # Check loaded modules
        code, stdout, _ = self._run_command(['lsmod'])
        if code == 0:
            driver_params['loaded_modules'] = {'content': stdout}
        
        return driver_params

    def _crawl_interface_settings(self) -> Dict[str, Dict[str, str]]:
        """Crawl network interface settings"""
        interface_settings = {}
        
        # Skip if ethtool is not available
        if not shutil.which('ethtool'):
            self.logger.debug("ethtool not available, skipping interface settings crawl")
            return interface_settings
        
        interfaces = self._get_network_interfaces()
        for interface in interfaces:
            iface_name = interface.name
            settings = {}
            
            # Get ethtool information
            code, stdout, _ = self._run_command(['ethtool', iface_name])
            if code == 0:
                settings['ethtool_info'] = stdout
            
            # Get ring buffer settings
            code, stdout, _ = self._run_command(['ethtool', '-g', iface_name])
            if code == 0:
                settings['ring_buffers'] = stdout
            
            # Get offload settings
            code, stdout, _ = self._run_command(['ethtool', '-k', iface_name])
            if code == 0:
                settings['offload_settings'] = stdout
            
            # Get driver info
            code, stdout, _ = self._run_command(['ethtool', '-i', iface_name])
            if code == 0:
                settings['driver_info'] = stdout
            
            if settings:
                interface_settings[iface_name] = settings
        
        return interface_settings

    def _calculate_performance_score(self, rules: List[OptimizationRule]) -> float:
        """Calculate overall performance score"""
        total_score = 100.0
        
        for rule in rules:
            if rule.severity == Severity.CRITICAL:
                total_score -= 15.0
            elif rule.severity == Severity.WARNING:
                total_score -= 10.0
            elif rule.severity == Severity.INFO:
                total_score -= 5.0
        
        return max(0.0, total_score)

    def _identify_bottlenecks(self, rules: List[OptimizationRule]) -> List[str]:
        """Identify primary performance bottlenecks"""
        bottlenecks = []
        
        critical_rules = [r for r in rules if r.severity == Severity.CRITICAL]
        warning_rules = [r for r in rules if r.severity == Severity.WARNING]
        
        if critical_rules:
            bottlenecks.append("Critical configuration issues detected")
        
        if len(warning_rules) > 3:
            bottlenecks.append("Multiple configuration warnings")
        
        # Check for specific bottleneck patterns
        tcp_issues = [r for r in rules if r.category == "TCP Stack"]
        if len(tcp_issues) > 2:
            bottlenecks.append("TCP stack not optimized for high-bandwidth networks")
        
        wifi_issues = [r for r in rules if r.category == "Wi-Fi"]
        if len(wifi_issues) > 1:
            bottlenecks.append("Wi-Fi configuration issues affecting performance")
        
        return bottlenecks

    def crawl_config(self) -> SystemConfig:
        """Crawl comprehensive system configuration"""
        print(f"{self.color_manager.color(Colors.BOLD, 'Crawling system configuration...')}")
        
        # Use threading to parallelize I/O operations
        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = {
                executor.submit(self._crawl_sysctl_config): 'sysctl',
                executor.submit(self._crawl_network_manager_configs): 'nm_configs',
                executor.submit(self._crawl_dns_config): 'dns_config',
                executor.submit(self._crawl_firewall_rules): 'firewall_rules',
                executor.submit(self._crawl_driver_params): 'driver_params',
                executor.submit(self._crawl_interface_settings): 'interface_settings'
            }
            
            results = {}
            for future in as_completed(futures):
                key = futures[future]
                try:
                    results[key] = future.result()
                except Exception as e:
                    self.logger.error(f"Failed to crawl {key}: {e}")
                    results[key] = {}
        
        return SystemConfig(
            sysctl_params=results.get('sysctl', {}),
            network_manager_configs=results.get('nm_configs', {}),
            dns_config=results.get('dns_config', {}),
            firewall_rules=results.get('firewall_rules', []),
            driver_params=results.get('driver_params', {}),
            interface_settings=results.get('interface_settings', {})
        )

    def analyze_optimizations(self, system_config: SystemConfig, 
                            interfaces: List[NetworkInterface],
                            wifi_info: Optional[WifiInfo]) -> NetworkOptimization:
        """Analyze system configuration and generate optimization recommendations"""
        print(f"{self.color_manager.color(Colors.BOLD, 'Analyzing configuration for optimization opportunities...')}")
        
        # Create system context for rules
        context = SystemContext(
            system_config=system_config,
            interfaces=interfaces,
            wifi_info=wifi_info,
            logger=self.logger,
            _debugger=self
        )
        
        # Run all enabled rules through the registry
        all_rules = self.rule_registry.analyze_all(context)
        
        # Group rules by category
        rules_by_category = defaultdict(list)
        for rule in all_rules:
            rules_by_category[rule.category].append(rule)
        
        # Calculate performance metrics
        performance_score = self._calculate_performance_score(all_rules)
        bottlenecks = self._identify_bottlenecks(all_rules)
        
        return NetworkOptimization(
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
            hostname=os.uname().nodename,
            system_config=system_config,
            optimization_rules=all_rules,
            performance_score=performance_score,
            bottlenecks=bottlenecks,
            recommendations_by_category=dict(rules_by_category)
        )

    def apply_safe_optimizations(self, optimization: NetworkOptimization) -> Dict[str, bool]:
        """Apply safe optimizations automatically with enhanced safety features"""
        mode_text = "Simulating safe optimizations..." if self.dry_run else "Applying safe optimizations..."
        print(f"{self.color_manager.color(Colors.BOLD, mode_text)}")
        
        results = {}
        safe_rules = [r for r in optimization.optimization_rules if r.safe_to_auto_apply]
        
        if not safe_rules:
            info_msg = self.color_manager.color(Colors.BRIGHT_CYAN, "No safe optimizations to apply")
            print(f"  {info_msg}")
            return results
        
        action_word = "simulate" if self.dry_run else "apply"
        print(f"  Found {len(safe_rules)} safe optimization(s) to {action_word}")
        
        for i, rule in enumerate(safe_rules, 1):
            print(f"\n[{i}/{len(safe_rules)}] {rule.category}: {rule.name}")
            
            # Apply or simulate the optimization using the common method
            success, details = self._apply_fix(rule, dry_run=self.dry_run)
            results[rule.name] = success
            
            if success:
                status_icon = "→" if self.dry_run else "✓"
                status_color = Colors.BRIGHT_CYAN if self.dry_run else Colors.BRIGHT_GREEN
                status_msg = self.color_manager.color(status_color, f"{status_icon} {rule.name}")
                print(f"  {status_msg}")
                if details:
                    print(f"    {details}")
            else:
                error_msg = self.color_manager.color(Colors.BRIGHT_RED, f"✗ {rule.name}")
                print(f"  {error_msg}")
                if details:
                    print(f"    {details}")
        
        # Summary
        applied = sum(1 for success in results.values() if success)
        failed = len(results) - applied
        
        summary_title = "Simulation Results:" if self.dry_run else "Safe Optimization Results:"
        print(f"\n{self.color_manager.color(Colors.BOLD, summary_title)}")
        
        if applied > 0:
            action_past = "would be applied" if self.dry_run else "applied successfully"
            success_msg = self.color_manager.color(Colors.BRIGHT_GREEN, 
                                                 f"✓ {applied} optimization(s) {action_past}")
            print(f"  {success_msg}")
        
        if failed > 0:
            fail_action = "could not be simulated" if self.dry_run else "failed"
            error_msg = self.color_manager.color(Colors.BRIGHT_RED, 
                                               f"✗ {failed} optimization(s) {fail_action}")
            print(f"  {error_msg}")
            
            # List failed optimizations
            failed_rules = [name for name, success in results.items() if not success]
            for failed_rule in failed_rules:
                print(f"    • {failed_rule}")
        
        # Verify applied settings if not in dry-run mode
        if not self.dry_run and applied > 0:
            print(f"\n{self.color_manager.color(Colors.BOLD, 'Verifying Applied Settings:')}")
            applied_rules = [rule for rule in safe_rules if results[rule.name]]
            verification_results = self._verify_applied_settings(applied_rules)
            
            for rule_name, (verified, message) in verification_results.items():
                if verified:
                    verify_msg = self.color_manager.color(Colors.BRIGHT_GREEN, f"✓ {message}")
                    print(f"  {verify_msg}")
                else:
                    verify_msg = self.color_manager.color(Colors.BRIGHT_RED, f"✗ {message}")
                    print(f"  {verify_msg}")
        
        return results

    def generate_optimization_report(self, optimization: NetworkOptimization) -> str:
        """Generate comprehensive optimization report"""
        report = []
        
        report.append("# Network Performance Optimization Report")
        report.append(f"Generated: {optimization.timestamp}")
        report.append(f"Hostname: {optimization.hostname}")
        report.append(f"Performance Score: {optimization.performance_score:.1f}/100")
        report.append("")
        
        # Executive Summary
        report.append("## Executive Summary")
        if optimization.bottlenecks:
            report.append("### Identified Bottlenecks:")
            for bottleneck in optimization.bottlenecks:
                report.append(f"- {bottleneck}")
        else:
            report.append("No major bottlenecks identified.")
        report.append("")
        
        # Recommendations by Category
        report.append("## Optimization Recommendations")
        
        for category, rules in optimization.recommendations_by_category.items():
            report.append(f"### {category}")
            
            for rule in sorted(rules, key=lambda r: r.severity.value):
                severity_icon = "🔴" if rule.severity == Severity.CRITICAL else "⚠️" if rule.severity == Severity.WARNING else "ℹ️"
                report.append(f"#### {severity_icon} {rule.name}")
                report.append(f"**Current**: {rule.current_value}")
                report.append(f"**Recommended**: {rule.recommended_value}")
                report.append(f"**Rationale**: {rule.rationale}")
                report.append(f"**Impact**: {rule.impact}")
                report.append(f"**Fix**: `{rule.fix_command}`")
                report.append("")
        
        return "\n".join(report)

    def print_optimization_results(self, optimization: NetworkOptimization):
        """Print optimization analysis results"""
        separator = "=" * 60
        print(f"\n{self.color_manager.color(Colors.BOLD, separator)}")
        print(f"{self.color_manager.color(Colors.BOLD, 'Network Performance Analysis')}")
        print(f"{self.color_manager.color(Colors.BOLD, separator)}")
        
        # Performance Score
        score = optimization.performance_score
        score_color = Colors.BRIGHT_GREEN if score >= 80 else Colors.BRIGHT_YELLOW if score >= 60 else Colors.BRIGHT_RED
        score_text = self.color_manager.color(score_color, f"{score:.1f}/100")
        print(f"\n{self.color_manager.color(Colors.BOLD, 'Performance Score:')} {score_text}")
        
        # Bottlenecks
        if optimization.bottlenecks:
            print(f"\n{self.color_manager.color(Colors.BOLD, 'Primary Bottlenecks:')}")
            for bottleneck in optimization.bottlenecks:
                bottleneck_text = self.color_manager.color(Colors.BRIGHT_RED, f"• {bottleneck}")
                print(f"  {bottleneck_text}")
        
        # Recommendations by Category
        print(f"\n{self.color_manager.color(Colors.BOLD, 'Optimization Recommendations:')}")
        
        for category, rules in optimization.recommendations_by_category.items():
            category_text = self.color_manager.color(Colors.BOLD, f"{category.upper()}:")
            print(f"\n  {category_text}")
            
            for rule in sorted(rules, key=lambda r: r.severity.value):
                severity_display = self.color_manager.get_severity_display(rule.severity)
                print(f"    {severity_display}: {rule.name}")
                print(f"      Current: {rule.current_value}")
                recommended_text = self.color_manager.color(Colors.BRIGHT_CYAN, rule.recommended_value)
                print(f"      Recommended: {recommended_text}")
                print(f"      Impact: {rule.impact}")
                fix_text = self.color_manager.color(Colors.BLUE, rule.fix_command)
                print(f"      Fix: {fix_text}")
                if rule.safe_to_auto_apply:
                    safe_text = self.color_manager.color(Colors.BRIGHT_GREEN, "✓ Safe for auto-apply")
                    print(f"      {safe_text}")
                print()
        
        print(f"{self.color_manager.color(Colors.BOLD, separator)}")

    def _prompt_user_interactive(self, rule: OptimizationRule) -> str:
        """Prompt user for interactive optimization application"""
        print(f"\n{Colors.BOLD}Optimization Available:{Colors.RESET}")
        print(f"  Name: {rule.name}")
        print(f"  Category: {rule.category}")
        print(f"  Current: {rule.current_value}")
        print(f"  Recommended: {Colors.CYAN}{rule.recommended_value}{Colors.RESET}")
        print(f"  Impact: {rule.impact}")
        print(f"  Command: {Colors.BLUE}{rule.fix_command}{Colors.RESET}")
        
        while True:
            choice = input(f"\nApply this optimization? [y/N/a/s/q]: ").lower().strip()
            if choice in ['', 'n', 'no']:
                return 'skip'
            elif choice in ['y', 'yes']:
                return 'apply'
            elif choice in ['a', 'all']:
                return 'apply_all'
            elif choice in ['s', 'skip']:
                return 'skip_all'
            elif choice in ['q', 'quit']:
                return 'quit'
            else:
                print("Please enter: y(es), n(o), a(pply all), s(kip all), or q(uit)")

    def _measure_ping_latency(self, target: str = "8.8.8.8") -> float:
        """Measure ping latency to target"""
        try:
            code, stdout, _ = self._run_command(['ping', '-c', '3', '-W', '2', target])
            if code == 0:
                for line in stdout.split('\n'):
                    if 'avg' in line and 'min/avg/max' in line:
                        # Extract average from: min/avg/max/mdev = 12.345/23.456/34.567/1.234 ms
                        avg_match = re.search(r'= [0-9.]+/([0-9.]+)/', line)
                        if avg_match:
                            return float(avg_match.group(1))
        except Exception as e:
            self.logger.debug(f"Failed to measure ping latency: {e}")
        return 0.0

    def _get_tcp_retransmissions(self) -> int:
        """Get current TCP retransmission count"""
        try:
            with open('/proc/net/netstat', 'r') as f:
                content = f.read()
            
            lines = content.strip().split('\n')
            for i in range(0, len(lines), 2):
                if i + 1 < len(lines) and 'TcpExt:' in lines[i]:
                    headers = lines[i].split()
                    values = lines[i + 1].split()
                    
                    for j, header in enumerate(headers):
                        if header == 'RetransSegs' and j < len(values):
                            return int(values[j])
        except Exception as e:
            self.logger.debug(f"Failed to get TCP retransmissions: {e}")
        return 0

    def run_benchmark(self, test_method: str = "auto") -> BenchmarkResult:
        """Run comprehensive network benchmark"""
        print(f"{Colors.BOLD}Running network benchmark...{Colors.RESET}")
        
        # Speed test (check connectivity first)
        if test_method == "auto":
            speed_result = self.check_speed()
        else:
            if not self._check_internet_connectivity():
                print(f"{Colors.YELLOW}Warning: No internet connectivity detected - skipping speed test{Colors.RESET}")
                speed_result = None
            elif test_method == "iperf3":
                speed_result = self._test_speed_iperf3()
            else:
                speed_result = self._test_speed_speedtest()
        
        # Default values if speed test fails
        download_mbps = speed_result.download_mbps if speed_result else 0.0
        upload_mbps = speed_result.upload_mbps if speed_result else 0.0
        speed_ping = speed_result.ping_ms if speed_result else 0.0
        
        # Ping latency
        ping_ms = self._measure_ping_latency()
        if ping_ms == 0.0 and speed_ping > 0:
            ping_ms = speed_ping
        
        # TCP retransmissions
        tcp_retrans = self._get_tcp_retransmissions()
        
        # DNS latency
        dns_latency = self._check_dns_latency() or 0.0
        
        # Test method used
        method = speed_result.test_method if speed_result else "unavailable"
        
        return BenchmarkResult(
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
            download_mbps=download_mbps,
            upload_mbps=upload_mbps,
            ping_ms=ping_ms,
            tcp_retransmissions=tcp_retrans,
            dns_latency_ms=dns_latency,
            test_method=method
        )

    def save_benchmark(self, benchmark: BenchmarkResult, filename: str):
        """Save benchmark results to file"""
        try:
            with open(filename, 'w') as f:
                json.dump(asdict(benchmark), f, indent=2, default=str)
            print(f"Benchmark saved to {filename}")
        except Exception as e:
            self.logger.error(f"Failed to save benchmark: {e}")

    def load_benchmark(self, filename: str) -> Optional[BenchmarkResult]:
        """Load benchmark results from file"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
            return BenchmarkResult(**data)
        except Exception as e:
            self.logger.debug(f"Failed to load benchmark from {filename}: {e}")
            return None

    def compare_benchmarks(self, before: BenchmarkResult, after: BenchmarkResult) -> BenchmarkComparison:
        """Compare before and after benchmark results"""
        improvements = {}
        regressions = {}
        
        # Compare download speed
        if after.download_mbps > before.download_mbps * 1.05:  # 5% threshold
            improvement = ((after.download_mbps - before.download_mbps) / before.download_mbps) * 100
            improvements['download_speed'] = f"+{improvement:.1f}% ({before.download_mbps:.1f} → {after.download_mbps:.1f} Mbps)"
        elif after.download_mbps < before.download_mbps * 0.95:
            regression = ((before.download_mbps - after.download_mbps) / before.download_mbps) * 100
            regressions['download_speed'] = f"-{regression:.1f}% ({before.download_mbps:.1f} → {after.download_mbps:.1f} Mbps)"
        
        # Compare upload speed
        if after.upload_mbps > before.upload_mbps * 1.05:
            improvement = ((after.upload_mbps - before.upload_mbps) / before.upload_mbps) * 100
            improvements['upload_speed'] = f"+{improvement:.1f}% ({before.upload_mbps:.1f} → {after.upload_mbps:.1f} Mbps)"
        elif after.upload_mbps < before.upload_mbps * 0.95:
            regression = ((before.upload_mbps - after.upload_mbps) / before.upload_mbps) * 100
            regressions['upload_speed'] = f"-{regression:.1f}% ({before.upload_mbps:.1f} → {after.upload_mbps:.1f} Mbps)"
        
        # Compare ping latency (lower is better)
        if before.ping_ms > 0 and after.ping_ms > 0:
            if after.ping_ms < before.ping_ms * 0.95:
                improvement = ((before.ping_ms - after.ping_ms) / before.ping_ms) * 100
                improvements['ping_latency'] = f"-{improvement:.1f}% ({before.ping_ms:.1f} → {after.ping_ms:.1f} ms)"
            elif after.ping_ms > before.ping_ms * 1.05:
                regression = ((after.ping_ms - before.ping_ms) / before.ping_ms) * 100
                regressions['ping_latency'] = f"+{regression:.1f}% ({before.ping_ms:.1f} → {after.ping_ms:.1f} ms)"
        
        # Compare TCP retransmissions (lower is better)
        if before.tcp_retransmissions > 0:
            if after.tcp_retransmissions < before.tcp_retransmissions * 0.95:
                improvement = ((before.tcp_retransmissions - after.tcp_retransmissions) / before.tcp_retransmissions) * 100
                improvements['tcp_retransmissions'] = f"-{improvement:.1f}% ({before.tcp_retransmissions} → {after.tcp_retransmissions})"
            elif after.tcp_retransmissions > before.tcp_retransmissions * 1.05:
                regression = ((after.tcp_retransmissions - before.tcp_retransmissions) / before.tcp_retransmissions) * 100
                regressions['tcp_retransmissions'] = f"+{regression:.1f}% ({before.tcp_retransmissions} → {after.tcp_retransmissions})"
        
        # Compare DNS latency (lower is better)
        if before.dns_latency_ms > 0 and after.dns_latency_ms > 0:
            if after.dns_latency_ms < before.dns_latency_ms * 0.95:
                improvement = ((before.dns_latency_ms - after.dns_latency_ms) / before.dns_latency_ms) * 100
                improvements['dns_latency'] = f"-{improvement:.1f}% ({before.dns_latency_ms:.1f} → {after.dns_latency_ms:.1f} ms)"
            elif after.dns_latency_ms > before.dns_latency_ms * 1.05:
                regression = ((after.dns_latency_ms - before.dns_latency_ms) / before.dns_latency_ms) * 100
                regressions['dns_latency'] = f"+{regression:.1f}% ({before.dns_latency_ms:.1f} → {after.dns_latency_ms:.1f} ms)"
        
        # Calculate overall improvement score
        improvement_count = len(improvements)
        regression_count = len(regressions)
        if improvement_count + regression_count > 0:
            overall_improvement = (improvement_count - regression_count) / (improvement_count + regression_count) * 100
        else:
            overall_improvement = 0.0
        
        return BenchmarkComparison(
            before=before,
            after=after,
            improvements=improvements,
            regressions=regressions,
            overall_improvement=overall_improvement
        )

    def print_benchmark_comparison(self, comparison: BenchmarkComparison):
        """Print benchmark comparison results"""
        print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}Benchmark Comparison Results{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")
        
        print(f"\n{Colors.BOLD}Before Optimization:{Colors.RESET} {comparison.before.timestamp}")
        print(f"  Download: {comparison.before.download_mbps:.1f} Mbps")
        print(f"  Upload: {comparison.before.upload_mbps:.1f} Mbps")
        print(f"  Ping: {comparison.before.ping_ms:.1f} ms")
        print(f"  TCP Retransmissions: {comparison.before.tcp_retransmissions}")
        print(f"  DNS Latency: {comparison.before.dns_latency_ms:.1f} ms")
        
        print(f"\n{Colors.BOLD}After Optimization:{Colors.RESET} {comparison.after.timestamp}")
        print(f"  Download: {comparison.after.download_mbps:.1f} Mbps")
        print(f"  Upload: {comparison.after.upload_mbps:.1f} Mbps")
        print(f"  Ping: {comparison.after.ping_ms:.1f} ms")
        print(f"  TCP Retransmissions: {comparison.after.tcp_retransmissions}")
        print(f"  DNS Latency: {comparison.after.dns_latency_ms:.1f} ms")
        
        if comparison.improvements:
            print(f"\n{Colors.BOLD}{Colors.GREEN}Improvements:{Colors.RESET}")
            for metric, change in comparison.improvements.items():
                print(f"  • {metric.replace('_', ' ').title()}: {Colors.GREEN}{change}{Colors.RESET}")
        
        if comparison.regressions:
            print(f"\n{Colors.BOLD}{Colors.RED}Regressions:{Colors.RESET}")
            for metric, change in comparison.regressions.items():
                print(f"  • {metric.replace('_', ' ').title()}: {Colors.RED}{change}{Colors.RESET}")
        
        if not comparison.improvements and not comparison.regressions:
            print(f"\n{Colors.YELLOW}No significant changes detected (>5% threshold){Colors.RESET}")
        
        # Overall assessment
        if comparison.overall_improvement > 50:
            print(f"\n{Colors.BOLD}{Colors.GREEN}Overall Assessment: Significant Improvement{Colors.RESET}")
        elif comparison.overall_improvement > 0:
            print(f"\n{Colors.BOLD}{Colors.YELLOW}Overall Assessment: Moderate Improvement{Colors.RESET}")
        elif comparison.overall_improvement == 0:
            print(f"\n{Colors.BOLD}Overall Assessment: No Change{Colors.RESET}")
        else:
            print(f"\n{Colors.BOLD}{Colors.RED}Overall Assessment: Performance Regression{Colors.RESET}")
        
        print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")

    def generate_benchmark_report(self, comparison: BenchmarkComparison) -> str:
        """Generate markdown benchmark comparison report"""
        report = []
        
        report.append("# Network Performance Benchmark Report")
        report.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        report.append("## Before vs After Optimization")
        report.append("")
        report.append("| Metric | Before | After | Change |")
        report.append("|--------|--------|-------|--------|")
        
        # Download speed
        before_dl = comparison.before.download_mbps
        after_dl = comparison.after.download_mbps
        dl_change = f"+{((after_dl - before_dl) / before_dl * 100):.1f}%" if before_dl > 0 else "N/A"
        report.append(f"| Download Speed | {before_dl:.1f} Mbps | {after_dl:.1f} Mbps | {dl_change} |")
        
        # Upload speed
        before_ul = comparison.before.upload_mbps
        after_ul = comparison.after.upload_mbps
        ul_change = f"+{((after_ul - before_ul) / before_ul * 100):.1f}%" if before_ul > 0 else "N/A"
        report.append(f"| Upload Speed | {before_ul:.1f} Mbps | {after_ul:.1f} Mbps | {ul_change} |")
        
        # Ping latency
        before_ping = comparison.before.ping_ms
        after_ping = comparison.after.ping_ms
        ping_change = f"{((after_ping - before_ping) / before_ping * 100):+.1f}%" if before_ping > 0 else "N/A"
        report.append(f"| Ping Latency | {before_ping:.1f} ms | {after_ping:.1f} ms | {ping_change} |")
        
        # TCP retransmissions
        before_tcp = comparison.before.tcp_retransmissions
        after_tcp = comparison.after.tcp_retransmissions
        tcp_change = f"{((after_tcp - before_tcp) / before_tcp * 100):+.1f}%" if before_tcp > 0 else "N/A"
        report.append(f"| TCP Retransmissions | {before_tcp} | {after_tcp} | {tcp_change} |")
        
        # DNS latency
        before_dns = comparison.before.dns_latency_ms
        after_dns = comparison.after.dns_latency_ms
        dns_change = f"{((after_dns - before_dns) / before_dns * 100):+.1f}%" if before_dns > 0 else "N/A"
        report.append(f"| DNS Latency | {before_dns:.1f} ms | {after_dns:.1f} ms | {dns_change} |")
        
        report.append("")
        
        if comparison.improvements:
            report.append("## ✅ Improvements")
            for metric, change in comparison.improvements.items():
                report.append(f"- **{metric.replace('_', ' ').title()}**: {change}")
            report.append("")
        
        if comparison.regressions:
            report.append("## ⚠️ Regressions")
            for metric, change in comparison.regressions.items():
                report.append(f"- **{metric.replace('_', ' ').title()}**: {change}")
            report.append("")
        
        return "\n".join(report)

    def apply_optimizations_interactive(self, optimization: NetworkOptimization) -> Dict[str, bool]:
        """Apply optimizations with interactive prompts"""
        mode_title = "Interactive Optimization Mode (Dry Run)" if self.dry_run else "Interactive Optimization Mode"
        print(f"{self.color_manager.color(Colors.BOLD, mode_title)}")
        
        # Check if we're running as root for system optimizations
        is_root = self._is_root()
        system_optimizations = any('sysctl.conf' in rule.fix_command for rule in optimization.optimization_rules if rule.safe_to_auto_apply)
        
        if system_optimizations and not is_root and not self.dry_run:
            warning_text = self.color_manager.color(Colors.YELLOW, "Note: System-level optimizations require root privileges.")
            command_text = self.color_manager.color(Colors.CYAN, "sudo python3 network_debug.py --interactive")
            print(f"{warning_text}")
            print(f"For full functionality, run: {command_text}")
            print(f"Continuing with available optimizations...\n")
        
        if self.dry_run:
            print("Available actions:")
            print("  y/yes   - Simulate this optimization")
            print("  n/no    - Skip this optimization (default)")
            print("  a/all   - Simulate all remaining optimizations")
            print("  s/skip  - Skip all remaining optimizations")
            print("  q/quit  - Exit interactive mode")
        else:
            print("Available actions:")
            print("  y/yes   - Apply this optimization")
            print("  n/no    - Skip this optimization (default)")
            print("  a/all   - Apply all remaining optimizations")
            print("  s/skip  - Skip all remaining optimizations")
            print("  q/quit  - Exit interactive mode")
        
        results = {}
        safe_rules = [r for r in optimization.optimization_rules if r.safe_to_auto_apply]
        apply_all = False
        skip_all = False
        
        for i, rule in enumerate(safe_rules):
            if skip_all:
                results[rule.name] = False
                continue
            
            if not apply_all:
                counter_text = self.color_manager.color(Colors.BOLD, f"[{i+1}/{len(safe_rules)}]")
                print(f"\n{counter_text}")
                choice = self._prompt_user_interactive(rule)
                
                if choice == 'quit':
                    print("Exiting interactive mode...")
                    break
                elif choice == 'skip_all':
                    skip_all = True
                    results[rule.name] = False
                    continue
                elif choice == 'apply_all':
                    apply_all = True
                elif choice == 'skip':
                    results[rule.name] = False
                    continue
            
            if apply_all or choice == 'apply':
                # Apply or simulate the optimization using the common method
                success, details = self._apply_fix(rule, dry_run=self.dry_run)
                results[rule.name] = success
                
                if success:
                    status_icon = "→" if self.dry_run else "✓"
                    status_color = Colors.BRIGHT_CYAN if self.dry_run else Colors.BRIGHT_GREEN
                    status_msg = self.color_manager.color(status_color, f"{status_icon} {rule.name}")
                    print(f"  {status_msg}")
                    if details:
                        print(f"    {details}")
                else:
                    error_msg = self.color_manager.color(Colors.BRIGHT_RED, f"✗ {rule.name}")
                    print(f"  {error_msg}")
                    if details:
                        print(f"    {details}")
                    
                    if not self.dry_run and not is_root and ('sysctl.conf' in rule.fix_command or 'modprobe.d' in rule.fix_command):
                        hint_msg = self.color_manager.color(Colors.YELLOW, 
                                                          "Hint: Try running with sudo for system-level changes")
                        print(f"    {hint_msg}")
        
        # Verify applied settings if not in dry-run mode
        if not self.dry_run:
            applied_rules = [rule for rule in safe_rules if results.get(rule.name, False)]
            if applied_rules:
                print(f"\n{self.color_manager.color(Colors.BOLD, 'Verifying Applied Settings:')}")
                verification_results = self._verify_applied_settings(applied_rules)
                
                for rule_name, (verified, message) in verification_results.items():
                    if verified:
                        verify_msg = self.color_manager.color(Colors.BRIGHT_GREEN, f"✓ {message}")
                        print(f"  {verify_msg}")
                    else:
                        verify_msg = self.color_manager.color(Colors.BRIGHT_RED, f"✗ {message}")
                        print(f"  {verify_msg}")
        
        return results



    def check_dependencies(self) -> Dict[str, bool]:
        """Check availability of optional dependencies"""
        dependencies = {
            'iperf3': False,
            'speedtest-cli': False,
            'iw': False,
            'iwconfig': False,
            'ethtool': False,
            'dig': False,
            'nslookup': False,
            'nmcli': False,
            'rfkill': False,
            'ping': False
        }
        
        for tool in dependencies.keys():
            dependencies[tool] = shutil.which(tool) is not None
        
        return dependencies
    
    def _check_internet_connectivity(self) -> bool:
        """Check if internet connectivity is available"""
        try:
            # Try to reach Google DNS
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex(('8.8.8.8', 53))
            sock.close()
            
            if result == 0:
                return True
            
            # Fallback: try ping
            code, _, _ = self._run_command(['ping', '-c', '1', '-W', '3', '8.8.8.8'])
            return code == 0
            
        except Exception:
            return False
    
    def _is_systemd_active(self) -> bool:
        """Check if systemd is the active init system"""
        try:
            # Method 1: Check /proc/1/comm (most reliable)
            try:
                with open('/proc/1/comm', 'r') as f:
                    init_name = f.read().strip()
                    if init_name == 'systemd':
                        self.logger.debug("systemd detected via /proc/1/comm")
                        return True
            except (FileNotFoundError, IOError):
                pass
            
            # Method 2: Check if systemd is running via pidof
            if shutil.which('pidof'):
                code, stdout, _ = self._run_command(['pidof', 'systemd'])
                if code == 0 and stdout.strip():
                    self.logger.debug("systemd detected via pidof")
                    return True
            
            # Method 3: Check for systemd directory
            if os.path.exists('/run/systemd/system'):
                self.logger.debug("systemd detected via /run/systemd/system")
                return True
            
            # Method 4: Try systemctl (may work even without systemd as PID 1)
            if shutil.which('systemctl'):
                code, _, _ = self._run_command(['systemctl', 'is-system-running'], timeout=5)
                if code in [0, 1]:  # 0 = running, 1 = degraded but still systemd
                    self.logger.debug("systemd detected via systemctl is-system-running")
                    return True
            
            self.logger.debug("systemd not detected")
            return False
            
        except Exception as e:
            self.logger.debug(f"Error checking systemd status: {e}")
            return False
    
    def _is_root(self) -> bool:
        """Check if running as root"""
        return os.geteuid() == 0
    
    def _check_root_required(self, operation: str) -> bool:
        """Check if root is required for operation and warn if not root"""
        if not self._is_root():
            warning_text = self.color_manager.color(Colors.YELLOW, f"Warning: {operation} requires root privileges for system-level changes")
            command_text = self.color_manager.color(Colors.CYAN, "sudo python3 network_debug.py")
            print(warning_text)
            print(f"Run with sudo for full functionality: {command_text}")
            return False
        return True
    
    def _create_timestamped_backup(self, file_path: str) -> Optional[str]:
        """Create a timestamped backup of a file"""
        try:
            if not os.path.exists(file_path):
                self.logger.debug(f"File {file_path} does not exist, no backup needed")
                return None
            
            # Generate timestamp
            timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
            backup_path = f"{file_path}.bak.{timestamp}"
            
            # Create backup
            shutil.copy2(file_path, backup_path)
            self.logger.info(f"Created backup: {backup_path}")
            return backup_path
            
        except Exception as e:
            self.logger.error(f"Failed to create backup of {file_path}: {e}")
            return None
    
    def _safe_write_file(self, file_path: str, content: str, backup: bool = True) -> bool:
        """Safely write content to file with atomic operation and optional backup"""
        try:
            # Create backup if requested
            if backup:
                backup_path = self._create_timestamped_backup(file_path)
                if backup_path is None and os.path.exists(file_path):
                    self.logger.warning(f"Could not create backup for {file_path}, proceeding anyway")
            
            # Write to temporary file first
            dir_path = os.path.dirname(file_path)
            with tempfile.NamedTemporaryFile(mode='w', dir=dir_path, delete=False, 
                                           prefix=f".{os.path.basename(file_path)}.tmp") as tmp_file:
                tmp_file.write(content)
                tmp_file.flush()
                os.fsync(tmp_file.fileno())  # Force write to disk
                tmp_path = tmp_file.name
            
            # Atomic rename
            os.rename(tmp_path, file_path)
            self.logger.debug(f"Successfully wrote {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to write {file_path}: {e}")
            # Clean up temp file if it exists
            try:
                if 'tmp_path' in locals():
                    os.unlink(tmp_path)
            except:
                pass
            return False
    
    def _read_sysctl_config_file(self, file_path: str) -> Dict[str, str]:
        """Read existing sysctl configuration from file"""
        config = {}
        try:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            key, value = line.split('=', 1)
                            config[key.strip()] = value.strip()
        except Exception as e:
            self.logger.error(f"Failed to read {file_path}: {e}")
        return config
    
    def _deduplicate_sysctl_params(self, existing_config: Dict[str, str], 
                                  new_params: Dict[str, str]) -> Dict[str, str]:
        """Remove parameters that already have the correct value"""
        filtered_params = {}
        for param, value in new_params.items():
            existing_value = existing_config.get(param)
            if existing_value != value:
                filtered_params[param] = value
                if existing_value:
                    self.logger.debug(f"Parameter {param} will be updated: {existing_value} -> {value}")
                else:
                    self.logger.debug(f"Parameter {param} will be added: {value}")
            else:
                self.logger.debug(f"Parameter {param} already has correct value: {value}")
        return filtered_params
    
    def _verify_sysctl_settings(self, expected_params: Dict[str, str]) -> Dict[str, bool]:
        """Verify that sysctl settings match expected values"""
        verification_results = {}
        
        for param, expected_value in expected_params.items():
            try:
                # Get current value from system
                code, stdout, stderr = self._run_command(['sysctl', '-n', param])
                if code == 0:
                    current_value = stdout.strip()
                    matches = current_value == expected_value
                    verification_results[param] = matches
                    
                    if matches:
                        success_msg = self.color_manager.color(Colors.BRIGHT_GREEN, 
                                                             f"✓ {param} successfully set to {expected_value}")
                        print(f"  {success_msg}")
                    else:
                        error_msg = self.color_manager.color(Colors.BRIGHT_RED, 
                                                           f"✗ {param} verification failed: expected {expected_value}, got {current_value}")
                        print(f"  {error_msg}")
                        self.logger.warning(f"Sysctl verification failed for {param}: expected {expected_value}, got {current_value}")
                else:
                    verification_results[param] = False
                    error_msg = self.color_manager.color(Colors.BRIGHT_RED, 
                                                       f"✗ {param} verification failed: {stderr.strip()}")
                    print(f"  {error_msg}")
                    self.logger.error(f"Failed to read sysctl parameter {param}: {stderr}")
                    
            except Exception as e:
                verification_results[param] = False
                error_msg = self.color_manager.color(Colors.BRIGHT_RED, 
                                                   f"✗ {param} verification error: {e}")
                print(f"  {error_msg}")
                self.logger.error(f"Exception while verifying {param}: {e}")
        
        return verification_results
    
    def _safe_update_sysctl_config(self, sysctl_file: str, new_params: Dict[str, str]) -> bool:
        """Safely update sysctl configuration with deduplication and verification"""
        backup_path = None
        try:
            # Read existing configuration
            existing_config = self._read_sysctl_config_file(sysctl_file)
            
            # Deduplicate parameters
            params_to_add = self._deduplicate_sysctl_params(existing_config, new_params)
            
            if not params_to_add:
                info_msg = self.color_manager.color(Colors.BRIGHT_CYAN, 
                                                  "All sysctl parameters already have correct values")
                print(f"  {info_msg}")
                return True
            
            # Read current file content
            current_content = ""
            if os.path.exists(sysctl_file):
                with open(sysctl_file, 'r') as f:
                    current_content = f.read()
            
            # Prepare new content
            new_lines = []
            if current_content and not current_content.endswith('\n'):
                new_lines.append('')  # Add newline if file doesn't end with one
            
            new_lines.append(f"# Network optimization settings added by network_debug.py on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            for param, value in params_to_add.items():
                new_lines.append(f"{param} = {value}")
            new_lines.append('')  # End with newline
            
            updated_content = current_content + '\n'.join(new_lines)
            
            # Write safely with backup
            backup_path = self._create_timestamped_backup(sysctl_file)
            if self._safe_write_file(sysctl_file, updated_content, backup=False):  # Already have backup
                success_msg = self.color_manager.color(Colors.BRIGHT_GREEN, 
                                                     f"✓ Updated {sysctl_file} with {len(params_to_add)} parameters")
                print(f"  {success_msg}")
                
                # Apply sysctl changes
                print(f"  Applying sysctl changes...")
                code, stdout, stderr = self._run_command(['sysctl', '-p', sysctl_file])
                if code == 0:
                    success_msg = self.color_manager.color(Colors.BRIGHT_GREEN, 
                                                         "✓ sysctl -p completed successfully")
                    print(f"  {success_msg}")
                    
                    # Verify settings
                    print(f"  Verifying applied settings...")
                    verification_results = self._verify_sysctl_settings(params_to_add)
                    
                    failed_verifications = [param for param, success in verification_results.items() if not success]
                    if failed_verifications:
                        warning_msg = self.color_manager.color(Colors.BRIGHT_YELLOW, 
                                                             f"⚠ {len(failed_verifications)} parameters failed verification")
                        print(f"  {warning_msg}")
                        
                        # Attempt rollback if backup exists
                        if backup_path and os.path.exists(backup_path):
                            print(f"  Attempting rollback from {backup_path}...")
                            try:
                                shutil.copy2(backup_path, sysctl_file)
                                rollback_msg = self.color_manager.color(Colors.BRIGHT_YELLOW, 
                                                                       "✓ Configuration rolled back successfully")
                                print(f"  {rollback_msg}")
                            except Exception as e:
                                rollback_error = self.color_manager.color(Colors.BRIGHT_RED, 
                                                                        f"✗ Rollback failed: {e}")
                                print(f"  {rollback_error}")
                        return False
                    else:
                        success_msg = self.color_manager.color(Colors.BRIGHT_GREEN, 
                                                             "✓ All parameters verified successfully")
                        print(f"  {success_msg}")
                        return True
                else:
                    error_msg = self.color_manager.color(Colors.BRIGHT_RED, 
                                                       f"✗ sysctl -p failed: {stderr.strip()}")
                    print(f"  {error_msg}")
                    
                    # Attempt rollback if backup exists
                    if backup_path and os.path.exists(backup_path):
                        print(f"  Attempting rollback from {backup_path}...")
                        try:
                            shutil.copy2(backup_path, sysctl_file)
                            rollback_msg = self.color_manager.color(Colors.BRIGHT_YELLOW, 
                                                                   "✓ Configuration rolled back successfully")
                            print(f"  {rollback_msg}")
                        except Exception as e:
                            rollback_error = self.color_manager.color(Colors.BRIGHT_RED, 
                                                                    f"✗ Rollback failed: {e}")
                            print(f"  {rollback_error}")
                    return False
            else:
                error_msg = self.color_manager.color(Colors.BRIGHT_RED, 
                                                   f"✗ Failed to write {sysctl_file}")
                print(f"  {error_msg}")
                return False
                
        except Exception as e:
            error_msg = self.color_manager.color(Colors.BRIGHT_RED, 
                                               f"✗ Exception updating sysctl config: {e}")
            print(f"  {error_msg}")
            self.logger.error(f"Exception in _safe_update_sysctl_config: {e}")
            return False
    
    def _safe_update_modprobe_config(self, module_name: str, options: str) -> bool:
        """Safely update modprobe configuration for a module"""
        try:
            modprobe_dir = Path('/etc/modprobe.d')
            config_file = modprobe_dir / f"{module_name}.conf"
            
            # Check if configuration already exists
            existing_options = ""
            if config_file.exists():
                with open(config_file, 'r') as f:
                    content = f.read()
                    for line in content.split('\n'):
                        if line.strip().startswith(f'options {module_name}'):
                            existing_options = line.strip()
                            break
            
            new_config_line = f"options {module_name} {options}"
            
            # Check if we need to update
            if existing_options == new_config_line:
                info_msg = self.color_manager.color(Colors.BRIGHT_CYAN, 
                                                  f"Module {module_name} already has correct configuration")
                print(f"  {info_msg}")
                return True
            
            # Prepare new content
            if existing_options:
                # Replace existing line
                with open(config_file, 'r') as f:
                    content = f.read()
                new_content = content.replace(existing_options, new_config_line)
            else:
                # Add new configuration
                header = f"# Module configuration for {module_name} added by network_debug.py on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                new_content = header + new_config_line + "\n"
            
            # Write safely with backup
            if self._safe_write_file(str(config_file), new_content, backup=True):
                success_msg = self.color_manager.color(Colors.BRIGHT_GREEN, 
                                                     f"✓ Updated {config_file}")
                print(f"  {success_msg}")
                
                # Note about module reload requirement
                info_msg = self.color_manager.color(Colors.BRIGHT_YELLOW, 
                                                  f"ℹ Module {module_name} configuration updated (requires reload/reboot to take effect)")
                print(f"  {info_msg}")
                return True
            else:
                error_msg = self.color_manager.color(Colors.BRIGHT_RED, 
                                                   f"✗ Failed to write {config_file}")
                print(f"  {error_msg}")
                return False
                
        except Exception as e:
            error_msg = self.color_manager.color(Colors.BRIGHT_RED, 
                                               f"✗ Exception updating modprobe config: {e}")
            print(f"  {error_msg}")
            self.logger.error(f"Exception in _safe_update_modprobe_config: {e}")
            return False
    
    def _apply_fix(self, rule: OptimizationRule, dry_run: bool = False) -> Tuple[bool, str]:
        """Common method to apply or simulate optimization fixes
        
        Returns:
            Tuple[bool, str]: (success, details)
        """
        try:
            if dry_run:
                return self._simulate_fix(rule)
            else:
                return self._execute_fix(rule)
        except Exception as e:
            error_msg = f"Exception applying {rule.name}: {e}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def _simulate_fix(self, rule: OptimizationRule) -> Tuple[bool, str]:
        """Simulate what would be done for a fix without actually doing it"""
        details = []
        
        if rule.fix_command.startswith('echo') and 'sysctl.conf' in rule.fix_command:
            # Simulate sysctl configuration update
            parts = rule.fix_command.split(' >> ')
            if len(parts) == 2:
                content = parts[0].replace('echo ', '').strip("'\"")
                file_path = parts[1].split(' &&')[0].strip()
                
                if '=' in content:
                    param, value = content.split('=', 1)
                    param = param.strip()
                    value = value.strip()
                    
                    details.append(f"Would append '{param} = {value}' to {file_path}")
                    details.append(f"Would run 'sysctl -p {file_path}'")
                    details.append(f"Would verify {param} is set to {value}")
                    
                    return True, '\n    '.join(details)
                    
        elif rule.fix_command.startswith('echo') and 'modprobe.d' in rule.fix_command:
            # Simulate modprobe configuration update
            parts = rule.fix_command.split(' >> ')
            if len(parts) == 2:
                content = parts[0].replace('echo ', '').strip("'\"")
                file_path = parts[1].split(' &&')[0].strip()
                
                details.append(f"Would write '{content}' to {file_path}")
                details.append(f"Would create backup of {file_path}")
                
                return True, '\n    '.join(details)
                
        else:
            # Simulate direct command execution
            details.append(f"Would execute: {rule.fix_command}")
            return True, '\n    '.join(details)
        
        return False, "Could not simulate this fix"
    
    def _execute_fix(self, rule: OptimizationRule) -> Tuple[bool, str]:
        """Actually execute the fix"""
        details = []
        
        if rule.fix_command.startswith('echo') and 'sysctl.conf' in rule.fix_command:
            # Handle sysctl configuration updates
            parts = rule.fix_command.split(' >> ')
            if len(parts) == 2:
                content = parts[0].replace('echo ', '').strip("'\"")
                file_path = parts[1].split(' &&')[0].strip()
                
                if '=' in content:
                    param, value = content.split('=', 1)
                    param = param.strip()
                    value = value.strip()
                    
                    success = self._safe_update_sysctl_config(file_path, {param: value})
                    if success:
                        details.append(f"Successfully updated {file_path}")
                        details.append(f"Applied sysctl changes")
                        details.append(f"Verified {param} = {value}")
                        return True, '\n    '.join(details)
                    else:
                        details.append(f"Failed to update {file_path}")
                        return False, '\n    '.join(details)
                        
        elif rule.fix_command.startswith('echo') and 'modprobe.d' in rule.fix_command:
            # Handle modprobe configuration updates
            parts = rule.fix_command.split(' >> ')
            if len(parts) == 2:
                content = parts[0].replace('echo ', '').strip("'\"")
                
                if content.startswith('options '):
                    config_parts = content.split(' ', 2)
                    if len(config_parts) >= 3:
                        module_name = config_parts[1]
                        options = config_parts[2]
                        success = self._safe_update_modprobe_config(module_name, options)
                        if success:
                            details.append(f"Successfully updated modprobe config for {module_name}")
                            return True, '\n    '.join(details)
                        else:
                            details.append(f"Failed to update modprobe config for {module_name}")
                            return False, '\n    '.join(details)
                            
        else:
            # Execute command directly
            code, stdout, stderr = self._run_command(rule.fix_command.split())
            if code == 0:
                details.append(f"Successfully executed: {rule.fix_command}")
                if stdout.strip():
                    details.append(f"Output: {stdout.strip()}")
                return True, '\n    '.join(details)
            else:
                details.append(f"Failed to execute: {rule.fix_command}")
                if stderr.strip():
                    details.append(f"Error: {stderr.strip()}")
                return False, '\n    '.join(details)
        
        return False, "Unsupported fix command"
    
    def _verify_applied_settings(self, rules: List[OptimizationRule]) -> Dict[str, Tuple[bool, str]]:
        """Verify that applied settings are actually in effect"""
        verification_results = {}
        
        for rule in rules:
            if rule.fix_command.startswith('echo') and 'sysctl.conf' in rule.fix_command:
                # Verify sysctl parameters
                parts = rule.fix_command.split(' >> ')
                if len(parts) == 2:
                    content = parts[0].replace('echo ', '').strip("'\"")
                    if '=' in content:
                        param, expected_value = content.split('=', 1)
                        param = param.strip()
                        expected_value = expected_value.strip()
                        
                        # Get current value
                        code, stdout, stderr = self._run_command(['sysctl', '-n', param])
                        if code == 0:
                            current_value = stdout.strip()
                            if current_value == expected_value:
                                verification_results[rule.name] = (True, f"{param} set correctly")
                            else:
                                verification_results[rule.name] = (False, 
                                    f"{param} still incorrect (expected {expected_value}, found {current_value})")
                        else:
                            verification_results[rule.name] = (False, 
                                f"{param} verification failed: {stderr.strip()}")
            else:
                # For non-sysctl commands, we can't easily verify, so assume success if applied
                verification_results[rule.name] = (True, f"{rule.name} applied")
        
        return verification_results

    def print_dependency_status(self, dependencies: Dict[str, bool]):
        """Print dependency availability status with installation guidance"""
        print(f"\n{self.color_manager.color(Colors.BOLD, 'Dependency Status:')}")
        
        required = ['ping', 'ip']  # Essential tools
        recommended = ['iperf3', 'speedtest-cli', 'iw', 'ethtool', 'nmcli']
        optional = ['dig', 'nslookup', 'iwconfig', 'rfkill']
        
        missing_by_category = {}
        distribution = self._detect_distribution()
        
        for category, tools in [('Required', required), ('Recommended', recommended), ('Optional', optional)]:
            category_text = self.color_manager.color(Colors.BOLD, f"{category}:")
            print(f"\n  {category_text}")
            missing_tools = []
            
            for tool in tools:
                if tool in dependencies:
                    status = dependencies[tool]
                    color = Colors.BRIGHT_GREEN if status else Colors.BRIGHT_RED
                    symbol = "✓" if status else "✗"
                    status_text = self.color_manager.color(color, f"{symbol} {tool}")
                    print(f"    {status_text}")
                    
                    if not status:
                        missing_tools.append(tool)
                else:
                    unknown_text = self.color_manager.color(Colors.YELLOW, f"? {tool} (not checked)")
                    print(f"    {unknown_text}")
            
            if missing_tools:
                missing_by_category[category] = missing_tools
        
        # Enhanced installation guidance
        if missing_by_category:
            # Package mapping for different distributions
            package_mapping = {
                'Ubuntu': {'speedtest-cli': 'speedtest-cli', 'iperf3': 'iperf3', 'iw': 'iw', 'ethtool': 'ethtool', 'nmcli': 'network-manager', 'dig': 'dnsutils', 'nslookup': 'dnsutils', 'iwconfig': 'wireless-tools', 'rfkill': 'rfkill'},
                'Fedora': {'speedtest-cli': 'speedtest-cli', 'iperf3': 'iperf3', 'iw': 'iw', 'ethtool': 'ethtool', 'nmcli': 'NetworkManager', 'dig': 'bind-utils', 'nslookup': 'bind-utils', 'iwconfig': 'wireless-tools', 'rfkill': 'rfkill'},
                'Arch': {'speedtest-cli': 'speedtest-cli', 'iperf3': 'iperf3', 'iw': 'iw', 'ethtool': 'ethtool', 'nmcli': 'networkmanager', 'dig': 'bind', 'nslookup': 'bind', 'iwconfig': 'wireless_tools', 'rfkill': 'rfkill'},
                'Alpine': {'speedtest-cli': 'speedtest-cli', 'iperf3': 'iperf3', 'iw': 'iw', 'ethtool': 'ethtool', 'nmcli': 'networkmanager', 'dig': 'bind-tools', 'nslookup': 'bind-tools', 'iwconfig': 'wireless-tools', 'rfkill': 'rfkill'}
            }
            
            dist_mapping = package_mapping.get(distribution, package_mapping['Ubuntu'])
            
            for category, tools in missing_by_category.items():
                if category == 'Required':
                    severity_color = Colors.BRIGHT_RED
                    severity_text = "CRITICAL"
                elif category == 'Recommended':
                    severity_color = Colors.BRIGHT_YELLOW
                    severity_text = "WARNING"
                else:
                    severity_color = Colors.BRIGHT_CYAN
                    severity_text = "INFO"
                
                warning_text = self.color_manager.color(severity_color, f"{severity_text}: Missing {category.lower()} tools may limit functionality:")
                print(f"\n{warning_text}")
                for tool in tools:
                    print(f"  • {tool}")
                
                # Distribution-specific installation commands
                packages = [dist_mapping.get(tool, tool) for tool in tools]
                unique_packages = sorted(set(pkg for pkg in packages if pkg is not None))
                
                if distribution == 'Ubuntu':
                    print(f"\nInstall with: sudo apt update && sudo apt install {' '.join(unique_packages)}")
                elif distribution == 'Fedora':
                    print(f"\nInstall with: sudo dnf install {' '.join(unique_packages)}")
                elif distribution == 'Arch':
                    print(f"\nInstall with: sudo pacman -S {' '.join(unique_packages)}")
                elif distribution == 'Alpine':
                    print(f"\nInstall with: sudo apk add {' '.join(unique_packages)}")
                else:
                    print(f"\nInstall packages: {' '.join(unique_packages)}")
                    print(f"  Ubuntu/Debian: sudo apt install {' '.join(unique_packages)}")
                    print(f"  Fedora: sudo dnf install {' '.join(unique_packages)}")
                    print(f"  Arch: sudo pacman -S {' '.join(unique_packages)}")
                    print(f"  Alpine: sudo apk add {' '.join(unique_packages)}")

        print(f"{self.color_manager.color(Colors.BOLD, '=' * 60)}")
    
    def check_speed(self) -> Optional[SpeedTestResult]:
        """Perform network speed test"""
        print(f"{self.color_manager.color(Colors.BOLD, 'Testing network speed...')}")
        
        # Check internet connectivity first
        if not self._check_internet_connectivity():
            warning_text = self.color_manager.color(Colors.YELLOW, "Warning: No internet connectivity detected - skipping speed test")
            print(warning_text)
            self._add_finding(
                'speed_test',
                Severity.WARNING,
                "No internet connectivity detected",
                "Check network configuration and DNS settings"
            )
            return None
        
        # Try iperf3 first
        result = self._test_speed_iperf3()
        if result:
            return result
        
        # Fallback to speedtest-cli
        result = self._test_speed_speedtest()
        if result:
            return result
        
        self._add_finding(
            'speed_test',
            Severity.WARNING,
            "Could not perform speed test",
            "Install iperf3 or speedtest-cli for speed testing"
        )
        
        return None
    
    def diagnose(self) -> NetworkDiagnostic:
        """Perform comprehensive network diagnosis"""
        print(f"{self.color_manager.color(Colors.BOLD, 'Performing network diagnosis...')}")
        
        # Gather system information
        distribution = self._detect_distribution()
        kernel_version = self._get_kernel_version()
        interfaces = self._get_network_interfaces()
        wifi_info = self._get_wifi_info()
        
        # Perform speed test
        speed_test = self.check_speed()
        
        # Run diagnostic checks
        self._check_driver_issues(interfaces)
        self._check_rfkill_status()
        self._check_channel_congestion()
        
        if wifi_info:
            self._check_band_usage(wifi_info)
        
        # Check DNS and TCP performance with context awareness
        dns_latency = self._check_dns_latency()
        if dns_latency:
            if dns_latency > 100:
                self._add_finding(
                    'dns_latency',
                    Severity.WARNING,
                    f"High DNS latency: {dns_latency:.1f}ms",
                    "Consider using faster DNS servers (8.8.8.8, 1.1.1.1)"
                )
            else:
                self.logger.debug(f"DNS latency acceptable: {dns_latency:.1f}ms")
        
        tcp_stats = self._check_tcp_retransmissions()
        if tcp_stats.get('retransmissions', 0) > 1000:
            self._add_finding(
                'tcp_retransmissions',
                Severity.WARNING,
                f"High TCP retransmissions: {tcp_stats['retransmissions']}",
                "Network congestion or packet loss detected"
            )
        
        # Suggest optimizations
        self._suggest_tcp_tuning()
        
        # Create diagnostic result
        diagnostic = NetworkDiagnostic(
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
            hostname=os.uname().nodename,
            distribution=distribution,
            kernel_version=kernel_version,
            interfaces=interfaces,
            wifi_info=wifi_info,
            speed_test=speed_test,
            findings=self.findings,
            system_info={
                'dns_latency_ms': str(dns_latency) if dns_latency else 'N/A',
                **{k: str(v) for k, v in tcp_stats.items()}
            }
        )
        
        return diagnostic
    
    def tune(self):
        """Apply automatic performance tuning"""
        mode_text = "Simulating performance tuning..." if self.dry_run else "Applying performance tuning..."
        print(f"{self.color_manager.color(Colors.BOLD, mode_text)}")
        
        # Check root privileges (skip in dry-run mode)
        if not self.dry_run and not self._check_root_required("Performance tuning"):
            warning_text = self.color_manager.color(Colors.YELLOW, "Skipping system-level tuning (requires root)")
            print(warning_text)
            return
        
        # Disable power management on Wi-Fi interfaces
        wifi_iface = self._get_wifi_interface()
        if wifi_iface and shutil.which('iw'):
            if self.dry_run:
                simulate_text = self.color_manager.color(Colors.BRIGHT_CYAN, f"→ Would disable power saving on {wifi_iface}")
                print(simulate_text)
                print(f"    Would execute: iw {wifi_iface} set power_save off")
            else:
                code, _, _ = self._run_command(['iw', wifi_iface, 'set', 'power_save', 'off'])
                if code == 0:
                    success_text = self.color_manager.color(Colors.BRIGHT_GREEN, f"✓ Disabled power saving on {wifi_iface}")
                    print(success_text)
                else:
                    error_text = self.color_manager.color(Colors.BRIGHT_RED, f"✗ Failed to disable power saving on {wifi_iface}")
                    print(error_text)
        elif wifi_iface:
            if self.dry_run:
                warning_text = self.color_manager.color(Colors.YELLOW, "⚠ iw not available, would skip Wi-Fi power management")
            else:
                warning_text = self.color_manager.color(Colors.YELLOW, "⚠ iw not available, skipping Wi-Fi power management")
            print(warning_text)
        
        # Apply TCP tuning using safe configuration update
        tcp_params = {
            'net.core.rmem_max': '134217728',
            'net.core.wmem_max': '134217728',
            'net.ipv4.tcp_window_scaling': '1',
            'net.ipv4.tcp_timestamps': '1',
            'net.ipv4.tcp_sack': '1'
        }
        
        if self.dry_run:
            print("Simulating TCP optimization parameters...")
            simulate_text = self.color_manager.color(Colors.BRIGHT_CYAN, "→ Would update /etc/sysctl.conf with:")
            print(simulate_text)
            for param, value in tcp_params.items():
                print(f"    {param} = {value}")
            print(f"    Would run 'sysctl -p /etc/sysctl.conf'")
            print(f"    Would verify all parameters are set correctly")
        else:
            print("Applying TCP optimization parameters...")
            sysctl_success = self._safe_update_sysctl_config('/etc/sysctl.conf', tcp_params)
            
            if sysctl_success:
                success_text = self.color_manager.color(Colors.BRIGHT_GREEN, 
                                                       "✓ TCP optimization parameters applied successfully")
                print(success_text)
            else:
                error_text = self.color_manager.color(Colors.BRIGHT_RED, 
                                                    "✗ Failed to apply TCP optimization parameters")
                print(error_text)
    
    def expert_json(self) -> str:
        """Generate expert-level JSON diagnostic"""
        diagnostic = self.diagnose()
        return json.dumps(asdict(diagnostic), indent=2, default=str)
    
    def print_results(self, diagnostic: NetworkDiagnostic):
        """Print diagnostic results with color coding"""
        header = "Network Diagnostic Results"
        separator = "=" * 60
        
        print(f"\n{self.color_manager.color(Colors.BOLD, separator)}")
        print(f"{self.color_manager.color(Colors.BOLD, header)}")
        print(f"{self.color_manager.color(Colors.BOLD, separator)}")
        
        # System information
        print(f"\n{self.color_manager.color(Colors.BOLD, 'System Information:')}")
        print(f"Hostname: {diagnostic.hostname}")
        print(f"Distribution: {diagnostic.distribution}")
        print(f"Kernel: {diagnostic.kernel_version}")
        print(f"Timestamp: {diagnostic.timestamp}")
        
        # Network interfaces
        print(f"\n{self.color_manager.color(Colors.BOLD, 'Network Interfaces:')}")
        for interface in diagnostic.interfaces:
            status_color = Colors.BRIGHT_GREEN if interface.state == 'UP' else Colors.BRIGHT_RED
            status_text = self.color_manager.color(status_color, interface.state)
            print(f"  {interface.name}: {status_text} ({interface.type}, {interface.driver})")
        
        # Wi-Fi information
        if diagnostic.wifi_info:
            wifi = diagnostic.wifi_info
            print(f"\n{self.color_manager.color(Colors.BOLD, 'Wi-Fi Information:')}")
            print(f"  Interface: {wifi.interface}")
            print(f"  SSID: {wifi.ssid}")
            if wifi.frequency:
                band = "5GHz" if wifi.frequency > 4.0 else "2.4GHz"
                print(f"  Frequency: {wifi.frequency:.1f} GHz ({band})")
            if wifi.channel:
                print(f"  Channel: {wifi.channel}")
            if wifi.signal_dbm:
                signal_color = Colors.BRIGHT_GREEN if wifi.signal_dbm > -50 else Colors.BRIGHT_YELLOW if wifi.signal_dbm > -70 else Colors.BRIGHT_RED
                signal_text = self.color_manager.color(signal_color, f"{wifi.signal_dbm} dBm")
                print(f"  Signal: {signal_text}")
            if wifi.bitrate:
                print(f"  Bitrate: {wifi.bitrate}")
        
        # Speed test results
        if diagnostic.speed_test:
            speed = diagnostic.speed_test
            print(f"\n{self.color_manager.color(Colors.BOLD, 'Speed Test Results:')}")
            download_text = self.color_manager.color(Colors.BRIGHT_CYAN, f"{speed.download_mbps:.1f} Mbps")
            upload_text = self.color_manager.color(Colors.BRIGHT_CYAN, f"{speed.upload_mbps:.1f} Mbps")
            print(f"  Download: {download_text}")
            print(f"  Upload: {upload_text}")
            if speed.ping_ms > 0:
                ping_text = self.color_manager.color(Colors.BRIGHT_CYAN, f"{speed.ping_ms:.1f} ms")
                print(f"  Ping: {ping_text}")
            print(f"  Server: {speed.server}")
            print(f"  Method: {speed.test_method}")
        
        # Diagnostic findings
        if diagnostic.findings:
            print(f"\n{self.color_manager.color(Colors.BOLD, 'Diagnostic Findings:')}")
            
            # Group findings by severity
            by_severity = {}
            for finding in diagnostic.findings:
                if finding.severity not in by_severity:
                    by_severity[finding.severity] = []
                by_severity[finding.severity].append(finding)
            
            # Print in order of severity
            for severity in [Severity.CRITICAL, Severity.WARNING, Severity.INFO, Severity.SUCCESS]:
                if severity in by_severity:
                    severity_display = self.color_manager.get_severity_display(severity)
                    print(f"\n  {severity_display}:")
                    for finding in by_severity[severity]:
                        print(f"    • {finding.message}")
                        if finding.recommendation:
                            recommendation_text = self.color_manager.color(Colors.BLUE, finding.recommendation)
                            print(f"      → {recommendation_text}")
        
        # Print diagnostic summary
        self._print_diagnostic_summary()
        
        # Print context awareness summary
        self._print_context_summary()
        
        print(f"\n{self.color_manager.color(Colors.BOLD, separator)}")

    def list_rules(self):
        """List all available optimization rules"""
        available_rules = self.rule_registry.get_available_rules()
        enabled_rules = self.rule_registry.get_enabled_rules()
        disabled_rules = self.rule_registry.disabled_rules
        
        print(f"{self.color_manager.color(Colors.BOLD, 'Available Optimization Rules:')}")
        print(f"Total: {len(available_rules)} rules")
        
        if enabled_rules:
            print(f"\n{self.color_manager.color(Colors.BRIGHT_GREEN, 'Enabled Rules:')}")
            for rule in sorted(enabled_rules):
                print(f"  ✓ {rule}")
        
        if disabled_rules:
            print(f"\n{self.color_manager.color(Colors.BRIGHT_RED, 'Disabled Rules:')}")
            for rule in sorted(disabled_rules):
                print(f"  ✗ {rule}")
        
        if not available_rules:
            warning_text = self.color_manager.color(Colors.YELLOW, "No rules loaded. Check rules/ directory.")
            print(f"\n{warning_text}")

@dataclass
class SystemContext:
    """Shared context for optimization rules with caching"""
    system_config: SystemConfig
    interfaces: List[NetworkInterface]
    wifi_info: Optional[WifiInfo]
    logger: logging.Logger
    
    # Method references (not stored as callables to avoid typing issues)
    _debugger: Optional['NetworkDebugger'] = None
    
    # Cached expensive operations
    _cached_interfaces: Optional[List[NetworkInterface]] = None
    _cached_wifi_info: Optional[WifiInfo] = None
    _cached_internet_connectivity: Optional[bool] = None
    _cached_systemd_status: Optional[bool] = None
    
    def run_command(self, cmd: Union[str, List[str]], timeout: int = 30, check: bool = False) -> Tuple[int, str, str]:
        """Run command through debugger instance"""
        if self._debugger:
            return self._debugger._run_command(cmd, timeout, check)
        return -1, "", "No debugger instance available"
    
    def check_internet_connectivity(self) -> bool:
        """Check internet connectivity through debugger instance"""
        if self._debugger:
            return self._debugger._check_internet_connectivity()
        return False
    
    def is_systemd_active(self) -> bool:
        """Check systemd status through debugger instance"""
        if self._debugger:
            return self._debugger._is_systemd_active()
        return False
    
    def get_interfaces(self) -> List[NetworkInterface]:
        """Get network interfaces with caching"""
        if self._cached_interfaces is None:
            self._cached_interfaces = self.interfaces
        return self._cached_interfaces
    
    def get_wifi_info(self) -> Optional[WifiInfo]:
        """Get Wi-Fi info with caching"""
        if self._cached_wifi_info is None:
            self._cached_wifi_info = self.wifi_info
        return self._cached_wifi_info
    
    def is_internet_available(self) -> bool:
        """Check internet connectivity with caching"""
        if self._cached_internet_connectivity is None:
            self._cached_internet_connectivity = self.check_internet_connectivity()
        return self._cached_internet_connectivity
    
    def is_systemd(self) -> bool:
        """Check systemd status with caching"""
        if self._cached_systemd_status is None:
            self._cached_systemd_status = self.is_systemd_active()
        return self._cached_systemd_status

class RuleRegistry:
    """Registry for dynamically loaded optimization rules"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.rules = {}
        self.disabled_rules = set()
        
    def load_rules(self, rules_package: str = "rules"):
        """Dynamically load all rule modules from the rules package"""
        try:
            # Import the rules package
            rules_path = Path(__file__).parent / rules_package
            if not rules_path.exists():
                self.logger.warning(f"Rules directory {rules_path} not found")
                return
            
            # Find all .py files in rules directory
            for module_info in pkgutil.iter_modules([str(rules_path)]):
                module_name = module_info.name
                if module_name.startswith('_'):  # Skip private modules
                    continue
                
                try:
                    # Dynamically import the module
                    module = importlib.import_module(f"{rules_package}.{module_name}")
                    
                    # Check if module has analyze function
                    if hasattr(module, 'analyze') and callable(module.analyze):
                        self.rules[module_name] = module.analyze
                        self.logger.debug(f"Loaded rule module: {module_name}")
                    else:
                        self.logger.warning(f"Rule module {module_name} missing analyze() function")
                        
                except Exception as e:
                    self.logger.error(f"Failed to load rule module {module_name}: {e}")
                    
        except Exception as e:
            self.logger.error(f"Failed to load rules from {rules_package}: {e}")
    
    def disable_rule(self, rule_name: str):
        """Disable a specific rule"""
        self.disabled_rules.add(rule_name)
        self.logger.info(f"Disabled rule: {rule_name}")
    
    def enable_rule(self, rule_name: str):
        """Enable a previously disabled rule"""
        self.disabled_rules.discard(rule_name)
        self.logger.info(f"Enabled rule: {rule_name}")
    
    def get_available_rules(self) -> List[str]:
        """Get list of all available rule names"""
        return list(self.rules.keys())
    
    def get_enabled_rules(self) -> List[str]:
        """Get list of enabled rule names"""
        return [name for name in self.rules.keys() if name not in self.disabled_rules]
    
    def analyze_all(self, context: SystemContext) -> List[OptimizationRule]:
        """Run all enabled rules and collect optimization rules"""
        all_rules = []
        
        for rule_name, analyze_func in self.rules.items():
            if rule_name in self.disabled_rules:
                self.logger.debug(f"Skipping disabled rule: {rule_name}")
                continue
            
            try:
                rules = analyze_func(context)
                all_rules.extend(rules)
                self.logger.debug(f"Rule {rule_name} generated {len(rules)} optimization(s)")
            except Exception as e:
                self.logger.error(f"Rule {rule_name} failed: {e}")
        
        return all_rules
    
    def load_config(self, config_path: str):
        """Load rule configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            # Handle disabled rules
            disabled_rules = config.get('disabled_rules', [])
            for rule in disabled_rules:
                self.disable_rule(rule)
            
            self.logger.info(f"Loaded rule configuration from {config_path}")
            
        except FileNotFoundError:
            self.logger.debug(f"No config file found at {config_path}")
        except Exception as e:
            self.logger.error(f"Failed to load config from {config_path}: {e}")

def main():
    """Main entry point"""
    # Check Python version compatibility
    if sys.version_info < (3, 7):
        print("Error: This tool requires Python 3.7 or higher", file=sys.stderr)
        print(f"Current version: {sys.version}", file=sys.stderr)
        sys.exit(1)
    
    parser = argparse.ArgumentParser(
        description="Network Debug Tool for Linux Wi-Fi Performance Optimization",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --diagnose              # Full diagnostic scan
  %(prog)s --check-speed           # Speed test only
  %(prog)s --tune                  # Apply performance tuning
  %(prog)s --tune --dry-run        # Simulate performance tuning
  %(prog)s --crawl-config          # Crawl system configuration
  %(prog)s --optimize-suggestions  # Generate optimization recommendations
  %(prog)s --auto-fix              # Apply safe optimizations automatically
  %(prog)s --auto-fix --dry-run    # Simulate safe optimizations
  %(prog)s --interactive           # Interactive optimization mode
  %(prog)s --interactive --dry-run # Interactive simulation mode
  %(prog)s --benchmark-before      # Run baseline benchmark
  %(prog)s --benchmark-after       # Run benchmark and compare
  %(prog)s --check-deps            # Check system dependencies
  %(prog)s --expert-json           # Export detailed JSON report
  %(prog)s --diagnose --verbose    # Verbose diagnostic output
  %(prog)s --list-rules            # List all available optimization rules
  %(prog)s --skip-rule tcp --skip-rule dns # Skip specific rules
  %(prog)s --config config.yaml   # Use custom configuration file
        """
    )
    
    parser.add_argument(
        '--check-speed',
        action='store_true',
        help='Perform network speed test'
    )
    
    parser.add_argument(
        '--diagnose',
        action='store_true',
        help='Perform comprehensive network diagnosis'
    )
    
    parser.add_argument(
        '--tune',
        action='store_true',
        help='Apply automatic performance tuning'
    )
    
    parser.add_argument(
        '--expert-json',
        action='store_true',
        help='Export detailed diagnostic data as JSON'
    )
    
    parser.add_argument(
        '--crawl-config',
        action='store_true',
        help='Crawl system configuration files and parameters'
    )
    
    parser.add_argument(
        '--optimize-suggestions',
        action='store_true',
        help='Generate optimization suggestions based on system analysis'
    )
    
    parser.add_argument(
        '--auto-fix',
        action='store_true',
        help='Automatically apply safe optimizations'
    )
    
    parser.add_argument(
        '--interactive',
        action='store_true',
        help='Interactively prompt before applying each optimization'
    )
    
    parser.add_argument(
        '--benchmark-before',
        action='store_true',
        help='Run network benchmark and save baseline measurements'
    )
    
    parser.add_argument(
        '--benchmark-after',
        action='store_true',
        help='Run network benchmark and compare with previous baseline'
    )
    
    parser.add_argument(
        '--benchmark-report',
        action='store_true',
        help='Generate markdown benchmark comparison report'
    )
    
    parser.add_argument(
        '--check-deps',
        action='store_true',
        help='Check availability of system dependencies'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version=f'Network Debug Tool v{VERSION}'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Simulate changes without modifying system (show what would be done)'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Output file for JSON export'
    )
    
    parser.add_argument(
        '--skip-rule',
        action='append',
        dest='skip_rules',
        help='Skip specific optimization rule (can be used multiple times)'
    )
    
    parser.add_argument(
        '--config',
        help='Path to configuration YAML file for rule settings'
    )
    
    parser.add_argument(
        '--list-rules',
        action='store_true',
        help='List all available optimization rules'
    )
    
    args = parser.parse_args()
    
    # Default to diagnose if no specific action is specified
    if not any([args.check_speed, args.diagnose, args.tune, args.expert_json,
               args.crawl_config, args.optimize_suggestions, args.auto_fix,
               args.interactive, args.benchmark_before, args.benchmark_after, 
               args.check_deps]):
        args.diagnose = True
    
    # Initialize debugger
    debugger = NetworkDebugger(
        verbose=args.verbose, 
        no_color=args.no_color, 
        dry_run=args.dry_run,
        skip_rules=args.skip_rules,
        config_file=args.config
    )
    
    # Check for root privileges when needed (skip check in dry-run mode)
    if (args.tune or args.auto_fix or args.interactive) and not args.dry_run:
        if not debugger._is_root():
            warning_text = debugger.color_manager.color(Colors.YELLOW, "Warning: This operation requires root privileges for system-level changes")
            command_text = debugger.color_manager.color(Colors.CYAN, "sudo python3 network_debug.py")
            print(f"{warning_text}")
            print(f"Run with sudo for full functionality: {command_text}")
            print(f"Continuing with limited functionality...\n")
    elif args.dry_run and (args.tune or args.auto_fix or args.interactive):
        info_text = debugger.color_manager.color(Colors.BRIGHT_CYAN, "Dry-run mode: No system changes will be made")
        print(f"{info_text}\n")
    
    try:
        if args.list_rules:
            debugger.list_rules()
            return
            
        if args.check_deps:
            dependencies = debugger.check_dependencies()
            debugger.print_dependency_status(dependencies)
            return
        
        if args.benchmark_before:
            benchmark = debugger.run_benchmark()
            filename = args.output or "network_baseline_before.json"
            debugger.save_benchmark(benchmark, filename)
            print(f"\n{Colors.BOLD}Baseline benchmark completed:{Colors.RESET}")
            print(f"Download: {benchmark.download_mbps:.1f} Mbps")
            print(f"Upload: {benchmark.upload_mbps:.1f} Mbps")
            print(f"Ping: {benchmark.ping_ms:.1f} ms")
            print(f"TCP Retransmissions: {benchmark.tcp_retransmissions}")
            print(f"DNS Latency: {benchmark.dns_latency_ms:.1f} ms")
            print(f"\nRun optimizations, then use --benchmark-after to measure improvements")
            return
        
        if args.benchmark_after:
            after_benchmark = debugger.run_benchmark()
            
            # Try to load before benchmark
            before_file = "network_baseline_before.json"
            before_benchmark = debugger.load_benchmark(before_file)
            
            if before_benchmark:
                comparison = debugger.compare_benchmarks(before_benchmark, after_benchmark)
                debugger.print_benchmark_comparison(comparison)
                
                if args.benchmark_report or args.output:
                    report = debugger.generate_benchmark_report(comparison)
                    report_file = args.output or "benchmark_comparison.md"
                    with open(report_file, 'w') as f:
                        f.write(report)
                    print(f"\nBenchmark report saved to {report_file}")
                
                # Save after benchmark
                after_file = args.output or "network_baseline_after.json"
                if after_file.endswith('.md'):
                    after_file = "network_baseline_after.json"
                debugger.save_benchmark(after_benchmark, after_file)
            else:
                print(f"{Colors.YELLOW}No baseline benchmark found. Run --benchmark-before first.{Colors.RESET}")
                filename = args.output or "network_baseline_after.json"
                debugger.save_benchmark(after_benchmark, filename)
            return
        
        if args.tune:
            debugger.tune()
        
        if args.crawl_config:
            system_config = debugger.crawl_config()
            print(f"\n{Colors.BOLD}System Configuration Summary:{Colors.RESET}")
            print(f"Sysctl parameters: {len(system_config.sysctl_params)}")
            print(f"NetworkManager configs: {len(system_config.network_manager_configs)}")
            print(f"DNS config entries: {len(system_config.dns_config)}")
            print(f"Firewall rules: {len(system_config.firewall_rules)}")
            print(f"Driver configs: {len(system_config.driver_params)}")
            print(f"Interface settings: {len(system_config.interface_settings)}")
            
            if args.output:
                json_data = json.dumps(asdict(system_config), indent=2, default=str)
                with open(args.output, 'w') as f:
                    f.write(json_data)
                print(f"\nSystem configuration exported to {args.output}")
        
        if args.optimize_suggestions or args.auto_fix or args.interactive:
            # Run comprehensive analysis
            diagnostic = debugger.diagnose()
            system_config = debugger.crawl_config()
            
            # Generate optimization analysis
            optimization = debugger.analyze_optimizations(
                system_config, 
                diagnostic.interfaces,
                diagnostic.wifi_info
            )
            
            # Add optimization analysis to diagnostic
            diagnostic.optimization_analysis = optimization
            
            if args.interactive:
                # Interactive optimization mode
                results = debugger.apply_optimizations_interactive(optimization)
                print(f"\n{Colors.BOLD}Interactive Mode Results:{Colors.RESET}")
                applied = sum(1 for success in results.values() if success)
                total = len(results)
                print(f"Applied {applied}/{total} optimizations")
                
                # Suggest running benchmark if optimizations were applied
                if applied > 0:
                    print(f"\n{Colors.BOLD}Recommendation:{Colors.RESET}")
                    print("Run --benchmark-after to measure the impact of these optimizations")
            
            elif args.auto_fix:
                # Apply safe optimizations
                results = debugger.apply_safe_optimizations(optimization)
                print(f"\n{Colors.BOLD}Auto-fix Results:{Colors.RESET}")
                applied = sum(1 for success in results.values() if success)
                total = len(results)
                print(f"Applied {applied}/{total} optimizations successfully")
                
                # Suggest running benchmark if optimizations were applied
                if applied > 0:
                    print(f"\n{Colors.BOLD}Recommendation:{Colors.RESET}")
                    print("Run --benchmark-after to measure the impact of these optimizations")
            
            if args.optimize_suggestions:
                # Print optimization recommendations
                debugger.print_optimization_results(optimization)
                
                # Generate markdown report if output specified
                if args.output:
                    report = debugger.generate_optimization_report(optimization)
                    with open(args.output, 'w') as f:
                        f.write(report)
                    print(f"\nOptimization report exported to {args.output}")
        
        elif args.expert_json:
            json_data = debugger.expert_json()
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(json_data)
                print(f"Expert diagnostic exported to {args.output}")
            else:
                print(json_data)
        
        elif args.check_speed:
            speed_result = debugger.check_speed()
            if speed_result:
                print(f"\nSpeed Test Results:")
                print(f"Download: {speed_result.download_mbps:.1f} Mbps")
                print(f"Upload: {speed_result.upload_mbps:.1f} Mbps")
                print(f"Server: {speed_result.server}")
                
                # Provide benchmark links
                print(f"\n{Colors.BOLD}Verify Results:{Colors.RESET}")
                print(f"• Fast.com: {Colors.BLUE}https://fast.com{Colors.RESET}")
                print(f"• Cloudflare: {Colors.BLUE}https://speed.cloudflare.com{Colors.RESET}")
                print(f"• Google: {Colors.BLUE}https://speed.measurementlab.net{Colors.RESET}")
            else:
                print("Speed test failed")
        
        elif args.diagnose:
            diagnostic = debugger.diagnose()
            debugger.print_results(diagnostic)
            
            if args.output:
                json_data = json.dumps(asdict(diagnostic), indent=2, default=str)
                with open(args.output, 'w') as f:
                    f.write(json_data)
                print(f"\nDiagnostic results exported to {args.output}")
    
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Operation cancelled by user{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}Error: {e}{Colors.RESET}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
