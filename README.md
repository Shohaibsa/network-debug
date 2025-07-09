# Network Debug Tool for Linux

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![Linux](https://img.shields.io/badge/platform-linux-green.svg)](https://www.linux.org/)

A comprehensive CLI tool for diagnosing Wi-Fi bottlenecks and optimizing network performance on Linux systems. Built for developers, system administrators, and power users who need production-grade network optimization with safety-first design.

## Features

- **Comprehensive Network Diagnosis**: Automatically detects Wi-Fi, DNS, TCP, and driver configuration issues
- **Safety-First Design**: Dry-run simulation, timestamped backups, and rollback capabilities
- **Interactive & Automated Modes**: Choose between guided optimization or fully automated safe fixes
- **Cross-Distribution Support**: Works on Ubuntu, Pop!_OS, Arch, Fedora, Alpine, and containers
- **Professional Reporting**: JSON export, Markdown reports, and before/after benchmarking
- **Modular Architecture**: Plugin-based optimization rules with 6 built-in modules

## Quick Start

```bash
# Download and make executable
chmod +x network_debug.py

# Check system dependencies
./network_debug.py --check-deps

# Run comprehensive diagnosis
./network_debug.py --diagnose

# Apply safe optimizations (requires root)
sudo ./network_debug.py --auto-fix --dry-run   # Simulate first
sudo ./network_debug.py --auto-fix             # Apply changes
```

## Installation

### Requirements
- **Python**: 3.7 or higher
- **Platform**: Linux (any distribution)
- **Privileges**: Root access required for system-level optimizations

### Dependencies
```bash
# Install Python dependency
pip install PyYAML>=5.1

# Or install system-wide
sudo apt install python3-yaml    # Ubuntu/Debian
sudo dnf install python3-PyYAML  # Fedora
sudo pacman -S python-yaml       # Arch
sudo apk add py3-yaml            # Alpine
```

### Optional System Tools
For full functionality, install these system utilities:
```bash
# Ubuntu/Debian
sudo apt install iw wireless-tools ethtool speedtest-cli iperf3 dnsutils

# Fedora
sudo dnf install iw wireless-tools ethtool speedtest-cli iperf3 bind-utils

# Arch Linux
sudo pacman -S iw wireless_tools ethtool speedtest-cli iperf3 bind

# Alpine Linux
sudo apk add iw wireless-tools ethtool speedtest-cli iperf3 bind-tools
```

## Usage Examples

### Basic Operations
```bash
# Comprehensive network diagnosis
./network_debug.py --diagnose

# Speed test only
./network_debug.py --check-speed

# List available optimization rules
./network_debug.py --list-rules

# Check system dependencies
./network_debug.py --check-deps
```

### Safe Optimization
```bash
# Simulate optimizations (no changes made)
./network_debug.py --auto-fix --dry-run

# Apply safe optimizations
sudo ./network_debug.py --auto-fix

# Interactive mode with user prompts
sudo ./network_debug.py --interactive

# Quick performance tuning
sudo ./network_debug.py --tune
```

### Advanced Features
```bash
# Generate optimization suggestions only
./network_debug.py --optimize-suggestions

# System configuration analysis
./network_debug.py --crawl-config --output system-config.json

# Before/after performance benchmarking
./network_debug.py --benchmark-before
# ... apply optimizations ...
./network_debug.py --benchmark-after --output benchmark-report.md

# Export detailed diagnostics
./network_debug.py --expert-json --output diagnostic.json

# Skip specific optimization categories
./network_debug.py --auto-fix --skip-rule vpn --skip-rule driver

# Use custom configuration
./network_debug.py --auto-fix --config custom-rules.yaml
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `--diagnose` | Perform comprehensive network diagnosis (default) |
| `--check-speed` | Run network speed test only |
| `--tune` | Apply automatic performance optimizations |
| `--auto-fix` | Automatically apply safe optimizations |
| `--interactive` | Interactively prompt before applying each optimization |
| `--optimize-suggestions` | Generate optimization suggestions without applying |
| `--benchmark-before` | Run baseline benchmark and save measurements |
| `--benchmark-after` | Run benchmark and compare with baseline |
| `--benchmark-report` | Generate markdown benchmark comparison report |
| `--crawl-config` | Analyze system configuration files and parameters |
| `--expert-json` | Export detailed diagnostic data as JSON |
| `--list-rules` | List all available optimization rules |
| `--check-deps` | Check availability of system dependencies |
| `--dry-run` | Simulate changes without modifying system |
| `--no-color` | Disable colored output |
| `--verbose, -v` | Enable verbose debug output |
| `--output, -o` | Specify output file for JSON/Markdown export |
| `--skip-rule` | Skip specific optimization rule (can be used multiple times) |
| `--config` | Path to configuration YAML file for rule settings |
| `--version` | Show program version |

## Sample Output

### Diagnostic Report
```
============================================================
Network Diagnostic Results
============================================================

System Information:
Hostname: pop-os
Distribution: Pop!_OS
Kernel: 6.12.10-76061203-generic
Timestamp: 2025-07-08 15:04:35

Network Interfaces:
  enp7s0: DOWN (ethernet, r8169)
  wlo1: UP (wifi, iwlwifi)

Wi-Fi Information:
  Interface: wlo1
  SSID: $SSID
  Frequency: 5.2 GHz (5GHz)
  Channel: 44
  Signal: -30 dBm
  Bitrate: 1.2009 Gb/s

Diagnostic Findings:

  [⚠] WARNING:
    • Power saving enabled on wlo1
      → Disable power saving for better performance: iw wlo1 set power_save off

  [i] INFO:
    • TCP tuning can improve performance
      → Add to /etc/sysctl.conf:
        net.core.rmem_max = 134217728
        net.core.wmem_max = 134217728
        net.ipv4.tcp_window_scaling = 1

Summary: 1 Warning, 1 Info

System Context:
  Wi-Fi interface: ✓ Available
  Internet access: ✓ Connected
  Init system: systemd
  Network tools: ✓ 7/7 tools available
  ✓ Full diagnostic capability
============================================================
```

### Dry-Run Simulation
```bash
$ sudo ./network_debug.py --tune --dry-run
Dry-run mode: No system changes will be made

Simulating performance tuning...
→ Would disable power saving on wlo1
    Would execute: iw wlo1 set power_save off
Simulating TCP optimization parameters...
→ Would update /etc/sysctl.conf with:
    net.core.rmem_max = 134217728
    net.core.wmem_max = 134217728
    net.ipv4.tcp_window_scaling = 1
    net.ipv4.tcp_timestamps = 1
    net.ipv4.tcp_sack = 1
    Would run 'sysctl -p /etc/sysctl.conf'
    Would verify all parameters are set correctly
```

### Dependency Check
```bash
$ ./network_debug.py --check-deps

Dependency Status:

  Required:
    ✓ ping
    ✓ ip

  Recommended:
    ✓ iperf3
    ✓ speedtest-cli
    ✓ iw
    ✓ ethtool
    ✓ nmcli

  Optional:
    ✓ dig
    ✓ nslookup
    ✓ iwconfig
    ✓ rfkill
```

## Optimization Rules

The tool includes 6 built-in optimization modules:

| Rule | Category | Description |
|------|----------|-------------|
| **TCP** | System | TCP buffer optimization, congestion control, window scaling |
| **Wi-Fi** | Wireless | Power management, band selection, signal strength analysis |
| **DNS** | Network | DNS server performance, caching configuration |
| **Driver** | Hardware | Known driver issues and optimizations |
| **Interface** | Hardware | Network interface hardware settings |
| **VPN** | Network | VPN detection and performance recommendations |

### Custom Rules
Create custom optimization rules by adding Python files to the `rules/` directory:

```python
"""
Custom optimization rules.
"""

from typing import List
from network_debug import OptimizationRule, Severity

def analyze(context) -> List[OptimizationRule]:
    """Analyze system and return optimization rules"""
    rules = []
    
    # Your custom analysis logic here
    # Access system data via context.system_config, context.interfaces, etc.
    
    rules.append(OptimizationRule(
        name="Custom Optimization",
        category="Custom",
        severity=Severity.INFO,
        description="Custom optimization description",
        current_value="current",
        recommended_value="recommended",
        rationale="Why this optimization helps",
        fix_command="command to apply fix",
        impact="Expected performance improvement",
        safe_to_auto_apply=True
    ))
    
    return rules
```

## Safety Features

- **Root Privilege Enforcement**: System-level changes require explicit root access
- **Dry-Run Simulation**: Preview all changes before applying them
- **Timestamped Backups**: Automatic backup of all modified configuration files
- **Rollback Capability**: Automatic rollback on failed verification
- **Verification Checks**: Confirm all applied settings are working correctly
- **No Silent Changes**: All modifications are logged and reported

## Supported Systems

### Tested Distributions
- **Ubuntu** 18.04+ (including flavors like Pop!_OS)
- **Fedora** 30+
- **Arch Linux** (including Manjaro)
- **Alpine Linux** 3.10+
- **Debian** 10+
- **openSUSE** Leap 15+

### Hardware Compatibility
- **Wi-Fi Chipsets**: Intel (iwlwifi), Realtek, Broadcom, Atheros, MediaTek
- **Network Interfaces**: Ethernet, Wi-Fi, Virtual (bridges, containers)
- **Init Systems**: systemd, OpenRC, SysV

### Known Limitations
- Requires Linux kernel 3.10+ for full functionality
- Some optimizations require specific hardware support
- Container environments may have limited network access

## Performance Impact

Typical improvements after optimization:

- **Wi-Fi Latency**: 20-50ms reduction with power management disabled
- **TCP Throughput**: 2-5x improvement on high-bandwidth connections
- **DNS Resolution**: 50-200ms faster with optimized servers
- **Connection Stability**: Reduced disconnections and timeouts

## Contributing

This project follows production-grade development practices:

1. **Code Quality**: All contributions must pass linting and type checking
2. **Testing**: New features require comprehensive test coverage
3. **Documentation**: Update README and inline documentation
4. **Safety**: Maintain backwards compatibility and safety checks

## License

MIT License - See [LICENSE](LICENSE) file for details.

## Support

- **Issues**: Report bugs and feature requests via GitHub Issues
- **Documentation**: This README and inline code documentation
- **Community**: Contributions welcome following the coding standards

---

**Version**: 1.0.1
**Python**: 3.7+  
**Platform**: Linux  
**License**: MIT 
