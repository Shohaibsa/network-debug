"""
Wi-Fi optimization rules.

This module analyzes Wi-Fi configuration and recommends optimizations
for wireless network performance.
"""

import shutil
import sys
import os
from typing import List

# Add parent directory to path to allow importing from main module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from network_debug import OptimizationRule, Severity


def analyze(context) -> List[OptimizationRule]:
    """Analyze Wi-Fi configuration and return optimization rules"""
    rules = []
    wifi_info = context.wifi_info
    
    if not wifi_info:
        return rules
    
    # Check power management (requires iw)
    if shutil.which('iw'):
        code, stdout, _ = context.run_command(['iw', wifi_info.interface, 'get', 'power_save'])
        if code == 0 and 'Power save: on' in stdout:
            rules.append(OptimizationRule(
                name="Disable Wi-Fi Power Management",
                category="Wi-Fi",
                severity=Severity.WARNING,
                description="Wi-Fi power management is reducing performance",
                current_value="on",
                recommended_value="off",
                rationale="Power management causes latency spikes and reduced throughput",
                fix_command=f"iw {wifi_info.interface} set power_save off",
                impact="Reduces connection drops and improves latency by 10-50ms",
                safe_to_auto_apply=True
            ))
    
    # Check frequency band
    if wifi_info.frequency and wifi_info.frequency < 3.0:
        rules.append(OptimizationRule(
            name="Switch to 5GHz Band",
            category="Wi-Fi",
            severity=Severity.INFO,
            description="Connected to 2.4GHz band",
            current_value=f"{wifi_info.frequency:.1f} GHz",
            recommended_value="5GHz",
            rationale="5GHz band offers more bandwidth and less congestion",
            fix_command="Use NetworkManager to prefer 5GHz networks",
            impact="Potential 2-5x speed improvement",
            safe_to_auto_apply=False
        ))
    
    # Check signal strength
    if wifi_info.signal_dbm and wifi_info.signal_dbm < -70:
        rules.append(OptimizationRule(
            name="Improve Wi-Fi Signal Strength",
            category="Wi-Fi",
            severity=Severity.WARNING,
            description="Weak Wi-Fi signal detected",
            current_value=f"{wifi_info.signal_dbm} dBm",
            recommended_value="> -50 dBm",
            rationale="Poor signal strength causes retransmissions and reduces throughput",
            fix_command="Move closer to access point or use Wi-Fi extender",
            impact="Signal improvement can double connection speed",
            safe_to_auto_apply=False
        ))
    
    return rules 