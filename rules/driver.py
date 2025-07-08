"""
Driver optimization rules.

This module analyzes network driver configuration and recommends optimizations
for driver-specific performance issues.
"""

import sys
import os
from typing import List

# Add parent directory to path to allow importing from main module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from network_debug import OptimizationRule, Severity


def analyze(context) -> List[OptimizationRule]:
    """Analyze driver configuration and return optimization rules"""
    rules = []
    driver_params = context.system_config.driver_params
    interfaces = context.interfaces
    
    for interface in interfaces:
        if interface.driver in ['iwlwifi', 'rtl8192ce', 'rtl8723be']:
            # Check for known problematic drivers
            if interface.driver == 'rtl8192ce':
                rules.append(OptimizationRule(
                    name="Fix RTL8192CE Driver Issues",
                    category="Driver",
                    severity=Severity.WARNING,
                    description="RTL8192CE driver has known performance issues",
                    current_value="default parameters",
                    recommended_value="optimized parameters",
                    rationale="Default RTL8192CE parameters cause connection drops",
                    fix_command=f"echo 'options rtl8192ce swenc=1 ips=0' >> /etc/modprobe.d/rtl8192ce.conf",
                    impact="Stabilizes connection and improves throughput",
                    safe_to_auto_apply=True
                ))
            
            elif interface.driver == 'iwlwifi':
                # Check for power management issues
                rules.append(OptimizationRule(
                    name="Optimize Intel Wi-Fi Driver",
                    category="Driver",
                    severity=Severity.INFO,
                    description="Intel iwlwifi driver can be optimized",
                    current_value="default parameters",
                    recommended_value="power_save=0",
                    rationale="Disabling driver-level power saving improves performance",
                    fix_command="echo 'options iwlwifi power_save=0' >> /etc/modprobe.d/iwlwifi.conf",
                    impact="Reduces latency spikes and improves reliability",
                    safe_to_auto_apply=True
                ))
    
    return rules 