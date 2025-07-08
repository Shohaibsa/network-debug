"""
Network interface optimization rules.

This module analyzes network interface settings and recommends optimizations
for hardware-level network performance.
"""

import re
import shutil
import sys
import os
from typing import List

# Add parent directory to path to allow importing from main module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from network_debug import OptimizationRule, Severity


def analyze(context) -> List[OptimizationRule]:
    """Analyze network interface settings and return optimization rules"""
    rules = []
    interface_settings = context.system_config.interface_settings
    
    # Skip if ethtool is not available
    if not shutil.which('ethtool'):
        context.logger.debug("ethtool not available, skipping interface settings analysis")
        return rules
    
    for iface_name, settings in interface_settings.items():
        # Check ring buffer sizes
        ring_info = settings.get('ring_buffers', '')
        if ring_info and 'RX:' in ring_info:
            try:
                rx_match = re.search(r'RX:\s*(\d+)', ring_info)
                if rx_match:
                    rx_current = int(rx_match.group(1))
                    if rx_current < 1024:
                        rules.append(OptimizationRule(
                            name=f"Increase RX Ring Buffer for {iface_name}",
                            category="Interface",
                            severity=Severity.INFO,
                            description="Small RX ring buffer may cause packet drops",
                            current_value=str(rx_current),
                            recommended_value="1024",
                            rationale="Larger ring buffers reduce packet drops under load",
                            fix_command=f"ethtool -G {iface_name} rx 1024",
                            impact="Reduces packet loss during traffic bursts",
                            safe_to_auto_apply=True
                        ))
            except (AttributeError, ValueError):
                pass
        
        # Check offload settings
        offload_info = settings.get('offload_settings', '')
        if offload_info and 'tcp-segmentation-offload: off' in offload_info:
            rules.append(OptimizationRule(
                name=f"Enable TCP Segmentation Offload for {iface_name}",
                category="Interface",
                severity=Severity.INFO,
                description="TCP segmentation offload is disabled",
                current_value="off",
                recommended_value="on",
                rationale="Hardware TSO reduces CPU usage for large transfers",
                fix_command=f"ethtool -K {iface_name} tso on",
                impact="Reduces CPU usage and improves throughput",
                safe_to_auto_apply=True
            ))
    
    return rules 