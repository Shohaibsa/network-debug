"""
VPN optimization rules.

This module detects VPN connections and recommends optimizations
for VPN-related performance issues.
"""

import sys
import os
from typing import List

# Add parent directory to path to allow importing from main module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from network_debug import OptimizationRule, Severity


def analyze(context) -> List[OptimizationRule]:
    """Detect VPN or proxy that might impact performance"""
    rules = []
    
    # Check for VPN interfaces
    code, stdout, _ = context.run_command(['ip', 'route', 'show'])
    if code == 0:
        vpn_detected = False
        for line in stdout.split('\n'):
            if any(vpn in line for vpn in ['tun', 'tap', 'ppp', 'wg']):
                vpn_detected = True
                break
        
        if vpn_detected:
            rules.append(OptimizationRule(
                name="VPN Performance Check",
                category="VPN",
                severity=Severity.INFO,
                description="VPN connection detected",
                current_value="VPN active",
                recommended_value="check MTU settings",
                rationale="VPN can cause MTU issues and performance problems",
                fix_command="Check VPN MTU settings and enable split tunneling if possible",
                impact="Proper VPN configuration can improve performance by 20-50%",
                safe_to_auto_apply=False
            ))
    
    return rules 