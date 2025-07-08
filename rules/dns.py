"""
DNS optimization rules.

This module analyzes DNS configuration and recommends optimizations
for DNS resolution performance.
"""

import time
import shutil
import sys
import os
from typing import List

# Add parent directory to path to allow importing from main module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from network_debug import OptimizationRule, Severity


def analyze(context) -> List[OptimizationRule]:
    """Analyze DNS configuration and return optimization rules"""
    rules = []
    dns_config = context.system_config.dns_config
    
    # Check DNS servers (only if we have internet connectivity and tools)
    if not context.check_internet_connectivity():
        context.logger.info("Skipping DNS server analysis — no internet connectivity")
        return rules
    
    # Check for DNS testing tools
    has_dig = shutil.which('dig')
    has_nslookup = shutil.which('nslookup')
    
    if not has_dig and not has_nslookup:
        context.logger.info("Skipping DNS latency tuning — neither dig nor nslookup available")
    else:
        nameservers = dns_config.get('nameservers', '')
        if nameservers:
            slow_dns = []
            dns_tool = 'dig' if has_dig else 'nslookup'
            
            for ns in nameservers.split(','):
                if ns.strip():
                    # Test DNS latency using available tool
                    start_time = time.time()
                    if has_dig:
                        code, _, _ = context.run_command(['dig', '@' + ns.strip(), 'google.com', '+short'], timeout=5)
                    else:
                        code, _, _ = context.run_command(['nslookup', 'google.com', ns.strip()], timeout=5)
                    latency = (time.time() - start_time) * 1000
                    
                    if code != 0 or latency > 100:
                        slow_dns.append(ns.strip())
                        context.logger.debug(f"DNS server {ns.strip()} slow: {latency:.1f}ms")
            
            if slow_dns:
                rules.append(OptimizationRule(
                    name="Optimize DNS Servers",
                    category="DNS",
                    severity=Severity.WARNING,
                    description=f"Slow DNS servers detected (tested with {dns_tool})",
                    current_value=nameservers,
                    recommended_value="1.1.1.1, 8.8.8.8",
                    rationale="Fast DNS servers reduce page load times",
                    fix_command="Update /etc/resolv.conf or NetworkManager settings",
                    impact="Reduces web browsing latency by 50-200ms",
                    safe_to_auto_apply=False
                ))
    
    # Check for DNS caching (only suggest systemd-resolved if systemd is active)
    systemd_resolved_active = dns_config.get('systemd_resolved_active', 'inactive')
    if systemd_resolved_active != 'active':
        is_systemd = context.is_systemd_active()
        
        if is_systemd:
            rules.append(OptimizationRule(
                name="Enable DNS Caching",
                category="DNS",
                severity=Severity.INFO,
                description="No DNS caching service detected",
                current_value="disabled",
                recommended_value="systemd-resolved",
                rationale="DNS caching reduces repeated lookup latency",
                fix_command="systemctl enable --now systemd-resolved",
                impact="Reduces DNS lookup time for repeated queries",
                safe_to_auto_apply=True
            ))
        else:
            context.logger.info("Skipping systemd-resolved suggestion — systemd not detected")
            # Could suggest alternatives like dnsmasq for non-systemd systems
            rules.append(OptimizationRule(
                name="Enable DNS Caching",
                category="DNS",
                severity=Severity.INFO,
                description="No DNS caching service detected",
                current_value="disabled",
                recommended_value="dnsmasq or unbound",
                rationale="DNS caching reduces repeated lookup latency",
                fix_command="Install and configure dnsmasq or unbound",
                impact="Reduces DNS lookup time for repeated queries",
                safe_to_auto_apply=False
            ))
    
    return rules 