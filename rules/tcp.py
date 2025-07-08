"""
TCP Stack optimization rules.

This module analyzes TCP stack configuration and recommends optimizations
for network performance.
"""

from typing import Dict, List
import sys
import os

# Add parent directory to path to allow importing from main module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from network_debug import OptimizationRule, Severity


def analyze(context) -> List[OptimizationRule]:
    """Analyze TCP stack configuration and return optimization rules"""
    rules = []
    sysctl_params = context.system_config.sysctl_params
    
    # Define optimal TCP parameters based on modern networks
    tcp_optimizations = {
        'net.core.rmem_max': {
            'recommended': '134217728',
            'rationale': 'Maximum receive buffer size for high-bandwidth networks',
            'impact': 'Prevents buffer overflow on fast connections'
        },
        'net.core.wmem_max': {
            'recommended': '134217728',
            'rationale': 'Maximum send buffer size for high-bandwidth networks',
            'impact': 'Improves upload performance'
        },
        'net.ipv4.tcp_window_scaling': {
            'recommended': '1',
            'rationale': 'Enables TCP window scaling for high-bandwidth delay products',
            'impact': 'Critical for connections >64KB bandwidth-delay product'
        },
        'net.ipv4.tcp_timestamps': {
            'recommended': '1',
            'rationale': 'Enables TCP timestamps for better RTT estimation',
            'impact': 'Improves congestion control accuracy'
        },
        'net.ipv4.tcp_sack': {
            'recommended': '1',
            'rationale': 'Enables selective acknowledgments for better loss recovery',
            'impact': 'Faster recovery from packet loss'
        },
        'net.ipv4.tcp_congestion_control': {
            'recommended': 'bbr',
            'rationale': 'BBR congestion control optimizes for bandwidth and latency',
            'impact': 'Better performance on varied network conditions'
        },
        'net.core.netdev_max_backlog': {
            'recommended': '5000',
            'rationale': 'Increases packet processing queue size',
            'impact': 'Reduces packet drops under high load'
        },
        'net.ipv4.tcp_fastopen': {
            'recommended': '3',
            'rationale': 'Enables TCP Fast Open for both client and server',
            'impact': 'Reduces connection establishment latency'
        }
    }
    
    for param, config in tcp_optimizations.items():
        current_value = sysctl_params.get(param)
        recommended = config['recommended']
        
        if current_value != recommended:
            severity = Severity.WARNING if param in ['net.core.rmem_max', 'net.core.wmem_max'] else Severity.INFO
            
            rules.append(OptimizationRule(
                name=f"Optimize {param}",
                category="TCP Stack",
                severity=severity,
                description=f"Suboptimal {param} setting",
                current_value=current_value or 'not set',
                recommended_value=recommended,
                rationale=config['rationale'],
                fix_command=f"echo '{param} = {recommended}' >> /etc/sysctl.conf && sysctl -p",
                impact=config['impact'],
                safe_to_auto_apply=True
            ))
    
    return rules 