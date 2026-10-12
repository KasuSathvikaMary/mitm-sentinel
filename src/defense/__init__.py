"""Defense countermeasures package."""
from src.defense.base_defense import BaseDefense, DefenseResult
from src.defense.arp_immunity import ARPImmunityDefense
from src.defense.firewall_blocker import FirewallBlockerDefense
from src.defense.dns_sec_enforcer import DNSSecEnforcerDefense
from src.defense.connection_killer import ConnectionKillerDefense

__all__ = [
    "BaseDefense",
    "DefenseResult",
    "ARPImmunityDefense",
    "FirewallBlockerDefense",
    "DNSSecEnforcerDefense",
    "ConnectionKillerDefense"
]
