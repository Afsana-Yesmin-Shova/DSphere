"""
DSphere — routes/network.py
Network Suggestor: given device count + purpose, compute subnet details
and recommend a suitable network topology.

  POST /network/suggest   – main calculation endpoint
  GET  /network/topologies – list all supported topologies
"""

import ipaddress
import math
import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator

from utils.jwt_handler import get_current_user

logger = logging.getLogger("dsphere.network")
router = APIRouter()


# ── Pydantic schemas ──────────────────────────────────────────────────────────
class NetworkRequest(BaseModel):
    device_count: int
    purpose: str        # e.g. "classroom", "campus", "datacenter", "city", "home"
    base_network: str = "192.168.1.0"   # optional base IP

    @field_validator("device_count")
    @classmethod
    def count_must_be_positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError("Device count must be at least 1.")
        if v > 16_777_214:
            raise ValueError("Device count exceeds maximum IPv4 host capacity.")
        return v

    @field_validator("purpose")
    @classmethod
    def clean_purpose(cls, v: str) -> str:
        return v.strip().lower()


# ── Topology rules ────────────────────────────────────────────────────────────
TOPOLOGY_RULES = [
    {
        "name": "PAN (Personal Area Network)",
        "type": "PAN",
        "max_devices": 8,
        "keywords": ["personal", "home", "bluetooth", "wearable", "smartwatch"],
        "description": "Short-range network for personal devices. Typically Bluetooth or USB.",
        "use_cases": ["Smart home", "Personal gadgets", "Wearables"],
        "icon": "🔵",
    },
    {
        "name": "LAN (Local Area Network)",
        "type": "LAN",
        "max_devices": 254,
        "keywords": ["office", "classroom", "lab", "floor", "building", "small", "home"],
        "description": "High-speed network within a single building or campus floor.",
        "use_cases": ["Office networks", "University labs", "Home broadband"],
        "icon": "🟢",
    },
    {
        "name": "WLAN (Wireless LAN)",
        "type": "WLAN",
        "max_devices": 254,
        "keywords": ["wireless", "wifi", "wi-fi", "mobile", "laptop"],
        "description": "Wireless local area network using 802.11 standards.",
        "use_cases": ["Coffee shops", "Open office", "Guest networks"],
        "icon": "📶",
    },
    {
        "name": "MAN (Metropolitan Area Network)",
        "type": "MAN",
        "max_devices": 65534,
        "keywords": ["campus", "city", "metropolitan", "university", "hospital", "municipality"],
        "description": "Covers a campus or city area, often using fibre or microwave links.",
        "use_cases": ["University campuses", "City-wide Wi-Fi", "Hospital networks"],
        "icon": "🏙️",
    },
    {
        "name": "WAN (Wide Area Network)",
        "type": "WAN",
        "max_devices": 16_777_214,
        "keywords": ["country", "global", "international", "nationwide", "enterprise", "isp"],
        "description": "Connects geographically dispersed networks across countries.",
        "use_cases": ["ISP backbones", "Multinational companies", "Internet"],
        "icon": "🌐",
    },
    {
        "name": "SAN (Storage Area Network)",
        "type": "SAN",
        "max_devices": 512,
        "keywords": ["storage", "datacenter", "data center", "san", "nas", "backup"],
        "description": "High-speed network dedicated to storage devices and servers.",
        "use_cases": ["Data centres", "Cloud storage backends", "Backup infrastructure"],
        "icon": "💾",
    },
]


# ── Subnet calculation ────────────────────────────────────────────────────────
def calculate_subnet(device_count: int, base_ip: str) -> dict:
    """
    Find the smallest subnet that accommodates device_count hosts.
    Returns full subnet details.
    """
    # Hosts per subnet = 2^(32-prefix) - 2  (network + broadcast reserved)
    # We need: 2^n - 2 >= device_count
    host_bits = math.ceil(math.log2(device_count + 2))
    prefix    = 32 - host_bits
    prefix    = max(1, min(30, prefix))   # clamp to usable range

    try:
        # Build network from base IP + prefix
        base = ipaddress.IPv4Address(base_ip)
        # Mask base address to get network address
        network = ipaddress.IPv4Network(f"{base}/{prefix}", strict=False)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid base network address: {e}")

    hosts = list(network.hosts())
    total_hosts = network.num_addresses - 2

    return {
        "prefix":            f"/{prefix}",
        "subnet_mask":       str(network.netmask),
        "wildcard_mask":     str(network.hostmask),
        "network_address":   str(network.network_address),
        "broadcast_address": str(network.broadcast_address),
        "first_host":        str(hosts[0])  if hosts else "N/A",
        "last_host":         str(hosts[-1]) if hosts else "N/A",
        "total_hosts":       total_hosts,
        "usable_hosts":      total_hosts,
        "network_size":      network.num_addresses,
        "host_bits":         host_bits,
        "network_bits":      prefix,
        "cidr_notation":     str(network),
    }


def recommend_topology(device_count: int, purpose: str) -> dict:
    """Score topologies by keyword match and device count fit."""
    purpose_lower = purpose.lower()
    scored: list[tuple[int, dict]] = []

    for topo in TOPOLOGY_RULES:
        score = 0
        # Keyword match
        for kw in topo["keywords"]:
            if kw in purpose_lower:
                score += 10
        # Device count fit
        if device_count <= topo["max_devices"]:
            # Prefer tightest fit
            score += max(0, 10 - int(math.log2(topo["max_devices"] / max(device_count, 1))))
        else:
            score -= 20   # over capacity

        scored.append((score, topo))

    scored.sort(key=lambda x: x[0], reverse=True)
    primary   = scored[0][1]
    alternate = scored[1][1] if len(scored) > 1 else None

    return {
        "primary":   primary,
        "alternate": alternate,
    }


# ── Routes ────────────────────────────────────────────────────────────────────
@router.post("/suggest")
async def suggest_network(
    body: NetworkRequest,
    current_user: dict = Depends(get_current_user),
):
    subnet   = calculate_subnet(body.device_count, body.base_network)
    topology = recommend_topology(body.device_count, body.purpose)

    logger.info(
        "Network suggestion: %d devices, purpose='%s', result=%s",
        body.device_count, body.purpose, topology["primary"]["type"],
    )

    return {
        "success": True,
        "input": {
            "device_count": body.device_count,
            "purpose":       body.purpose,
            "base_network":  body.base_network,
        },
        "subnet":   subnet,
        "topology": topology,
        "summary": (
            f"For {body.device_count} device(s) with purpose '{body.purpose}', "
            f"use a {subnet['cidr_notation']} subnet "
            f"({subnet['usable_hosts']} usable hosts) on a "
            f"{topology['primary']['name']}."
        ),
    }


@router.get("/topologies")
async def list_topologies(current_user: dict = Depends(get_current_user)):
    return {
        "success": True,
        "topologies": [
            {
                "type":        t["type"],
                "name":        t["name"],
                "max_devices": t["max_devices"],
                "description": t["description"],
                "use_cases":   t["use_cases"],
                "icon":        t["icon"],
            }
            for t in TOPOLOGY_RULES
        ],
    }