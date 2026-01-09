"""
Frost Gate Spear Tool Catalog

Registry of available tools with risk tiers and capabilities.
"""

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

from ..core.config import Config

logger = logging.getLogger(__name__)


class RiskTier(Enum):
    """Tool risk tier classification."""
    LOW = 1       # Reconnaissance, passive
    MEDIUM = 2    # Active scanning, enumeration
    HIGH = 3      # Exploitation, credential access
    CRITICAL = 4  # Destructive, persistence


class ToolCategory(Enum):
    """Tool category classification."""
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_SCAN = "vulnerability_scan"
    EXPLOITATION = "exploitation"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    PERSISTENCE = "persistence"
    DEFENSE_EVASION = "defense_evasion"
    COMMAND_CONTROL = "command_control"
    IMPACT = "impact"


@dataclass
class Tool:
    """Tool definition."""
    tool_id: str
    name: str
    category: ToolCategory
    risk_tier: RiskTier
    description: str
    techniques: List[str]  # MITRE ATT&CK technique IDs
    min_classification: str  # Minimum classification level required
    requires_approval: bool
    approval_roles: List[str]
    parameters: Dict[str, Any]
    enabled: bool = True


class ToolCatalog:
    """
    Tool Catalog.

    Registry of available tools with:
    - Risk tier classification
    - Category mapping
    - Technique associations
    - Approval requirements
    """

    def __init__(self, config: Config):
        """Initialize Tool Catalog."""
        self.config = config
        self._tools: Dict[str, Tool] = {}
        self._load_default_tools()

    def _load_default_tools(self) -> None:
        """Load default tool definitions."""
        default_tools = [
            # Reconnaissance
            Tool(
                tool_id="nmap",
                name="Nmap",
                category=ToolCategory.RECONNAISSANCE,
                risk_tier=RiskTier.LOW,
                description="Network mapper for host discovery and service enumeration",
                techniques=["T1595.001", "T1595.002", "T1046"],
                min_classification="UNCLASS",
                requires_approval=False,
                approval_roles=[],
                parameters={
                    "scan_types": ["ping", "syn", "connect", "udp", "service"],
                    "timing": ["T0", "T1", "T2", "T3", "T4", "T5"],
                },
            ),
            Tool(
                tool_id="masscan",
                name="Masscan",
                category=ToolCategory.RECONNAISSANCE,
                risk_tier=RiskTier.LOW,
                description="Fast port scanner",
                techniques=["T1595.001", "T1046"],
                min_classification="UNCLASS",
                requires_approval=False,
                approval_roles=[],
                parameters={
                    "rate": {"default": 1000, "max": 100000},
                },
            ),
            Tool(
                tool_id="amass",
                name="Amass",
                category=ToolCategory.RECONNAISSANCE,
                risk_tier=RiskTier.LOW,
                description="Subdomain enumeration and network mapping",
                techniques=["T1590", "T1591"],
                min_classification="UNCLASS",
                requires_approval=False,
                approval_roles=[],
                parameters={},
            ),
            # Vulnerability Scanning
            Tool(
                tool_id="nessus",
                name="Nessus",
                category=ToolCategory.VULNERABILITY_SCAN,
                risk_tier=RiskTier.MEDIUM,
                description="Vulnerability scanner",
                techniques=["T1595.002"],
                min_classification="UNCLASS",
                requires_approval=False,
                approval_roles=[],
                parameters={
                    "scan_policies": ["basic", "advanced", "compliance"],
                },
            ),
            Tool(
                tool_id="openvas",
                name="OpenVAS",
                category=ToolCategory.VULNERABILITY_SCAN,
                risk_tier=RiskTier.MEDIUM,
                description="Open vulnerability assessment scanner",
                techniques=["T1595.002"],
                min_classification="UNCLASS",
                requires_approval=False,
                approval_roles=[],
                parameters={},
            ),
            Tool(
                tool_id="nikto",
                name="Nikto",
                category=ToolCategory.VULNERABILITY_SCAN,
                risk_tier=RiskTier.MEDIUM,
                description="Web server scanner",
                techniques=["T1595.002", "T1595.003"],
                min_classification="UNCLASS",
                requires_approval=False,
                approval_roles=[],
                parameters={},
            ),
            Tool(
                tool_id="nuclei",
                name="Nuclei",
                category=ToolCategory.VULNERABILITY_SCAN,
                risk_tier=RiskTier.MEDIUM,
                description="Template-based vulnerability scanner",
                techniques=["T1595.002"],
                min_classification="UNCLASS",
                requires_approval=False,
                approval_roles=[],
                parameters={
                    "templates": ["cves", "vulnerabilities", "misconfiguration"],
                },
            ),
            # Exploitation
            Tool(
                tool_id="metasploit",
                name="Metasploit Framework",
                category=ToolCategory.EXPLOITATION,
                risk_tier=RiskTier.HIGH,
                description="Exploitation framework",
                techniques=["T1190", "T1203", "T1210"],
                min_classification="UNCLASS",
                requires_approval=True,
                approval_roles=["Security"],
                parameters={
                    "payload_types": ["reverse_tcp", "reverse_https", "bind_tcp"],
                },
            ),
            Tool(
                tool_id="cobalt_strike",
                name="Cobalt Strike",
                category=ToolCategory.EXPLOITATION,
                risk_tier=RiskTier.HIGH,
                description="Adversary simulation and red team operations",
                techniques=["T1059", "T1071", "T1095"],
                min_classification="CUI",
                requires_approval=True,
                approval_roles=["Security", "MissionOwner"],
                parameters={
                    "beacon_types": ["http", "https", "dns", "smb"],
                },
            ),
            Tool(
                tool_id="sqlmap",
                name="SQLMap",
                category=ToolCategory.EXPLOITATION,
                risk_tier=RiskTier.HIGH,
                description="SQL injection automation tool",
                techniques=["T1190"],
                min_classification="UNCLASS",
                requires_approval=True,
                approval_roles=["Security"],
                parameters={
                    "techniques": ["boolean", "time", "union", "error", "stacked"],
                },
            ),
            # Credential Access
            Tool(
                tool_id="mimikatz",
                name="Mimikatz",
                category=ToolCategory.CREDENTIAL_ACCESS,
                risk_tier=RiskTier.HIGH,
                description="Credential extraction tool",
                techniques=["T1003.001", "T1003.002", "T1003.004", "T1558"],
                min_classification="UNCLASS",
                requires_approval=True,
                approval_roles=["Security"],
                parameters={
                    "modules": ["sekurlsa", "kerberos", "lsadump"],
                },
            ),
            Tool(
                tool_id="rubeus",
                name="Rubeus",
                category=ToolCategory.CREDENTIAL_ACCESS,
                risk_tier=RiskTier.HIGH,
                description="Kerberos abuse toolkit",
                techniques=["T1558.003", "T1558.004"],
                min_classification="UNCLASS",
                requires_approval=True,
                approval_roles=["Security"],
                parameters={},
            ),
            Tool(
                tool_id="hashcat",
                name="Hashcat",
                category=ToolCategory.CREDENTIAL_ACCESS,
                risk_tier=RiskTier.MEDIUM,
                description="Password recovery tool",
                techniques=["T1110.002"],
                min_classification="UNCLASS",
                requires_approval=False,
                approval_roles=[],
                parameters={
                    "attack_modes": ["dictionary", "brute_force", "rule_based", "hybrid"],
                },
            ),
            # Discovery
            Tool(
                tool_id="bloodhound",
                name="BloodHound",
                category=ToolCategory.DISCOVERY,
                risk_tier=RiskTier.MEDIUM,
                description="Active Directory reconnaissance",
                techniques=["T1087", "T1482", "T1069"],
                min_classification="UNCLASS",
                requires_approval=False,
                approval_roles=[],
                parameters={},
            ),
            Tool(
                tool_id="adexplorer",
                name="AD Explorer",
                category=ToolCategory.DISCOVERY,
                risk_tier=RiskTier.LOW,
                description="Active Directory browser",
                techniques=["T1087.002"],
                min_classification="UNCLASS",
                requires_approval=False,
                approval_roles=[],
                parameters={},
            ),
            # Lateral Movement
            Tool(
                tool_id="psexec",
                name="PsExec",
                category=ToolCategory.LATERAL_MOVEMENT,
                risk_tier=RiskTier.HIGH,
                description="Remote command execution",
                techniques=["T1021.002", "T1569.002"],
                min_classification="UNCLASS",
                requires_approval=True,
                approval_roles=["Security"],
                parameters={},
            ),
            Tool(
                tool_id="impacket",
                name="Impacket",
                category=ToolCategory.LATERAL_MOVEMENT,
                risk_tier=RiskTier.HIGH,
                description="Network protocol toolkit",
                techniques=["T1021.002", "T1021.003", "T1021.006"],
                min_classification="UNCLASS",
                requires_approval=True,
                approval_roles=["Security"],
                parameters={
                    "scripts": ["psexec", "wmiexec", "smbexec", "atexec", "dcomexec"],
                },
            ),
            Tool(
                tool_id="crackmapexec",
                name="CrackMapExec",
                category=ToolCategory.LATERAL_MOVEMENT,
                risk_tier=RiskTier.HIGH,
                description="Network penetration testing tool",
                techniques=["T1021.002", "T1110"],
                min_classification="UNCLASS",
                requires_approval=True,
                approval_roles=["Security"],
                parameters={
                    "protocols": ["smb", "winrm", "mssql", "ldap", "ssh"],
                },
            ),
            # Collection
            Tool(
                tool_id="sharphound",
                name="SharpHound",
                category=ToolCategory.COLLECTION,
                risk_tier=RiskTier.MEDIUM,
                description="BloodHound data collector",
                techniques=["T1087", "T1069"],
                min_classification="UNCLASS",
                requires_approval=False,
                approval_roles=[],
                parameters={},
            ),
            # Exfiltration
            Tool(
                tool_id="rclone",
                name="Rclone",
                category=ToolCategory.EXFILTRATION,
                risk_tier=RiskTier.HIGH,
                description="Cloud storage sync tool",
                techniques=["T1567"],
                min_classification="UNCLASS",
                requires_approval=True,
                approval_roles=["Security", "MissionOwner"],
                parameters={},
            ),
            # Persistence
            Tool(
                tool_id="empire",
                name="PowerShell Empire",
                category=ToolCategory.PERSISTENCE,
                risk_tier=RiskTier.HIGH,
                description="Post-exploitation framework",
                techniques=["T1059.001", "T1053", "T1547"],
                min_classification="UNCLASS",
                requires_approval=True,
                approval_roles=["Security"],
                parameters={},
            ),
        ]

        for tool in default_tools:
            self._tools[tool.tool_id] = tool

    def get_tool(self, tool_id: str) -> Optional[Tool]:
        """Get tool by ID."""
        return self._tools.get(tool_id)

    def list_tools(
        self,
        category: Optional[ToolCategory] = None,
        risk_tier: Optional[RiskTier] = None,
        classification: Optional[str] = None,
    ) -> List[Tool]:
        """List tools with optional filters."""
        tools = list(self._tools.values())

        if category:
            tools = [t for t in tools if t.category == category]

        if risk_tier:
            tools = [t for t in tools if t.risk_tier == risk_tier]

        if classification:
            level_order = ["UNCLASS", "CUI", "SECRET", "TOPSECRET"]
            max_level = level_order.index(classification)
            tools = [
                t for t in tools
                if level_order.index(t.min_classification) <= max_level
            ]

        return tools

    def get_tools_for_technique(self, technique_id: str) -> List[Tool]:
        """Get tools that implement a technique."""
        return [
            t for t in self._tools.values()
            if technique_id in t.techniques
        ]

    def validate_tool_access(
        self,
        tool_id: str,
        classification: str,
        approved_roles: List[str],
    ) -> tuple[bool, Optional[str]]:
        """
        Validate access to a tool.

        Returns:
            Tuple of (allowed, reason_if_denied)
        """
        tool = self.get_tool(tool_id)

        if not tool:
            return False, f"Tool not found: {tool_id}"

        if not tool.enabled:
            return False, f"Tool disabled: {tool_id}"

        # Check classification
        level_order = ["UNCLASS", "CUI", "SECRET", "TOPSECRET"]
        current_level = level_order.index(classification)
        required_level = level_order.index(tool.min_classification)

        if current_level < required_level:
            return False, f"Tool requires {tool.min_classification} classification"

        # Check approval
        if tool.requires_approval:
            missing_roles = set(tool.approval_roles) - set(approved_roles)
            if missing_roles:
                return False, f"Tool requires approval from: {list(missing_roles)}"

        return True, None

    def register_tool(self, tool: Tool) -> None:
        """Register a new tool."""
        self._tools[tool.tool_id] = tool
        logger.info(f"Registered tool: {tool.tool_id}")

    def disable_tool(self, tool_id: str) -> bool:
        """Disable a tool."""
        tool = self.get_tool(tool_id)
        if tool:
            tool.enabled = False
            logger.info(f"Disabled tool: {tool_id}")
            return True
        return False

    def get_risk_summary(self) -> Dict[str, int]:
        """Get count of tools by risk tier."""
        summary = {tier.name: 0 for tier in RiskTier}
        for tool in self._tools.values():
            if tool.enabled:
                summary[tool.risk_tier.name] += 1
        return summary

    def to_dict(self) -> Dict[str, Any]:
        """Export catalog to dictionary."""
        return {
            "tools": [
                {
                    "tool_id": t.tool_id,
                    "name": t.name,
                    "category": t.category.value,
                    "risk_tier": t.risk_tier.value,
                    "description": t.description,
                    "techniques": t.techniques,
                    "min_classification": t.min_classification,
                    "requires_approval": t.requires_approval,
                    "enabled": t.enabled,
                }
                for t in self._tools.values()
            ],
            "summary": self.get_risk_summary(),
        }
