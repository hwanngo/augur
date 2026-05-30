from enum import Enum


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Criticality(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class Zone(str, Enum):
    DMZ = "DMZ"
    Internal_Server = "Internal_Server"
    User_Endpoint = "User_Endpoint"
    Cloud_SaaS = "Cloud_SaaS"
    Active_Directory = "Active_Directory"
    Unknown = "Unknown"


class LinkScope(str, Enum):
    same_host = "same_host"
    cross_host = "cross_host"
    any = "any"


SEVERITY_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}
