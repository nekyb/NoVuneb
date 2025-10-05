"""
Data models for NoVuneb security scanning system.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class Severity(str, Enum):
    """Vulnerability severity levels based on CVSS v3.1"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    
    @property
    def score_range(self) -> tuple[float, float]:
        """Return CVSS score range for this severity"""
        ranges = {
            Severity.CRITICAL: (9.0, 10.0),
            Severity.HIGH: (7.0, 8.9),
            Severity.MEDIUM: (4.0, 6.9),
            Severity.LOW: (0.1, 3.9),
            Severity.INFO: (0.0, 0.0),
        }
        return ranges[self]
    
    def to_emoji(self) -> str:
        """Return emoji representation"""
        emojis = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🟢",
            Severity.INFO: "🔵",
        }
        return emojis[self]


class FixStatus(str, Enum):
    """Status of automated fix"""
    AVAILABLE = "available"
    APPLIED = "applied"
    FAILED = "failed"
    NOT_AVAILABLE = "not_available"
    MANUAL_REQUIRED = "manual_required"


@dataclass
class Location:
    """Code location information"""
    file_path: Path
    line_start: int
    line_end: int
    column_start: Optional[int] = None
    column_end: Optional[int] = None
    
    def __str__(self) -> str:
        if self.column_start is not None:
            return f"{self.file_path}:{self.line_start}:{self.column_start}"
        return f"{self.file_path}:{self.line_start}"


@dataclass
class Fix:
    """Automated fix for a vulnerability"""
    description: str
    original_code: str
    fixed_code: str
    status: FixStatus = FixStatus.AVAILABLE
    confidence: float = 0.0
    backup_path: Optional[Path] = None
    applied_at: Optional[datetime] = None
    error_message: Optional[str] = None
    
    def apply(self) -> bool:
        """Apply the fix (to be implemented by specific fixers)"""
        raise NotImplementedError("Subclasses must implement apply()")


@dataclass
class Vulnerability:
    """Detected security vulnerability"""
    id: str
    title: str
    description: str
    severity: Severity
    cvss_score: float
    cwe_id: Optional[str] = None
    location: Optional[Location] = None
    scanner: str = ""
    rule_id: str = ""
    message: str = ""
    references: list[str] = field(default_factory=list)
    fix: Optional[Fix] = None
    metadata: dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "cwe_id": self.cwe_id,
            "location": str(self.location) if self.location else None,
            "scanner": self.scanner,
            "rule_id": self.rule_id,
            "message": self.message,
            "references": self.references,
            "has_fix": self.fix is not None,
            "fix_status": self.fix.status.value if self.fix else None,
            "metadata": self.metadata,
            "detected_at": self.detected_at.isoformat(),
        }


@dataclass
class ScanStatistics:
    """Statistics from a security scan"""
    total_files: int = 0
    total_lines: int = 0
    files_with_issues: int = 0
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    fixed_count: int = 0
    scan_duration: float = 0.0
    
    def add_vulnerability(self, vuln: Vulnerability) -> None:
        """Add a vulnerability to statistics"""
        self.total_vulnerabilities += 1
        if vuln.severity == Severity.CRITICAL:
            self.critical_count += 1
        elif vuln.severity == Severity.HIGH:
            self.high_count += 1
        elif vuln.severity == Severity.MEDIUM:
            self.medium_count += 1
        elif vuln.severity == Severity.LOW:
            self.low_count += 1
        elif vuln.severity == Severity.INFO:
            self.info_count += 1
        
        if vuln.fix and vuln.fix.status == FixStatus.APPLIED:
            self.fixed_count += 1
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary"""
        return {
            "total_files": self.total_files,
            "total_lines": self.total_lines,
            "files_with_issues": self.files_with_issues,
            "total_vulnerabilities": self.total_vulnerabilities,
            "by_severity": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "fixed_count": self.fixed_count,
            "scan_duration_seconds": round(self.scan_duration, 2),
        }


@dataclass
class ScanResult:
    """Complete scan result"""
    scan_id: str
    target_path: Path
    started_at: datetime
    completed_at: Optional[datetime] = None
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    statistics: ScanStatistics = field(default_factory=ScanStatistics)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def add_vulnerability(self, vuln: Vulnerability) -> None:
        """Add a vulnerability to results"""
        self.vulnerabilities.append(vuln)
        self.statistics.add_vulnerability(vuln)
    
    def get_by_severity(self, severity: Severity) -> list[Vulnerability]:
        """Get vulnerabilities by severity"""
        return [v for v in self.vulnerabilities if v.severity == severity]
    
    def get_critical_and_high(self) -> list[Vulnerability]:
        """Get critical and high severity vulnerabilities"""
        return [
            v for v in self.vulnerabilities 
            if v.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "scan_id": self.scan_id,
            "target_path": str(self.target_path),
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "statistics": self.statistics.to_dict(),
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "errors": self.errors,
            "metadata": self.metadata,
        }
