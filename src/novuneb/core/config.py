"""
Configuration management for NoVuneb.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel, Field, field_validator


class ScanConfig(BaseModel):
    """Scan configuration"""
    languages: list[str] = Field(
        default_factory=lambda: ["python", "javascript", "typescript"]
    )
    exclude: list[str] = Field(
        default_factory=lambda: ["node_modules/**", "venv/**", ".git/**", "*.test.js"]
    )
    severity_threshold: str = "low"
    max_issues: int = 1000
    timeout_seconds: int = 3600
    parallel_jobs: int = 4
    
    @field_validator("severity_threshold")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        valid = ["critical", "high", "medium", "low", "info"]
        if v.lower() not in valid:
            raise ValueError(f"Invalid severity: {v}. Must be one of {valid}")
        return v.lower()


class AutoFixConfig(BaseModel):
    """Auto-fix configuration"""
    enabled: bool = False
    mode: str = "safe"
    backup: bool = True
    interactive: bool = False
    max_fixes: int = 100
    
    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        valid = ["safe", "aggressive", "interactive"]
        if v.lower() not in valid:
            raise ValueError(f"Invalid mode: {v}. Must be one of {valid}")
        return v.lower()


class ReportingConfig(BaseModel):
    """Reporting configuration"""
    formats: list[str] = Field(default_factory=lambda: ["json"])
    output_dir: str = "security-reports"
    include_metrics: bool = True
    show_fixed: bool = True
    verbose: bool = False


class GitHubConfig(BaseModel):
    """GitHub integration configuration"""
    enabled: bool = False
    token: Optional[str] = None
    comment_on_pr: bool = True
    create_issues: bool = False
    labels: list[str] = Field(default_factory=lambda: ["security", "automated"])
    
    @field_validator("token")
    @classmethod
    def validate_token(cls, v: Optional[str]) -> Optional[str]:
        if v and not v.startswith("ghp_"):
            raise ValueError("Invalid GitHub token format")
        return v


class Config(BaseModel):
    """Main NoVuneb configuration"""
    version: str = "1.0"
    scan: ScanConfig = Field(default_factory=ScanConfig)
    autofix: AutoFixConfig = Field(default_factory=AutoFixConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    github: GitHubConfig = Field(default_factory=GitHubConfig)
    
    @classmethod
    def from_file(cls, config_path: Path) -> "Config":
        """Load configuration from YAML file"""
        if not config_path.exists():
            return cls()
        
        with open(config_path) as f:
            data = yaml.safe_load(f)
        
        return cls(**data)
    
    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables"""
        config = cls()
        
        if github_token := os.getenv("GITHUB_TOKEN"):
            config.github.token = github_token
            config.github.enabled = True
        
        if autofix := os.getenv("NOVUNEB_AUTOFIX"):
            config.autofix.enabled = autofix.lower() == "true"
        
        if severity := os.getenv("NOVUNEB_SEVERITY"):
            config.scan.severity_threshold = severity
        
        return config
    
    def to_file(self, config_path: Path) -> None:
        """Save configuration to YAML file"""
        with open(config_path, "w") as f:
            yaml.dump(self.model_dump(), f, default_flow_style=False)
    
    def merge_with_cli_args(self, **kwargs: Any) -> "Config":
        """Merge configuration with CLI arguments"""
        config_dict = self.model_dump()
        
        for key, value in kwargs.items():
            if value is not None:
                if "." in key:
                    section, field = key.split(".", 1)
                    if section in config_dict:
                        config_dict[section][field] = value
                else:
                    config_dict[key] = value
        
        return Config(**config_dict)


@dataclass
class RuntimeConfig:
    """Runtime configuration for a scan session"""
    config: Config
    target_path: Path
    output_file: Optional[Path] = None
    dry_run: bool = False
    verbose: bool = False
    debug: bool = False
    cache_dir: Path = field(default_factory=lambda: Path(".novuneb-cache"))
    
    def __post_init__(self) -> None:
        """Initialize runtime configuration"""
        self.cache_dir.mkdir(exist_ok=True)
        
        if self.output_file and self.output_file.parent:
            self.output_file.parent.mkdir(parents=True, exist_ok=True)


def load_config(config_path: Optional[Path] = None) -> Config:
    """
    Load configuration with priority:
    1. Specified config file
    2. .novuneb.yaml in current directory
    3. Environment variables
    4. Default values
    """
    if config_path and config_path.exists():
        return Config.from_file(config_path)
    
    default_config = Path(".novuneb.yaml")
    if default_config.exists():
        return Config.from_file(default_config)
    
    return Config.from_env()
