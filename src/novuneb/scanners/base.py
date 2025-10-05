"""
Base scanner interface for all security scanners.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from novuneb.core.config import RuntimeConfig
from novuneb.core.models import Vulnerability


class BaseScanner(ABC):
    """
    Abstract base class for all security scanners.
    """
    
    def __init__(self, config: RuntimeConfig):
        """Initialize scanner with configuration"""
        self.config = config
        self.name = self.__class__.__name__
    
    @abstractmethod
    def scan(self, target: Path) -> list[Vulnerability]:
        """
        Scan target path for vulnerabilities.
        
        Args:
            target: Path to scan (file or directory)
            
        Returns:
            List of detected vulnerabilities
        """
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if scanner is available/installed"""
        pass
    
    def get_scanner_version(self) -> Optional[str]:
        """Get scanner tool version"""
        return None
    
    def supports_language(self, language: str) -> bool:
        """Check if scanner supports given language"""
        return True
    
    def _is_target_supported(self, target: Path) -> bool:
        """Check if target is supported by this scanner"""
        if not target.exists():
            return False
        
        if target.is_file():
            return self._is_file_supported(target)
        
        return True
    
    def _is_file_supported(self, file_path: Path) -> bool:
        """Check if file type is supported"""
        supported_extensions = self._get_supported_extensions()
        return file_path.suffix in supported_extensions if supported_extensions else True
    
    def _get_supported_extensions(self) -> Optional[set[str]]:
        """Get set of supported file extensions"""
        return None
