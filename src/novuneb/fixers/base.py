"""
Base fixer interface for automated vulnerability fixes.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from novuneb.core.config import RuntimeConfig
from novuneb.core.models import Fix, FixStatus, Vulnerability


class BaseFixer(ABC):
    """
    Abstract base class for automated fix engines.
    """
    
    def __init__(self, config: RuntimeConfig):
        """Initialize fixer with configuration"""
        self.config = config
        self.name = self.__class__.__name__
    
    @abstractmethod
    def can_fix(self, vuln: Vulnerability) -> bool:
        """
        Check if this fixer can handle the vulnerability.
        
        Args:
            vuln: Vulnerability to check
            
        Returns:
            True if fixer can handle this vulnerability
        """
        pass
    
    @abstractmethod
    def generate_fix(self, vuln: Vulnerability) -> Optional[Fix]:
        """
        Generate a fix for the vulnerability.
        
        Args:
            vuln: Vulnerability to fix
            
        Returns:
            Fix object or None if no fix available
        """
        pass
    
    def apply_fix(self, vuln: Vulnerability) -> bool:
        """
        Apply the fix for a vulnerability.
        
        Args:
            vuln: Vulnerability with fix to apply
            
        Returns:
            True if fix was applied successfully
        """
        if not vuln.fix:
            return False
        
        if not self.config.config.autofix.enabled:
            return False
        
        try:
            if self.config.config.autofix.backup:
                self._create_backup(vuln)
            
            self._apply_code_change(vuln)
            
            vuln.fix.status = FixStatus.APPLIED
            return True
            
        except Exception as e:
            vuln.fix.status = FixStatus.FAILED
            vuln.fix.error_message = str(e)
            return False
    
    def _create_backup(self, vuln: Vulnerability) -> None:
        """Create backup of file before applying fix"""
        if not vuln.location:
            return
        
        file_path = vuln.location.file_path
        backup_path = file_path.with_suffix(file_path.suffix + ".bak")
        
        import shutil
        shutil.copy2(file_path, backup_path)
        
        if vuln.fix:
            vuln.fix.backup_path = backup_path
    
    @abstractmethod
    def _apply_code_change(self, vuln: Vulnerability) -> None:
        """Apply the code change to fix the vulnerability"""
        pass
    
    def supports_language(self, language: str) -> bool:
        """Check if fixer supports given language"""
        return False
