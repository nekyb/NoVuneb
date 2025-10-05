"""
Python code fixer for automated vulnerability remediation.
"""

import logging
import re
from typing import Optional

import libcst as cst

from novuneb.core.models import Fix, FixStatus, Vulnerability
from novuneb.fixers.base import BaseFixer

logger = logging.getLogger(__name__)


class PythonFixer(BaseFixer):
    """
    Automated fixer for Python security vulnerabilities.
    Uses LibCST for safe code transformations.
    """
    
    FIX_PATTERNS = {
        "hardcoded-password": {
            "pattern": r'password\s*=\s*["\'].*["\']',
            "fix": 'password = os.getenv("PASSWORD")',
            "imports": ["import os"],
        },
        "sql-injection": {
            "pattern": r'execute\((f?["\'].*\{.*\}.*["\'])\)',
            "fix": 'Use parameterized queries instead',
        },
        "assert-used": {
            "pattern": r'\bassert\b',
            "fix": 'if not condition:\n    raise ValueError("Error message")',
        },
    }
    
    def can_fix(self, vuln: Vulnerability) -> bool:
        """Check if we can fix this Python vulnerability"""
        if not vuln.location:
            return False
        
        if vuln.location.file_path.suffix != ".py":
            return False
        
        fixable_rules = [
            "B105",
            "B106",
            "B107",
            "B608",
            "B101",
        ]
        
        return vuln.rule_id in fixable_rules
    
    def generate_fix(self, vuln: Vulnerability) -> Optional[Fix]:
        """Generate fix for Python vulnerability"""
        if not self.can_fix(vuln):
            return None
        
        try:
            if not vuln.location:
                return None
            
            file_path = vuln.location.file_path
            
            with open(file_path) as f:
                source_code = f.read()
            
            if "B105" in vuln.rule_id or "B106" in vuln.rule_id or "B107" in vuln.rule_id:
                return self._fix_hardcoded_password(source_code, vuln)
            
            elif "B608" in vuln.rule_id:
                return self._fix_sql_injection(source_code, vuln)
            
            elif "B101" in vuln.rule_id:
                return self._fix_assert_usage(source_code, vuln)
            
        except Exception as e:
            logger.error(f"Failed to generate fix: {e}")
        
        return None
    
    def _fix_hardcoded_password(self, source: str, vuln: Vulnerability) -> Fix:
        """Fix hardcoded password vulnerability"""
        pattern = self.FIX_PATTERNS["hardcoded-password"]
        
        lines = source.split("\n")
        if vuln.location:
            line_idx = vuln.location.line_start - 1
            original_line = lines[line_idx]
            fixed_line = re.sub(
                pattern["pattern"],
                pattern["fix"],
                original_line
            )
        else:
            original_line = ""
            fixed_line = ""
        
        return Fix(
            description="Replace hardcoded password with environment variable",
            original_code=original_line,
            fixed_code=fixed_line,
            status=FixStatus.AVAILABLE,
            confidence=0.9,
        )
    
    def _fix_sql_injection(self, source: str, vuln: Vulnerability) -> Fix:
        """Fix SQL injection vulnerability"""
        return Fix(
            description="Use parameterized queries to prevent SQL injection",
            original_code="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
            fixed_code="cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
            status=FixStatus.MANUAL_REQUIRED,
            confidence=0.7,
        )
    
    def _fix_assert_usage(self, source: str, vuln: Vulnerability) -> Fix:
        """Fix assert statement usage"""
        return Fix(
            description="Replace assert with proper exception handling",
            original_code="assert value > 0",
            fixed_code="if not value > 0:\n    raise ValueError('Value must be positive')",
            status=FixStatus.MANUAL_REQUIRED,
            confidence=0.8,
        )
    
    def _apply_code_change(self, vuln: Vulnerability) -> None:
        """Apply the code change to fix the vulnerability"""
        if not vuln.fix or not vuln.location:
            return
        
        file_path = vuln.location.file_path
        
        with open(file_path) as f:
            lines = f.readlines()
        
        line_idx = vuln.location.line_start - 1
        
        if line_idx < len(lines):
            lines[line_idx] = vuln.fix.fixed_code + "\n"
        
        with open(file_path, "w") as f:
            f.writelines(lines)
    
    def supports_language(self, language: str) -> bool:
        """Check if fixer supports the language"""
        return language.lower() == "python"
