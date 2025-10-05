"""
Base reporter interface for generating scan reports.
"""

from abc import ABC, abstractmethod
from pathlib import Path

from novuneb.core.models import ScanResult


class BaseReporter(ABC):
    """
    Abstract base class for all report generators.
    """
    
    def __init__(self, output_path: Path):
        """Initialize reporter with output path"""
        self.output_path = output_path
        self.format_name = self.__class__.__name__.replace("Reporter", "")
    
    @abstractmethod
    def generate(self, result: ScanResult) -> None:
        """
        Generate report from scan result.
        
        Args:
            result: ScanResult to report on
        """
        pass
    
    @abstractmethod
    def get_file_extension(self) -> str:
        """Get file extension for this report format"""
        pass
    
    def _ensure_output_dir(self) -> None:
        """Ensure output directory exists"""
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
