"""
JSON report generator.
"""

import json
from pathlib import Path

from novuneb.core.models import ScanResult
from novuneb.reporters.base import BaseReporter


class JSONReporter(BaseReporter):
    """
    Generate JSON format reports for easy parsing and integration.
    """
    
    def generate(self, result: ScanResult) -> None:
        """Generate JSON report"""
        self._ensure_output_dir()
        
        report_data = result.to_dict()
        
        with open(self.output_path, "w") as f:
            json.dump(report_data, f, indent=2, default=str)
    
    def get_file_extension(self) -> str:
        """Get file extension"""
        return ".json"
