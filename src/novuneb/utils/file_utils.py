"""
File utility functions.
"""

from pathlib import Path
from typing import Iterator, Optional


def find_files(
    directory: Path,
    pattern: str = "*",
    exclude_patterns: Optional[list[str]] = None
) -> Iterator[Path]:
    """
    Find files matching pattern in directory.
    
    Args:
        directory: Directory to search
        pattern: Glob pattern to match
        exclude_patterns: Patterns to exclude
        
    Yields:
        Path objects for matching files
    """
    exclude_patterns = exclude_patterns or []
    
    for file_path in directory.rglob(pattern):
        if file_path.is_file():
            if not any(
                exclude in str(file_path)
                for exclude in exclude_patterns
            ):
                yield file_path


def read_file(file_path: Path, encoding: str = "utf-8") -> str:
    """
    Read file content safely.
    
    Args:
        file_path: Path to file
        encoding: File encoding
        
    Returns:
        File content as string
    """
    with open(file_path, encoding=encoding) as f:
        return f.read()


def write_file(file_path: Path, content: str, encoding: str = "utf-8") -> None:
    """
    Write content to file safely.
    
    Args:
        file_path: Path to file
        content: Content to write
        encoding: File encoding
    """
    file_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(file_path, "w", encoding=encoding) as f:
        f.write(content)


def get_file_extension(file_path: Path) -> str:
    """Get file extension without dot"""
    return file_path.suffix.lstrip(".")


def is_text_file(file_path: Path) -> bool:
    """Check if file is a text file"""
    text_extensions = {
        "py", "js", "ts", "jsx", "tsx", "java", "go", "rb", "php",
        "c", "cpp", "h", "hpp", "cs", "rs", "swift", "kt",
        "html", "css", "scss", "sass", "less",
        "json", "yaml", "yml", "toml", "xml",
        "txt", "md", "rst",
    }
    
    return get_file_extension(file_path) in text_extensions
