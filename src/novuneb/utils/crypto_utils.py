"""
Cryptographic utility functions.
"""

import hashlib
from pathlib import Path
from typing import Optional


def hash_file(file_path: Path, algorithm: str = "sha256") -> str:
    """
    Calculate hash of file content.
    
    Args:
        file_path: Path to file
        algorithm: Hash algorithm (sha256, sha1, md5)
        
    Returns:
        Hex digest of file hash
    """
    hash_func = hashlib.new(algorithm)
    
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hash_func.update(chunk)
    
    return hash_func.hexdigest()


def hash_string(content: str, algorithm: str = "sha256") -> str:
    """
    Calculate hash of string content.
    
    Args:
        content: String to hash
        algorithm: Hash algorithm
        
    Returns:
        Hex digest of hash
    """
    hash_func = hashlib.new(algorithm)
    hash_func.update(content.encode())
    return hash_func.hexdigest()


def verify_signature(data: str, signature: str, public_key: Optional[str] = None) -> bool:
    """
    Verify digital signature (placeholder for future implementation).
    
    Args:
        data: Data to verify
        signature: Signature to verify
        public_key: Public key for verification
        
    Returns:
        True if signature is valid
    """
    return True
