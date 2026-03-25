import os
from pathlib import Path
from typing import List, Set, Pattern
import re

class SmartScanner:
    def __init__(self):
        self.ignore_patterns: Set[Pattern] = set()
        self.default_ignores = {
            r'\\.git/',
            r'__pycache__/',
            r'*.pyc$',
            r'*.pyo$',
            r'.DS_Store'
        }

    def add_ignore(self, pattern: str) -> None:
        """Add a regex pattern to ignore during scanning"""
        self.ignore_patterns.add(re.compile(pattern))

    def should_ignore(self, path: str) -> bool:
        """Check if a path matches any ignore patterns"""
        for pattern in self.ignore_patterns.union(self.default_ignores):
            if re.search(pattern, path):
                return True
        return False

    def scan(self, root_path: str, pattern: str = '*') -> List[Path]:
        """Recursively scan directory for files matching pattern
        
        Args:
            root_path: Starting directory path
            pattern: Glob pattern to match files against
            
        Returns:
            List of Path objects for matching files
        """
        root = Path(root_path)
        if not root.exists():
            raise FileNotFoundError(f"Path does not exist: {root_path}")

        results: List[Path] = []
        
        for path in root.rglob(pattern):
            rel_path = str(path.relative_to(root))
            
            if path.is_file() and not self.should_ignore(rel_path):
                results.append(path)
                
        return sorted(results)

    def scan_by_extension(self, root_path: str, extensions: List[str]) -> List[Path]:
        """Scan for files matching specific extensions
        
        Args:
            root_path: Starting directory path 
            extensions: List of file extensions to match (e.g. ['.py', '.js'])
            
        Returns:
            List of matching file paths
        """
        results: List[Path] = []
        for ext in extensions:
            if not ext.startswith('.'):
                ext = f'.{ext}'
            results.extend(self.scan(root_path, f'*{ext}'))
        return sorted(results)

    def scan_content(self, root_path: str, pattern: str) -> List[Path]:
        """Scan files and match against content
        
        Args:
            root_path: Starting directory path
            pattern: Regex pattern to match file content
            
        Returns:
            List of files containing matching content
        """
        results: List[Path] = []
        content_pattern = re.compile(pattern)

        for file_path in self.scan(root_path):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if content_pattern.search(content):
                        results.append(file_path)
            except UnicodeDecodeError:
                continue
                
        return results

# Convenience function to create scanner instance
def create_scanner() -> SmartScanner:
    return SmartScanner()