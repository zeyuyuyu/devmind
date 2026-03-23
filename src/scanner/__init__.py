'''Edge Code Quality Scanner Module.

This module provides a production‑ready code quality scanner suitable for
integration into the Swarming‑Hive orchestration pipeline. It can run a suite of
static analysis tools (pylint, flake8, bandit, black, radon, mypy) on a list of
source files, caches results based on file content hashes, and returns a structured
JSON report.

Usage:
    from src.scanner import EdgeCodeQualityScanner, ScanConfig

    config = ScanConfig()
    scanner = EdgeCodeQualityScanner(config)
    # Scan specific files
    result = asyncio.run(scanner.scan_files(['src/main.py', 'src/orchestrator.py']))
    print(scanner.generate_report(result))

    # Or use the high‑level run() method that accepts a task dict as defined
    # in the orchestrator.
    task = {
        'source_files': ['src/main.py', 'src/orchestrator.py'],
        'options': {}
    }
    report = asyncio.run(scanner.run(task))
    print(report['report'])
'''

import asyncio
import fnmatch
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from dataclasses import dataclass, field
from dataclasses import asdict


class Severity(Enum):
    INFO = 'info'
    WARNING = 'warning'
    ERROR = 'error'
    CRITICAL = 'critical'


@dataclass
class Issue:
    file: str
    line: int
    column: int
    severity: Severity
    tool: str
    code: str
    message: str


@dataclass
class ToolResult:
    tool: str
    passed: bool
    issues: List[Issue] = field(default_factory=list)
    duration: float = 0.0
    error: Optional[str] = None


@dataclass
class OverallResult:
    overall_pass: bool
    total_issues: int
    issues_by_severity: Dict[str, int]
    tool_results: List[ToolResult] = field(default_factory=list)
    cache_hit: bool = False
    duration: float = 0.0


@dataclass
class ScanConfig:
    enabled_tools: List[str] = field(
        default_factory=lambda: ['pylint', 'flake8', 'bandit', 'black', 'radon', 'mypy']
    )
    exclude_patterns: List[str] = field(
        default_factory=lambda: ['*.pyc', '__pycache__', '.git', '.tox', '*.egg-info']
    )
    thresholds: Dict[str, int] = field(
        default_factory=lambda: {
            'critical': 0,
            'error': 0,
            'warning': 10,
            'info': 100,
            'radon_max_complexity': 10,
        }
    )
    cache_dir: Path = field(default_factory=lambda: Path('.scanner_cache'))
    concurrency: int = 4
    timeout: int = 120
    log_level: str = 'INFO'


def _serialize_tool_result(tr: ToolResult) -> Dict[str, Any]:
    return {
        'tool': tr.tool,
        'passed': tr.passed,
        'duration': tr.duration,
        'error': tr.error,
        'issues': [
            {
                'file': i.file,
                'line': i.line,
                'column': i.column,
                'severity': i.severity.value,
                'tool': i.tool,
                'code': i.code,
                'message': i.message,
            }
            for i in tr.issues
        ],
    }


def _deserialize_tool_result(data: Dict[str, Any]) -> ToolResult:
    issues = [
        Issue(
            file=issue['file'],
            line=issue['line'],
            column=issue['column'],
            severity=Severity(issue['severity']),
            tool=issue['tool'],
            code=issue['code'],
            message=issue['message'],
        )
        for issue in data.get('issues', [])
    ]
    return ToolResult(
        tool=data['tool'],
        passed=data['passed'],
        issues=issues,
        duration=data.get('duration', 0.0),
        error=data.get('error'),
    )


class EdgeCodeQualityScanner:
    """High‑level scanner that orchestrates multiple static analysis tools.

    The scanner is designed to be used either as a standalone command line
    utility or as a component of the Swarming‑Hive orchestrator. It supports
    caching, concurrency, and a configurable set of tools.

    Parameters
    ----------
    config : ScanConfig, optional
        Configuration object. If omitted, default values are used.

    Attributes
    ----------
    config : ScanConfig
        Active configuration.
    """

    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config or ScanConfig()
        self._setup_logging()
        self._tool_available = self._detect_tools()
        self._cache_dir = self.config.cache_dir
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._semaphore = asyncio.Semaphore(self.config.concurrency)

    # ----------------------------------------------------------------------
    # Public API
    # ----------------------------------------------------------------------

    async def scan_files(self, file_paths: List[Path]) -> OverallResult:
        """Scan a list of source files with the configured tools.

        Parameters
        ----------
        file_paths : List[Path]
            Files to scan.

        Returns
        -------
        OverallResult
            Aggregated scan result.
        """
        start_time = time.time()
        cache_hit = False
        all_issues: List[Issue] = []
        tool_results: List[ToolResult] = []

        # Filter and resolve files
        files_to_scan: List[Path] = []
        for fp in file_paths:
            if not fp.is_file():
                continue
            if any(fnmatch.fnmatch(str(fp), pat) for pat in self.config.exclude_patterns):
                continue
            files_to_scan.append(fp)

        # Prepare scanning tasks
        tasks: List[asyncio.Task] = []
        for fp in files_to_scan:
            cached = self._load_cached_results(fp)
            if cached is not None:
                # Re‑use cached results
                for tr in cached:
                    tool_results.append(tr)
                    all_issues.extend(tr.issues)
                cache_hit = True
            else:
                # Schedule tools for this file
                for tool in self.config.enabled_tools:
                    if self._tool_available.get(tool, False):
                        tasks.append(asyncio.create_task(self._run_tool_async(tool, fp)))
                    else:
                        logging.debug('Tool %s not available, skipping.', tool)

        # Execute all pending tasks
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if isinstance(res, Exception):
                    logging.error('Tool task raised exception: %s', res)
                    continue
                if isinstance(res, ToolResult):
                    tool_results.append(res)
                    all_issues.extend(res.issues)

        # Tally issues by severity
        issues_by_severity: Dict[str, int] = {s.value: 0 for s in Severity}
        for issue in all_issues:
            issues_by_severity[issue.severity.value] = issues_by_severity.get(issue.severity.value, 0) + 1

        # Determine overall pass based on thresholds
        overall_pass = True
        for sev, count in issues_by_severity.items():
            threshold = self.config.thresholds.get(sev, None)
            if threshold is not None and count > threshold:
                overall_pass = False
                break

        duration = time.time() - start_time
        return OverallResult(
            overall_pass=overall_pass,
            total_issues=len(all_issues),
            issues_by_severity=issues_by_severity,
            tool_results=tool_results,
            cache_hit=cache_hit,
            duration=duration,
        )

    async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """High‑level entry point used by the orchestrator.

        Parameters
        ----------
        task : Dict[str, Any]
            Orchestrator task dictionary. Expected keys:
                - source_files: List[str] paths to source files.
                - options: optional dict to override the scanner configuration.

        Returns
        -------
        Dict[str, Any]
            Dictionary containing summary fields and a full JSON report.
        """
        source_files = [Path(p) for p in task.get('source_files', [])]
        overall = await self.scan_files(source_files)
        report = self.generate_report(overall)
        return {
            'overall_pass': overall.overall_pass,
            'total_issues': overall.total_issues,
            'issues_by_severity': overall.issues_by_severity,
            'cache_hit': overall.cache_hit,
            'duration': overall.duration,
            'report': report,
        }

    def generate_report(self, result: OverallResult) -> str:
        """Convert an OverallResult into a JSON string."""
        report_dict = {
            'overall_pass': result.overall_pass,
            'total_issues': result.total_issues,
            'issues_by_severity': result.issues_by_severity,
            'cache_hit': result.cache_hit,
            'duration': result.duration,
            'tool_results': [
                {
                    'tool': tr.tool,
                    'passed': tr.passed,
                    'duration': tr.duration,
                    'error': tr.error,
                    'issues': [
                        {
                            'file': i.file,
                            'line': i.line,
                            'column': i.column,
                            'severity': i.severity.value,
                            'code': i.code,
                            'message': i.message,
                        }
                        for i in tr.issues
                    ],
                }
                for tr in result.tool_results
            ],
        }
        return json.dumps(report_dict, indent=2)

    # ----------------------------------------------------------------------
    # Private helpers
    # ----------------------------------------------------------------------

    def _setup_logging(self):
        logging.basicConfig(
            level=getattr(logging, self.config.log_level, logging.INFO),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
        )

    def _detect_tools(self) -> Dict[str, bool]:
        available = {}
        for tool in self.config.enabled_tools:
            path = shutil.which(tool)
            available[tool] = path is not None
            if not available[tool]:
                logging.debug('Tool %s not found in PATH', tool)
        return available

    def _compute_file_hash(self, fp: Path) -> str:
        sha256 = hashlib.sha256()
        sha256.update(fp.read_bytes())
        return sha256.hexdigest()

    def _load_cached_results(self, fp: Path) -> Optional[List[ToolResult]]:
        file_hash = self._compute_file_hash(fp)
        cache_file = self._cache_dir / f'{file_hash}.json'
        if cache_file.is_file():
            try:
                data = json.loads(cache_file.read_text())
                return [_deserialize_tool_result(d) for d in data]
            except Exception as e:
                logging.warning('Failed to load cache for %s: %s', fp, e)
        return None

    def _save_cached_results(self, fp: Path, results: List[ToolResult]) -> None:
        file_hash = self._compute_file_hash(fp)
        cache_file = self._cache_dir / f'{file_hash}.json'
        try:
            cache_file.write_text(json.dumps([_serialize_tool_result(r) for r in results], indent=2))
        except Exception as e:
            logging.warning('Failed to save cache for %s: %s', fp, e)

    async def _run_tool_async(self, tool: str, fp: Path) -> ToolResult:
        start_time = time.time()
        try:
            if tool == 'pylint':
                cmd = [
                    'pylint',
                    '--msg-template',
                    '{line}:{column}: {category}: {msg} ({symbol})',
                    str(fp),
                ]
            elif tool == 'flake8':
                cmd = [
                    'flake8',
                    '--format={line}:{column}: {category} {msg}',
                    str(fp),
                ]
            elif tool == 'bandit':
                cmd = ['bandit', '-f', 'json', str(fp)]
            elif tool == 'black':
                cmd = ['black', '--check', '--quiet', str(fp)]
            elif tool == 'radon':
                cmd = ['radon', 'cc', '-j', str(fp)]
            elif tool == 'mypy':
                cmd = ['mypy', str(fp)]
            else:
                raise ValueError(f'Unknown tool: {tool}')

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=fp.parent,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=self.config.timeout
            )
            duration = time.time() - start_time
            stdout = stdout_bytes.decode('utf-8', errors='replace')
            stderr = stderr_bytes.decode('utf-8', errors='replace')
            issues = self._parse_tool_output(tool, stdout, stderr)
            passed = (proc.returncode == 0) and (len(issues) == 0)
            # If tool returned non‑zero but we parsed issues, treat as failed as well.
            if not passed and len(issues) == 0:
                # Some tools (e.g., black) return non‑zero even when only formatting issues.
                # In that case we treat as failure anyway.
                passed = False
            return ToolResult(tool=tool, passed=passed, issues=issues, duration=duration)

        except asyncio.TimeoutError:
            duration = time.time() - start_time
            return ToolResult(
                tool=tool, passed=False, issues=[], duration=duration, error='Timeout'
            )
        except Exception as e:
            duration = time.time() - start_time
            return ToolResult(
                tool=tool, passed=False, issues=[], duration=duration, error=str(e)
            )

    def _parse_tool_output(self, tool: str, stdout: str, stderr: str) -> List[Issue]:
        if tool == 'pylint':
            return self._parse_pylint(stdout)
        elif tool == 'flake8':
            return self._parse_flake8(stdout)
        elif tool == 'bandit':
            return self._parse_bandit(stdout)
        elif tool == 'black':
            return self._parse_black(stdout, stderr)
        elif tool == 'radon':
            return self._parse_radon(stdout)
        elif tool == 'mypy':
            return self._parse_mypy(stdout)
        return []

    # ----------------------------------------------------------------------
    # Individual parsers
    # ----------------------------------------------------------------------

    def _parse_pylint(self, output: str) -> List[Issue]:
        issues = []
        for line in output.splitlines():
            if not line.strip():
                continue
            parts = line.split(':', 3)
            if len(parts) < 4:
                continue
            try:
                file_path = parts[0]
                line_no = int(parts[1])
                column = int(parts[2])
                rest = parts[3]
                # Format: 'Category: Message (symbol)'
                category_msg = rest.rsplit('(', 1)
                if len(category_msg) == 2:
                    category = category_msg[0].strip()
                    message = category_msg[1].rstrip(')')
                    symbol = message
                else:
                    category = rest
                    message = ''
                    symbol = ''
                severity = self._category_to_severity(category)
                issues.append(
                    Issue(
                        file=file_path,
                        line=line_no,
                        column=column,
                        severity=severity,
                        tool='pylint',
                        code=symbol,
                        message=message,
                    )
                )
            except Exception:
                logging.debug('Failed to parse pylint line: %s', line)
        return issues

    def _category_to_severity(self, category: str) -> Severity:
        first = category[0].upper() if category else ''
        mapping = {'C': Severity.INFO, 'R': Severity.INFO, 'W': Severity.WARNING, 'E': Severity.ERROR, 'F': Severity.CRITICAL}
        return mapping.get(first, Severity.INFO)

    def _parse_flake8(self, output: str) -> List[Issue]:
        issues = []
        for line in output.splitlines():
            if not line.strip():
                continue
            parts = line.split(':', 3)
            if len(parts) < 4:
                continue
            try:
                file_path = parts[0]
                line_no = int(parts[1])
                column = int(parts[2])
                code_msg = parts[3].strip()
                code = ''
                message = code_msg
                if ' ' in code_msg:
                    code, message = code_msg.split(' ', 1)
                severity = self._code_to_severity(code)
                issues.append(
                    Issue(
                        file=file_path,
                        line=line_no,
                        column=column,
                        severity=severity,
                        tool='flake8',
                        code=code,
                        message=message,
                    )
                )
            except Exception:
                logging.debug('Failed to parse flake8 line: %s', line)
        return issues

    def _code_to_severity(self, code: str) -> Severity:
        if not code:
            return Severity.INFO
        first = code[0].upper()
        if first == 'E':
            return Severity.ERROR
        if first == 'W':
            return Severity.WARNING
        if first == 'C':
            return Severity.INFO
        return Severity.INFO

    def _parse_bandit(self, output: str) -> List[Issue]:
        issues = []
        try:
            data = json.loads(output)
            results = data.get('results', data) if isinstance(data, dict) else data
            for r in results:
                severity_str = r.get('severity', 'LOW')
                severity = self._bandit_severity(severity_str)
                issues.append(
                    Issue(
                        file=r.get('filename', ''),
                        line=r.get('line', 0),
                        column=0,
                        severity=severity,
                        tool='bandit',
                        code=r.get('test_id', ''),
                        message=r.get('issue_text', ''),
                    )
                )
        except Exception as e:
            logging.debug('Failed to parse bandit output: %s', e)
        return issues

    def _bandit_severity(self, severity_str: str) -> Severity:
        mapping = {'LOW': Severity.INFO, 'MEDIUM': Severity.WARNING, 'HIGH': Severity.ERROR, 'CRITICAL': Severity.CRITICAL}
        return mapping.get(severity_str.upper(), Severity.INFO)

    def _parse_black(self, stdout: str, stderr: str) -> List[Issue]:
        issues = []
        combined = stdout + '\n' + stderr
        for line in combined.splitlines():
            lower_line = line.lower()
            if 'would reformat' in lower_line or 'reformat' in lower_line:
                # Example: "Would reformat /path/to/file.py"
                parts = line.split('reformat', 1)
                if len(parts) < 2:
                    continue
                file_path = parts[1].strip()
                issues.append(
                    Issue(
                        file=file_path,
                        line=1,
                        column=0,
                        severity=Severity.WARNING,
                        tool='black',
                        code='format',
                        message='File is not properly formatted.',
                    )
                )
            if 'error' in lower_line:
                issues.append(
                    Issue(
                        file='',
                        line=0,
                        column=0,
                        severity=Severity.ERROR,
                        tool='black',
                        code='error',
                        message=line,
                    )
                )
        return issues

    def _parse_radon(self, output: str) -> List[Issue]:
        issues = []
        try:
            data = json.loads(output)
            max_complexity = self.config.thresholds.get('radon_max_complexity', 10)
            for item in data:
                if isinstance(item, dict):
                    complexity = item.get('complexity', 0)
                    if complexity > max_complexity:
                        issues.append(
                            Issue(
                                file=item.get('file', ''),
                                line=item.get('lineno', 0),
                                column=item.get('col_offset', 0),
                                severity=Severity.WARNING,
                                tool='radon',
                                code=f'CC{complexity}',
                                message=f'Cyclomatic complexity {complexity} exceeds threshold {max_complexity}.',
                            )
                        )
        except Exception as e:
            logging.debug('Failed to parse radon output: %s', e)
        return issues

    def _parse_mypy(self, output: str) -> List[Issue]:
        issues = []
        for line in output.splitlines():
            if not line.strip():
                continue
            # Format: "file:line: [severity] message"
            parts = line.split(':', 3)
            if len(parts) < 3:
                continue
            try:
                file_path = parts[0]
                line_no = int(parts[1])
                rest = parts[2].strip()
                severity = Severity.ERROR if 'error' in rest else Severity.WARNING
                message = parts[3].strip() if len(parts) > 3 else rest
                issues.append(
                    Issue(
                        file=file_path,
                        line=line_no,
                        column=0,
                        severity=severity,
                        tool='mypy',
                        code='type',
                        message=message,
                    )
                )
            except Exception:
                logging.debug('Failed to parse mypy line: %s', line)
        return issues


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Edge Code Quality Scanner')
    parser.add_argument(
        'files',
        nargs='*',
        type=Path,
        default=None,
        help='Source files to scan. If omitted, defaults to all .py files under src/.',
    )
    parser.add_argument(
        '--config',
        type=Path,
        default=None,
        help='Path to a JSON configuration file.',
    )
    parser.add_argument(
        '--output',
        type=Path,
        default=None,
        help='Path to write the JSON report.',
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable debug logging.',
    )
    args = parser.parse_args()

    log_level = 'DEBUG' if args.verbose else 'INFO'

    # Build configuration – start from defaults then override from file
    config = ScanConfig()
    if args.config and args.config.is_file():
        try:
            config_data = json.loads(args.config.read_text())
            for key, value in config_data.items():
                if hasattr(config, key):
                    setattr(config, key, value)
        except Exception as e:
            print(f'Failed to load config file: {e}', file=sys.stderr)
            sys.exit(1)

    # Override log level if set via args (even if config file already sets a level)
    config.log_level = log_level

    scanner = EdgeCodeQualityScanner(config)

    # Determine file list
    if args.files:
        files = args.files
    else:
        # Default: scan all .py files under src/
        src_dir = Path('src')
        if src_dir.is_dir():
            files = list(src_dir.rglob('*.py'))
        else:
            files = list(Path('.').rglob('*.py'))

    result = asyncio.run(scanner.scan_files(files))
    report = scanner.generate_report(result)

    if args.output:
        args.output.write_text(report)
        print(f'Report written to {args.output}')
    else:
        print(report)

    # Exit code reflects the overall pass/fail status
    sys.exit(0 if result.overall_pass else 1)


if __name__ == '__main__':
    main()
