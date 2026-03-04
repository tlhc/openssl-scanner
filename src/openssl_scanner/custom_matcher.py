"""Custom pattern matching for non-OpenSSL library detection in ELF binaries.

Scans .dynsym UND symbols and .rodata strings against user-defined pattern
groups (e.g., openHiTLS, wolfSSL). Runs independently from OpenSSL detection.
"""

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class CustomMatch:
    """A single pattern match in an ELF file."""
    file: str
    group: str
    pattern: str
    location: str


@dataclass
class CustomResult:
    """Aggregated custom pattern matches for a package."""
    matches: Dict[str, Set[str]] = field(default_factory=dict)
    details: List[CustomMatch] = field(default_factory=list)

    def summary_text(self):
        """Format matches as 'groupA (N), groupB (M)'."""
        parts = []
        for group in sorted(self.matches):
            count = len(self.matches[group])
            if count > 0:
                parts.append(f'{group} ({count})')
        return ', '.join(parts)

    @property
    def has_matches(self):
        return any(len(v) > 0 for v in self.matches.values())


class CustomMatcher:
    """Match ELF symbols and strings against custom pattern groups."""

    def __init__(self):
        self.groups: Dict[str, Set[str]] = {}
        self.all_patterns: Set[str] = set()

    def _rebuild_all_patterns(self):
        self.all_patterns = set()
        for syms in self.groups.values():
            self.all_patterns.update(syms)

    def load_patterns(self, path=None):
        """Load pattern groups from JSON file.

        Args:
            path: Path to JSON file. If None, uses built-in data file.

        Returns:
            Total number of patterns loaded.
        """
        if path is None:
            path = os.path.join(
                os.path.dirname(__file__), 'data', 'custom_patterns.json')

        try:
            with open(path, 'r') as f:
                data = json.load(f)
        except (IOError, OSError, json.JSONDecodeError) as e:
            logger.debug("Cannot load custom patterns from %s: %s", path, e)
            self.groups = {}
            self.all_patterns = set()
            return 0

        groups = data.get('groups', {})
        if not isinstance(groups, dict):
            logger.warning("Invalid 'groups' in %s: expected dict, got %s",
                           path, type(groups).__name__)
            self.groups = {}
            self.all_patterns = set()
            return 0
        self.groups = {}
        for name, syms in groups.items():
            if not isinstance(syms, list):
                logger.warning("Skipping group '%s': expected list, got %s",
                               name, type(syms).__name__)
                continue
            self.groups[name] = set(syms)
        self._rebuild_all_patterns()
        return len(self.all_patterns)

    def match_strings(self, strings):
        """Match a set of strings against all pattern groups.

        Args:
            strings: Set of strings to match.

        Returns:
            Dict mapping group name to set of matched patterns.
        """
        result = {}
        for group, patterns in self.groups.items():
            result[group] = patterns & strings
        return result

    def match_to_result(self, matched_symbols):
        """Convert a flat set of matched symbols into grouped CustomResult.

        Used after piggybacked custom matching in _analyze_file_worker
        to build a CustomResult without any ELF I/O.

        Args:
            matched_symbols: Set of pattern strings already matched
                against ELF UND/DEF symbols and rodata.

        Returns:
            CustomResult with matches grouped by pattern group.
        """
        result = CustomResult()
        if not matched_symbols:
            return result
        for group, patterns in self.groups.items():
            group_hits = patterns & matched_symbols
            if group_hits:
                result.matches[group] = group_hits
        return result

    def scan_file(self, elf_path):
        """Scan a single ELF file for custom patterns.

        Searches .dynsym UND symbols, .dynsym DEF symbols (static linking),
        and .rodata strings.

        Args:
            elf_path: Path to ELF binary.

        Returns:
            Tuple of (file_matches, details) where file_matches is a dict
            mapping group name to set of matched patterns, and details is
            a list of CustomMatch objects.
        """
        if not self.all_patterns:
            return {g: set() for g in self.groups}, []

        from .elf_analyzer import ELFAnalyzer, extract_rodata_strings

        analyzer = ELFAnalyzer()
        und_syms = set(analyzer.get_undefined_symbols(elf_path))
        def_syms = set(analyzer.get_defined_symbols(elf_path))
        rodata_strings = extract_rodata_strings(elf_path)

        und_matches = und_syms & self.all_patterns
        def_matches = def_syms & self.all_patterns
        rodata_matches = rodata_strings & self.all_patterns

        file_matches = {}
        details = []
        basename = os.path.basename(elf_path)

        for group, patterns in self.groups.items():
            group_und = patterns & und_matches
            group_def = (patterns & def_matches) - group_und
            already = group_und | group_def
            group_rodata = (patterns & rodata_matches) - already
            file_matches[group] = already | group_rodata

            for p in sorted(group_und):
                details.append(
                    CustomMatch(basename, group, p, 'dynsym_und'))
            for p in sorted(group_def):
                details.append(
                    CustomMatch(basename, group, p, 'dynsym_def'))
            for p in sorted(group_rodata):
                details.append(
                    CustomMatch(basename, group, p, 'rodata'))

        return file_matches, details

    def scan_directory(self, extract_dir):
        """Scan all .so files in a directory for custom patterns.

        Args:
            extract_dir: Directory containing extracted .so files.

        Returns:
            CustomResult with aggregated matches.
        """
        result = CustomResult()
        if not self.all_patterns:
            return result

        for dirpath, _dirs, filenames in os.walk(extract_dir):
            for fname in filenames:
                if not fname.endswith('.so') and '.so.' not in fname:
                    continue
                fpath = os.path.join(dirpath, fname)
                try:
                    file_matches, file_details = self.scan_file(fpath)
                except Exception as e:
                    logger.debug("Custom scan error on %s: %s", fname, e)
                    continue

                for group, matched in file_matches.items():
                    if group not in result.matches:
                        result.matches[group] = set()
                    result.matches[group].update(matched)
                result.details.extend(file_details)

        return result
