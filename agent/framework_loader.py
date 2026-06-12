"""
Framework mapping loader for EXHIBIT.

Loads control-to-system mappings from YAML files in frameworks/mappings/.
Validates all system names against the System enum at load time — typos
and stale references fail loud rather than silently routing to MANUAL.

Usage:
    from agent.framework_loader import get_framework_registry

    registry = get_framework_registry()
    systems = registry.lookup("soc2", "CC6.1")  # -> [System.OKTA, System.AWS, System.GITHUB]
    category = registry.category("soc2", "CC6.1")  # -> "Logical Access"
    framework = registry.detect(["CC6.1", "CC6.2", "CC7.1"])  # -> "soc2"
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .models import System

MAPPINGS_DIR = Path(__file__).parent.parent / "frameworks" / "mappings"


@dataclass
class FrameworkMapping:
    """A single framework's control-to-system mapping."""
    framework: str
    name: str
    description: str
    id_pattern: re.Pattern
    controls: dict[str, list[System]]
    categories: dict[str, str]  # control_id -> category

    def lookup(self, control_id: str) -> list[System]:
        """Look up systems for a control ID with prefix matching.

        Tries exact match first, then progressively shorter prefixes:
          CC6.1 -> CC6 -> CC
          8.25 -> 8
          GV.OC-1 -> GV.OC -> GV
        """
        candidates = [control_id]

        # Strip trailing sub-item indicators
        if "-" in control_id:
            candidates.append(control_id.rsplit("-", 1)[0])
        if "." in control_id:
            parts = control_id.split(".")
            # Try major.minor without patch
            if len(parts) >= 2:
                candidates.append(f"{parts[0]}.{parts[1]}")
            # Try major only
            candidates.append(parts[0])

        for candidate in candidates:
            if candidate in self.controls:
                return self.controls[candidate]

        return []

    def category(self, control_id: str) -> str | None:
        """Look up category for a control ID with same prefix matching."""
        candidates = [control_id]
        if "-" in control_id:
            candidates.append(control_id.rsplit("-", 1)[0])
        if "." in control_id:
            parts = control_id.split(".")
            if len(parts) >= 2:
                candidates.append(f"{parts[0]}.{parts[1]}")
            candidates.append(parts[0])

        for candidate in candidates:
            if candidate in self.categories:
                return self.categories[candidate]

        return None

    def matches_id(self, item_id: str) -> bool:
        """Check if an item ID matches this framework's pattern."""
        return bool(self.id_pattern.match(item_id.upper()))


class FrameworkRegistry:
    """Registry of all loaded framework mappings."""

    def __init__(self):
        self._frameworks: dict[str, FrameworkMapping] = {}
        self._load_all()

    def _load_all(self):
        """Load all YAML mapping files from the mappings directory."""
        if not MAPPINGS_DIR.exists():
            return

        for path in sorted(MAPPINGS_DIR.glob("*.yml")):
            self._load_file(path)

    def _load_file(self, path: Path):
        """Load and validate a single framework mapping file."""
        data = yaml.safe_load(path.read_text())

        framework_id = data["framework"]
        name = data.get("name", framework_id)
        description = data.get("description", "")
        id_pattern = re.compile(data.get("id_pattern", ".*"), re.IGNORECASE)

        controls: dict[str, list[System]] = {}
        categories: dict[str, str] = {}
        errors: list[str] = []

        for control_id, control_data in data.get("controls", {}).items():
            control_id = str(control_id)
            system_names = control_data.get("systems", [])
            category = control_data.get("category", "")

            systems = []
            for s_name in system_names:
                if s_name not in System._value2member_map_:
                    errors.append(f"  {control_id}: unknown system '{s_name}'")
                else:
                    systems.append(System(s_name))

            controls[control_id] = systems
            if category:
                categories[control_id] = category

        if errors:
            error_list = "\n".join(errors)
            raise ValueError(
                f"Invalid system names in {path.name}:\n{error_list}\n"
                f"Valid systems: {[s.value for s in System]}"
            )

        self._frameworks[framework_id] = FrameworkMapping(
            framework=framework_id,
            name=name,
            description=description,
            id_pattern=id_pattern,
            controls=controls,
            categories=categories,
        )

    @property
    def frameworks(self) -> list[str]:
        """List loaded framework IDs."""
        return list(self._frameworks.keys())

    def get(self, framework: str) -> FrameworkMapping | None:
        """Get a framework mapping by ID."""
        return self._frameworks.get(framework)

    def lookup(self, framework: str, control_id: str) -> list[System]:
        """Look up systems for a control in a specific framework."""
        mapping = self._frameworks.get(framework)
        if not mapping:
            return []
        return mapping.lookup(control_id)

    def category(self, framework: str, control_id: str) -> str | None:
        """Look up category for a control in a specific framework."""
        mapping = self._frameworks.get(framework)
        if not mapping:
            return None
        return mapping.category(control_id)

    def detect(self, item_ids: list[str]) -> str | None:
        """Detect which framework a set of item IDs belongs to.

        Scores each framework by how many IDs match its pattern,
        then returns the best match. This handles overlapping patterns
        (e.g. "500.2" matches both NYDFS and ISO numeric patterns)
        by preferring the framework with more specific matches.
        """
        scores: dict[str, int] = {}
        for framework_id, mapping in self._frameworks.items():
            # Count IDs that match pattern AND have a control defined
            pattern_matches = sum(1 for id_ in item_ids[:10] if mapping.matches_id(id_))
            control_matches = sum(1 for id_ in item_ids[:10] if mapping.lookup(id_))
            # Prefer control-level matches (more specific) over pattern-only
            scores[framework_id] = control_matches * 3 + pattern_matches

        if not scores:
            return None

        best = max(scores, key=scores.get)
        if scores[best] >= 2:
            return best
        return None


# Module-level singleton — loaded once on first import
_registry: FrameworkRegistry | None = None


def get_framework_registry() -> FrameworkRegistry:
    """Get the framework registry singleton (lazy-loaded)."""
    global _registry
    if _registry is None:
        _registry = FrameworkRegistry()
    return _registry
