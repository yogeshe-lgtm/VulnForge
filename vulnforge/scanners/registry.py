"""Registry and plugin discovery for scanner modules."""

from typing import Dict, List, Optional, Set, Type, Union

from vulnforge.scanners.base import BaseScanner
from vulnforge.scanners.exceptions import ScannerRegistrationError


class ScannerRegistry:
    """Central registry of all available assessment and analysis modules."""

    _registry: Dict[str, BaseScanner] = {}

    @classmethod
    def register(cls, scanner: Union[BaseScanner, Type[BaseScanner]]) -> None:
        """Register a scanner instance or class.

        Args:
            scanner: BaseScanner instance or subclass.

        Raises:
            ScannerRegistrationError: If scanner is invalid or has empty name.
        """
        instance = scanner() if isinstance(scanner, type) else scanner
        if not isinstance(instance, BaseScanner):
            raise ScannerRegistrationError(f"Cannot register non-BaseScanner object: {scanner}")

        name = instance.name.strip().lower()
        if not name:
            raise ScannerRegistrationError("Scanner name cannot be empty.")

        cls._registry[name] = instance

    @classmethod
    def unregister(cls, name: str) -> bool:
        """Remove a scanner from the registry."""
        normalized = name.strip().lower()
        if normalized in cls._registry:
            del cls._registry[normalized]
            return True
        return False

    @classmethod
    def get(cls, name: str) -> Optional[BaseScanner]:
        """Retrieve a registered scanner by name."""
        return cls._registry.get(name.strip().lower())

    @classmethod
    def list_all(cls) -> List[BaseScanner]:
        """Return all registered scanners."""
        return list(cls._registry.values())

    @classmethod
    def list(cls) -> List[BaseScanner]:
        """Alias for list_all()."""
        return cls.list_all()

    @classmethod
    def filter(
        cls,
        include: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
    ) -> List[BaseScanner]:
        """Filter registered scanners based on include/exclude patterns (supports comma-separated names & categories).

        Args:
            include: Optional list/strings of scanner names or categories to selectively run.
            exclude: Optional list/strings of scanner names or categories to skip.

        Returns:
            Filtered list of BaseScanner instances.
        """
        all_scanners = cls.list_all()

        def parse_tokens(items: Optional[List[str]]) -> Set[str]:
            tokens = set()
            if not items:
                return tokens
            for item in items:
                if not item:
                    continue
                for part in str(item).split(","):
                    cleaned = part.strip().lower()
                    if cleaned:
                        tokens.add(cleaned)
            return tokens

        include_tokens = parse_tokens(include)
        exclude_tokens = parse_tokens(exclude)

        if include_tokens:
            filtered = [
                s for s in all_scanners
                if s.name.lower() in include_tokens or s.category.lower() in include_tokens
            ]
        else:
            filtered = list(all_scanners)

        if exclude_tokens:
            filtered = [
                s for s in filtered
                if s.name.lower() not in exclude_tokens and s.category.lower() not in exclude_tokens
            ]

        return filtered

    @classmethod
    def clear(cls) -> None:
        """Clear all registered scanners (useful in testing)."""
        cls._registry.clear()
