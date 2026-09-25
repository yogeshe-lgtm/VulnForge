"""VulnForge main executable entrypoint."""

import sys
from vulnforge.cli.main import app


def main() -> None:
    """Run the VulnForge CLI application."""
    try:
        app()
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
