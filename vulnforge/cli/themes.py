"""Console themes and styles for VulnForge."""

from rich.theme import Theme

SECURITY_THEME = Theme(
    {
        "banner": "bold cyan",
        "title": "bold white on blue",
        "header": "bold cyan",
        "info": "dim cyan",
        "success": "bold green",
        "warning": "bold yellow",
        "error": "bold red",
        "scope.allowed": "bold green",
        "scope.blocked": "bold red",
        "stat.key": "bold white",
        "stat.val": "bold cyan",
        "url": "underline blue",
        "dim": "dim grey70",
    }
)
