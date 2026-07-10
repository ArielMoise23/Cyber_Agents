from pathlib import Path

WORDLISTS_DIR = Path(__file__).parent / "wordlists"

_FALLBACK_ADMIN_PATHS = [
    "/admin", "/administrator", "/login", "/wp-admin", "/wp-login.php",
    "/dashboard", "/panel", "/cpanel", "/phpmyadmin", "/manage",
]


def load_wordlist(name: str) -> list[str]:
    path = WORDLISTS_DIR / f"{name}.txt"
    if not path.exists():
        return list(_FALLBACK_ADMIN_PATHS)

    entries = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            entries.append(line)
    return entries or list(_FALLBACK_ADMIN_PATHS)
