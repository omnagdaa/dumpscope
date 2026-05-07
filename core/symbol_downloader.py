import os

def symbols_present(base_dir: str) -> bool:
    symbols_dir = os.path.join(base_dir, "symbols")
    if not os.path.isdir(symbols_dir):
        return False
    for root, dirs, files in os.walk(symbols_dir):
        for f in files:
            if f.endswith((".json", ".json.xz", ".json.gz", ".json.bz2")):
                return True
    return False


def get_vol3_cache_dir() -> str:
    try:
        from volatility3.framework import constants
        if hasattr(constants, "SYMBOL_BASEPATHS"):
            for p in constants.SYMBOL_BASEPATHS:
                if os.path.isdir(p):
                    return p
    except Exception:
        pass
    return os.path.expanduser("~/.cache/volatility3")


# Kept for import compatibility
class SymbolDownloader:
    pass
