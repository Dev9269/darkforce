__version__ = "0.1.0"

__all__ = ["stylometry"]

# Backwards-compatible alias: the module implementing author stylometry is
# darkforce.stylo, but public docs/AI references historically say "stylometry".
def __getattr__(name):
    if name == "stylometry":
        from importlib import import_module

        return import_module(f"{__name__}.stylo")
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")