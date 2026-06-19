"""UI-agnostic core layer for hetzman.

This package holds the pure, presentation-free building blocks that operations
are composed from: the typed error hierarchy (:mod:`hetzman.core.errors`), the
progress/result contract (:mod:`hetzman.core.events`) and small privilege
helpers (:mod:`hetzman.core.privilege`).

Nothing here knows about Rich, the console, argparse or any other front-end.
Consumers import submodules explicitly (e.g. ``from hetzman.core import events``)
so that importing the package never triggers import-time side effects.
"""
