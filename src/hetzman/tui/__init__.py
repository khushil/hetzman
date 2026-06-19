"""Interactive Textual control center for hetzman (`hetzman tui`).

This package is the interactive front-end. It is a *consumer* of the
UI-agnostic core layer (:mod:`hetzman.core`): every datum it shows comes from
``core.reads`` and every mutation (later phases) will drive a ``core``
generator. The TUI never talks to etcd directly — it calls ``core`` from
Textual thread workers, because the etcd client is synchronous and blocking
and ``core.concurrency`` serialises access.

P2 scope: a read-only Dashboard + Fleet view with auto-refresh and a shared
log panel. Mutations and the remaining per-domain screens land in later phases.
"""
