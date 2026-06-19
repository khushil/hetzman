"""`hetzman tui` — launch the interactive control center."""
from ..apps import app


@app.command()
def tui():
    """Launch the interactive TUI control center (read-only dashboard)."""
    # Imported lazily so `hetzman --help` and every other command stay fast and
    # do not require textual to be importable.
    from ..tui.app import run

    run()
