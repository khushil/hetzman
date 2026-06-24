"""`hetzman tui` — launch the interactive control center."""
from ..apps import app


@app.command()
def tui():
    """Launch the interactive control center (create/resize/reboot VMs+containers,
    DNS/IP/port records, fleet updates+reboots). Press Ctrl+P for all actions."""
    # Imported lazily so `hetzman --help` and every other command stay fast and
    # do not require textual to be importable.
    from ..tui.app import run

    run()
