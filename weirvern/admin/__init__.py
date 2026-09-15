"""Weirvern admin: CLI, TUI, config I/O, and runtime control.

Kept separate from the data-plane (ingest/detect) so an operator workstations
does not need the ML dependencies, and so the control plane can be reasoned
about without loading scikit-learn.
"""
