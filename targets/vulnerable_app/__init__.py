"""AcmeCorp HelpBot — a deliberately vulnerable LLM app used to demo and test the scanner.

Three surfaces (chat, RAG, tool-using agent) with three defence levels (weak/medium/hardened).
By default the "model" is a deterministic simulation (no GPU, no downloads, reproducible);
set ``TARGET_BACKEND=ollama`` to put a real local model behind the same app.

WARNING: intentionally insecure. Everything runs against fake in-memory data, but never expose
it to a network you do not control.
"""

from targets.vulnerable_app.core import DemoApp, Level

__all__ = ["DemoApp", "Level"]
