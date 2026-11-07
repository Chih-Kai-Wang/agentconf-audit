import os
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _run_from_repo_root(monkeypatch):
    """Golden reports store fixture paths relative to the repository root."""
    monkeypatch.chdir(ROOT)
