"""Make the single-file agent importable as ``opnsense_agent`` from these tests."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
