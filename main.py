"""PyInstaller entry point. Kept at repo root and separate from cli.py so
`pyinstaller --onefile main.py -n cxone-ai-triage` has a single, stable target.
"""
import sys

from cxone_ai_triage.cli import main

if __name__ == "__main__":
    sys.exit(main())
