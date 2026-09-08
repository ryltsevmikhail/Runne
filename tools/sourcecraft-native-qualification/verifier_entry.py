#!/usr/bin/python3 -I
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from verifier import main
raise SystemExit(main(sys.argv[1:]))
