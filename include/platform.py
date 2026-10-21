"""Portable runtime constants corresponding to include/platform.h."""
import os, sys
IS_WINDOWS = os.name == 'nt'
IS_LINUX = sys.platform.startswith('linux')
IS_MACOS = sys.platform == 'darwin'
PYTHON_VERSION = sys.version_info[:3]
