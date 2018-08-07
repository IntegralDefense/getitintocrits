import os

_current_dir = os.path.abspath(os.path.dirname(__file__))
INTEL_HOME = os.path.normpath(os.path.join(_current_dir, "../.."))
IOC_HOME = os.path.normpath(os.path.join(_current_dir, "../../lib/ioc-parser"))
