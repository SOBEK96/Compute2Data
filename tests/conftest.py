import sys
import os
import importlib.util

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TEST_DIR = os.path.join(_ROOT, "test")
if _TEST_DIR not in sys.path:
    sys.path.insert(0, _TEST_DIR)

_TEST_CONFTEST = os.path.join(_TEST_DIR, "conftest.py")
spec = importlib.util.spec_from_file_location("test_conftest", _TEST_CONFTEST)
test_conftest = importlib.util.module_from_spec(spec)
sys.modules["test_conftest"] = test_conftest
spec.loader.exec_module(test_conftest)

for attr in dir(test_conftest):
    if not attr.startswith("__"):
        globals()[attr] = getattr(test_conftest, attr)
