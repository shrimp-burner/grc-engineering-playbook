import importlib
import pkgutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import grc_playbook


def test_every_module_imports():
    # A syntax error or bad import in ANY module fails here, even one nothing else
    # imports. This is the guard that would have caught the grc_api docstring break
    # that pytest previously sailed past.
    pkg_dir = Path(grc_playbook.__file__).parent
    names = [m.name for m in pkgutil.iter_modules([str(pkg_dir)]) if m.name != "__main__"]
    assert names, "no modules discovered"
    for name in names:
        importlib.import_module("grc_playbook." + name)
