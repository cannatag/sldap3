EXEC_PROCESS = 'PROCESS'
EXEC_THREAD = 'THREAD'
import sys
import platform

if platform.system() == 'Windows':
    sys.stderr = open('C:\\Temp\\pyasn1.log', 'w+')  # patch for pyasn1 without access to stderr

from .version import __author__, __version__, __email__, __description__, __status__, __license__, __url__

from .core.dsa import Dsa
from .core.instance import Instance
from .backend.user.json_store import JsonUserBackend
