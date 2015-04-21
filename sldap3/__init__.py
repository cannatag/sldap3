from .version import __author__, __version__, __email__, __description__, __status__, __license__, __url__

from .core.dsa import Dsa
from .core.instance import Instance
from .backend.user.json import JsonUserBackend
NATIVE_ASYNCIO = False

try:
    # Use builtin asyncio
    from asyncio import BaseEventLoop
    NATIVE_ASYNCIO = True
except ImportError:
    # Use Trollius for backward compatability
    import trollius
