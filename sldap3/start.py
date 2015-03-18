import asyncio
from core.dsa import Dsa

dsa = Dsa('localhost', 389)
dsa.start()

dsa2 = Dsa('localhost', 1389)
dsa2.start()
