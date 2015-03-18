from core.dsa import Dsa
from core.instance import Instance
from multiprocessing import Process

instances = []

dsa1 = Instance(Dsa('DSA1', 'localhost', 389, use_ssl=False))
dsa2 = Instance(Dsa('DSA2', 'localhost', 1389, use_ssl=False))

instances.append(dsa1)
instances.append(dsa2)


for instance in instances:
    instance.process = Process(target=instance.dsa.start)
    instance.process.start()

print('started %d instances' % (len(instances)))

for instance in instances:
    instance.process.join()

print('sldap3 done')
