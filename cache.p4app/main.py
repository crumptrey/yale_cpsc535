from p4app import P4Mininet
from mininet.topo import SingleSwitchTopo
import sys
import time
N = 2 # number of hosts
topo = SingleSwitchTopo(N) # single switch, 2 hosts
net = P4Mininet(program='cache.p4', topo=topo)
net.start()

s1, h1, h2 = net.get('s1'), net.get('h1'), net.get('h2')

# TODO Populate IPv4 forwarding table
# Making a blank list of table entries to store each of the forwarding table entries (2 in total since we have 2 hosts)
table_entries = []
# Looping through the number of hosts; creating a forwarding table for each host and storing in our list table_entries
for i in range(1, N+1):
    table_entries.append(dict(table_name='MyIngress.ipv4_lpm',
                        match_fields={'hdr.ipv4.dstAddr': ["10.0.0.%d" % i, 32]},
                        action_name='MyIngress.ipv4_forward',
                        action_params={'dstAddr': net.get('h%d'%i).intfs[0].MAC(),
                                          'port': i}))
# Putting our forwarding tables list into forwarding table entries
for table_entry in table_entries:
    s1.insertTableEntry(table_entry)

# TODO Populate the cache table
s1.insertTableEntry(table_name='MyIngress.reqHdr_exact',
                    match_fields={'hdr.reqHdr.key': [3]},
                    action_name='MyIngress.cache_response',
                    action_params={'key': [3], 'is_valid': [1],'value' : [33]})
# Now, we can test that everything works

# Start the server with some key-values
server = h1.popen('./server.py 1=11 2=22', stdout=sys.stdout, stderr=sys.stdout)
time.sleep(0.4) # wait for the server to be listening

out = h2.cmd('./client.py 10.0.0.1 1') # expect a resp from server
assert out.strip() == "11"
out = h2.cmd('./client.py 10.0.0.1 1') # expect a value from switch cache (registers)
assert out.strip() == "11"
out = h2.cmd('./client.py 10.0.0.1 2') # resp from server
assert out.strip() == "22"
out = h2.cmd('./client.py 10.0.0.1 3') # from switch cache (table)
assert out.strip() == "33"
out = h2.cmd('./client.py 10.0.0.1 123') # resp not found from server
assert out.strip() == "NOTFOUND"

server.terminate()
