# Copyright 2012 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

"""
A shortest-path forwarding application.

This is a standalone L2 switch that learns ethernet addresses
across the entire network and picks short paths between them.

You shouldn't really write an application this way -- you should
keep more state in the controller (that is, your flow tables),
and/or you should make your topology more static.  However, this
does (mostly) work. :)

Depends on openflow.discovery
Works with openflow.spanning_tree
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.recoco import Timer
from pox.lib.util import dpidToStr
from collections import defaultdict
from pox.openflow.discovery import Discovery
from pox.lib.util import dpid_to_str
from pox.lib.addresses import IPAddr
from pox.lib.addresses import EthAddr
log = core.getLogger()
import thread
import string
import re
import socket
import struct
import time


log = core.getLogger()

# Adjacency map.  [sw1][sw2] -> port from sw1 to sw2
adjacency = defaultdict(lambda:defaultdict(lambda:None))

# Switches we know of.  [dpid] -> Switch
switches = {}

# ethaddr -> (switch, port)
mac_map = {}

# [sw1][sw2] -> (distance, intermediate)
path_map = defaultdict(lambda:defaultdict(lambda:(None,None)))

# Waiting path.  (dpid,xid)->WaitingPath
waiting_paths = {}

# Time to not flood in seconds
FLOOD_HOLDDOWN = 5

# Flow timeouts
FLOW_IDLE_TIMEOUT = 10
FLOW_HARD_TIMEOUT = 30

# How long is allowable to set up a path?
PATH_SETUP_TIME = 4

_7_bat = '16:55:0E:D1:5F:DD'
_8_bat = 'DE:BD:53:F2:4D:A5'
_9_bat = 'C2:FA:A5:FE:E5:FE' 
mesh_bat0_mac = {7:EthAddr(_7_bat),8:EthAddr(_8_bat),9:EthAddr(_9_bat)}

channel = {}  ##dpid : {dpid : linksituation} the larger the value of linksituation is,the worst the linksituation is 
#init_channel = {}
temp_channel = {}
channel_flag = 0

#########################################################a sw join in controller pox,reinit channel
def initial_channel():
        #print len(channel.keys())
        #print len(switches.keys())
        ##when a sw disconnect to or join in controller pox,the switches.keys() change ,reinit channel ;!!!!the situation a sw disconnect to controller,the len(switches.keys()) cant change ,
       
        if len(channel.keys()) != len(switches.keys()):
          print 'len(channel.keys()) != len(switches.keys()):'
          print len(channel.keys())
          print len(switches.keys())
          initchannel()
        else:
          for i in channel.keys():
            if len(channel[i].keys())!=len(switches.keys())-1:##when this situation happens ,reinit channel 
              print 'len(channel[i].keys())!=len(switches.keys())-1:'
              print len(channel[i].keys())
              print len(switches.keys())-1
              initchannel()
              break
      
#########################################################a sw  join in controller pox,reinit channel              

#########################################################get channel
def generate_channel():
  ControllerIP = '10.0.0.200'
  Controller_Listen_Event_Port = 5560

  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
  s.bind((ControllerIP, Controller_Listen_Event_Port))
  s.listen(30)
  
  temp = len(switches.keys())
  time.sleep(10)
  while 1:  ##when all switch connect , we get channel
    if len(switches.keys()) == temp:
      break
    else:
      temp = len(switches.keys())
    time.sleep(3)
    
  ##initial channel
  initchannel()
  '''
  global channel ,init_channel
  for i in switches.keys():
    dicc = {}
    for j in switches.keys():
      if i != j:
        dicc[j] = 1
    #print dicc
    init_channel[int(i)] = dicc  
  channel = init_channel.copy()
  print 'init_channel'
  print init_channel
  print channel
  '''
  while 1:
	client_sock, client_addr = s.accept()
        thread.start_new_thread(handle,(client_sock, client_addr))
	
def initchannel():
  ##initial channel
  global channel 
  init_channel = {}
  for i in switches.keys():
    dicc = {}
    for j in switches.keys():
      if i != j:
        dicc[j] = 100
    #print dicc
    init_channel[int(i)] = dicc  
  channel = init_channel.copy()
  print 'init_channel'
  print init_channel
  print channel


def handle(client_sock, client_addr):
        dic = {}
        dicc = {}
	msg = client_sock.recv(16)
	dpid = struct.unpack("!16s", msg)
	msg = client_sock.recv(17)
	mac = struct.unpack("!17s", msg)
	#print "dpid is",dpid[0]
	#print "mac is", mac[0]
	msg = client_sock.recv(4)
	#if len(msg) <= 0:
	#	continue
	ap_num = struct.unpack("!i", msg)
	#print "AP number is %d" %ap_num[0]
	for i in range(0, ap_num[0]):
		#msg = client_sock.recv(struct.calcsize("i18s20sf"))
		msg = client_sock.recv(struct.calcsize("!i18s20shf"))
		#print struct.calcsize("!i18s20sf")
		#print "msg is",
		#print msg
		mesh_num, bssid, essid, other, qual = struct.unpack("!i18s20shf", msg)
		#mesh_num1 = struct.unpack("!i", mesh_num)
		#bssid1 = struct.unpack("!18s", bssid)
		#essid1 = struct.unpack("!20s", essid)
		#qual1 = struct.unpack("!f", qual)
		#print mesh_num, bssid, str(essid), qual
		#print essid
		if qual < 0:
		  dic[str(essid)]=-qual
		#print  essid
	dicc = {}	
        dicc = mesh_point(dic)
        
        global channel,temp_channel,switches
        
        for i in dicc.keys():##change channel with channel[int(dpid[0])][i],when a sw not in dicc.keys(),means it not within the scope of dpid[0].then it will remain init value 100
          channel[int(dpid[0])][i] = dicc[i]
        #channel[int(dpid[0])] = dicc
        print len(channel.keys())
        print len(switches.keys())
        ##when a sw disconnect to or join in controller pox,the switches.keys() change ,reinit channel ;!!!!the situation a sw disconnect to controller,the len(switches.keys()) cant change ,
        initial_channel()
        
        print channel
        '''
        if len(channel.keys()) == len(switches.keys()):
            if channel != temp_channel:
                channel_flag = 2   ##channel change , path must change
                #print channel
            else:
                channel_flag = 1   ##channel dont change ,path need not change
            
        else:
            channel_flag = 0   ##channel is not completed , path cant install
        #print channel
        #print channel_flag, temp_channel,channel
        temp_channel = channel.copy()
        #print channel_flag, channel
        '''
        
def mesh_point(dic):  
  dicc = {}
  a = dic.keys()
  str = 'OpenWrt\d_4300'
  c = []
  for i in a:
    if len(re.findall(str,i)) is 0:
      continue
    else:
      c.append(re.findall(str,i)[0])
      for j in switches.keys():
        if j == int(re.findall(str,i)[0][7]):
          dicc[int(re.findall(str,i)[0][7])] = dic[i]
      #print re.findall(str,i)[0]
  return dicc

#########################################################get channel


#########################################################get path
def _check_path (p):
  """
  Make sure that a path is actually a string of nodes with connected ports

  returns True if path is valid
  """
  for a,b in zip(p[:-1],p[1:]):
    if adjacency[a[0]][b[0]] != a[2]:
      return False
    if adjacency[b[0]][a[0]] != b[2]:
      return False
  return True

def generate_graph(adj):
  graph = {}
  for sw in adj:
    graph[sw.dpid] = []
    for sw1 in adj[sw]:
      graph[sw.dpid].append(sw1.dpid)  
  #print '########################'
  #print graph
  return graph

def find_all_paths(graph, start, end, path=[]):
        path = path + [start]
        if start == end:
            return [path]
        if not graph.has_key(start):
            return []
        paths = []
        for node in graph[start]:
            if node not in path:
                newpaths = find_all_paths(graph, node, end, path)
                for newpath in newpaths:
                    paths.append(newpath)
        return paths

def chose_path(start,end,channel):##according to channel and hop to decide the final path from allpath
  #print start
  #print end
  print 'channel'
  print channel
  paths_dic={}
  maxi=0
  whole_maxi={}
  whole_min = 1000
  min_hop = 100
  count = {}
  graph = generate_graph(adjacency)
  paths = find_all_paths(graph, start, end, path=[])
  ##print 'paths = find_all_paths(graph, start, end, path=[])'
  #print channel
  #print paths
  for j in range(0,len(paths)):
    paths_dic[j+1] = paths[j] 
  ##print paths_dic
  for j in paths_dic:##calc every path the worst linksituation
    for i in range(0,len(paths_dic[j])-1):
      if channel[paths_dic[j][i]][paths_dic[j][i+1]]>=maxi:
        maxi = channel[paths_dic[j][i]][paths_dic[j][i+1]]
    
    whole_maxi[j]=maxi
    maxi=0 ##important !!!!when each path maxi finished ,make maxi 0,start the nest path
  ##print whole_maxi
  for i in whole_maxi: ##chose a better one, (linksituation is small)
    if whole_maxi[i]<whole_min:
      whole_min = whole_maxi[i]
  #print whole_min    
  for i in whole_maxi:
    if whole_min == whole_maxi[i]:
      count[i] = whole_min
  #print 'count'
  #print count    
  if len(count.keys())>1:
    for i in count:
      if len(paths_dic[i])<min_hop:
        min_hop = len(paths_dic[i])
    for i in count:
      if  min_hop ==  len(paths_dic[i]):
          return paths_dic[i]
  else:
    #print paths_dic[count.keys()[0]]
    return paths_dic[count.keys()[0]]

def _get_path (src, dst, first_port, final_port):
  """
  Gets a cooked path -- a list of (node,in_port,out_port)
  """
  # Start with a raw path...
  path = chose_path(src.dpid,dst.dpid,channel)
  print '_handle_PacketIn() -> install_path() -> _get_path() -> chose_path() -> channel path'
  print channel
  print path
  r = []
  #print 'path = chose_path(mac_map[srcmac][0].dpid,mac_map[dstmac][0].dpid,channel)'
  #print path
  mesh_path = {}
  #mesh_path[1] = (srcmac,0,mac_map[srcmac][1]))
  if len(path) == 1:
    mesh_path[1] = (src,first_port,final_port)
  else :  
    if len(path) == 2:
      #mesh_path[len(path)+2] = (dstmac,mac_map[dstmac][1],0)
      mesh_path[1] = (src,first_port,adjacency[switches[path[0]]][switches[path[1]]])
      mesh_path[2] = (dst,adjacency[switches[path[len(path)-1]]][switches[path[len(path)-2]]],final_port)
    else:
      mesh_path[1] = (src,first_port,adjacency[switches[path[0]]][switches[path[1]]])
      mesh_path[len(path)] = (dst,adjacency[switches[path[len(path)-1]]][switches[path[len(path)-2]]],final_port)
      for i in range(2,len(path)):
        mesh_path[i] = (switches[path[i-1]], adjacency[switches[path[i-1]]][switches[path[i-2]]] , adjacency[switches[path[i-1]]][switches[path[i]]] )
  #print mesh_path
  r = mesh_path.values()

  assert _check_path(r), "Illegal path!"

  return r

#########################################################get path

class WaitingPath (object):
  """
  A path which is waiting for its path to be established
  """
  def __init__ (self, path, packet):
    """
    xids is a sequence of (dpid,xid)
    first_switch is the DPID where the packet came from
    packet is something that can be sent in a packet_out
    """
    self.expires_at = time.time() + PATH_SETUP_TIME
    self.path = path
    self.first_switch = path[0][0].dpid
    self.xids = set()
    self.packet = packet

    if len(waiting_paths) > 1000:
      WaitingPath.expire_waiting_paths()

  def add_xid (self, dpid, xid):
    self.xids.add((dpid,xid))
    waiting_paths[(dpid,xid)] = self

  @property
  def is_expired (self):
    return time.time() >= self.expires_at

  def notify (self, event):
    """
    Called when a barrier has been received
    """
    self.xids.discard((event.dpid,event.xid))
    if len(self.xids) == 0:
      # Done!
      if self.packet:
        log.debug("Sending delayed packet out %s"
                  % (dpid_to_str(self.first_switch),))
        msg = of.ofp_packet_out(data=self.packet,
            action=of.ofp_action_output(port=of.OFPP_TABLE))
        core.openflow.sendToDPID(self.first_switch, msg)

      core.l2_multi.raiseEvent(PathInstalled(self.path))


  @staticmethod
  def expire_waiting_paths ():
    packets = set(waiting_paths.values())
    killed = 0
    for p in packets:
      if p.is_expired:
        killed += 1
        for entry in p.xids:
          waiting_paths.pop(entry, None)
    if killed:
      log.error("%i paths failed to install" % (killed,))


class PathInstalled (Event):
  """
  Fired when a path is installed
  """
  def __init__ (self, path):
    Event.__init__(self)
    self.path = path


class Switch (EventMixin):
  def __init__ (self):
    self.connection = None
    self.ports = None
    self.dpid = None
    self._listeners = None
    self._connected_at = None

  def __repr__ (self):
    return dpid_to_str(self.dpid)

  def _install (self, switch, in_port, out_port, match, mac ,buf = None):
    #print '_install (self, switch, in_port, out_port, match, mac ,buf = None):'
    msg = of.ofp_flow_mod()
    #msg.match = match

    #msg.match.dl_dst =  mesh_bat0_mac[self.dpid] 
    msg.match.in_port = in_port
    msg.match.dl_type = match.dl_type
    msg.match.nw_tos = match.nw_tos
    msg.match.nw_proto = match.nw_proto
    msg.match.nw_src = match.nw_src
    msg.match.nw_dst = match.nw_dst
    msg.idle_timeout = FLOW_IDLE_TIMEOUT
    msg.hard_timeout = FLOW_HARD_TIMEOUT
    msg.match.dl_src = match.dl_src
    #msg.match.dl_dst = match.dl_src
    msg.actions.append(of.ofp_action_dl_addr.set_dst(mac))
    if in_port == out_port:
      msg.actions.append(of.ofp_action_output(port = 0xfff8))
    else:
      msg.actions.append(of.ofp_action_output(port = out_port))
    msg.buffer_id = buf
    switch.connection.send(msg)

  def _install_path (self, p, match, packet_in=None):
    wp = WaitingPath(p, packet_in)    
    #for sw,in_port,out_port in p:
    for i in range(0,len(p)):
      #print '_install_path (self, p, match, packet_in=None):'
      #print i
      if i is not (len(p)-1):
        self._install(p[i][0], p[i][1], p[i][2], match ,mesh_bat0_mac[p[i+1][0].dpid])
      else:
        self._install(p[i][0], p[i][1], p[i][2], match ,match.dl_dst)
      msg = of.ofp_barrier_request()
      p[i][0].connection.send(msg)
      wp.add_xid(p[i][0].dpid,msg.xid)

  def install_path (self, dst_sw, last_port, match, event):
    """
    Attempts to install a path between this switch and some destination
    """
    p = _get_path(self, dst_sw, event.port, last_port)
    if p is None:
      log.warning("Can't get from %s to %s", match.dl_src, match.dl_dst)

      import pox.lib.packet as pkt

      if (match.dl_type == pkt.ethernet.IP_TYPE and
          event.parsed.find('ipv4')):
        # It's IP -- let's send a destination unreachable
        log.debug("Dest unreachable (%s -> %s)",
                  match.dl_src, match.dl_dst)

        from pox.lib.addresses import EthAddr
        e = pkt.ethernet()
        e.src = EthAddr(dpid_to_str(self.dpid)) #FIXME: Hmm...
        e.dst = match.dl_src
        e.type = e.IP_TYPE
        ipp = pkt.ipv4()
        ipp.protocol = ipp.ICMP_PROTOCOL
        ipp.srcip = match.nw_dst #FIXME: Ridiculous
        ipp.dstip = match.nw_src
        icmp = pkt.icmp()
        icmp.type = pkt.ICMP.TYPE_DEST_UNREACH
        icmp.code = pkt.ICMP.CODE_UNREACH_HOST
        orig_ip = event.parsed.find('ipv4')

        d = orig_ip.pack()
        d = d[:orig_ip.hl * 4 + 8]
        import struct
        d = struct.pack("!HH", 0,0) + d #FIXME: MTU
        icmp.payload = d
        ipp.payload = icmp
        e.payload = ipp
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port = event.port))
        msg.data = e.pack()
        self.connection.send(msg)

      return

    log.debug("Installing path for %s -> %s %04x (%i hops)",
        match.dl_src, match.dl_dst, match.dl_type, len(p))

    # We have a path -- install it
    self._install_path(p, match, event.ofp)

    # Now reverse it and install it backwards
    # (we'll just assume that will work)
    p = [(sw,out_port,in_port) for sw,in_port,out_port in p]
    ##############the path order is important,change it
    c=[]
    for i in range(0,len(p)):
      c.append(p[len(p)-1-i])
    self._install_path(c, match.flip())
    ##############the path order is important,change it
    #print match
    #print match.flip()


  def _handle_PacketIn (self, event):
    #print self.dpid
    #print '_handle_PacketIn (self, event):'
    initial_channel()  ##when sw dont send iw channel info to pox,if a sw join in the pox,the init channel must change 
    print 'switches'
    print switches
    def flood ():
      """ Floods the packet """
      if self.is_holding_down:
        log.warning("Not flooding -- holddown active")
      msg = of.ofp_packet_out()
      # OFPP_FLOOD is optional; some switches may need OFPP_ALL
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)

    def drop ():
      # Kill the buffer
      if event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        event.ofp.buffer_id = None # Mark is dead
        msg.in_port = event.port
        self.connection.send(msg)

    packet = event.parsed

    loc = (self, event.port) # Place we saw this ethaddr
    oldloc = mac_map.get(packet.src) # Place we last saw this ethaddr

    if packet.effective_ethertype == packet.LLDP_TYPE:
      drop()
      return

    if oldloc is None:#get the switch and port connected to host
      if packet.src.is_multicast == False:
        mac_map[packet.src] = loc # Learn position for ethaddr
        log.debug("Learned %s at %s.%i", packet.src, loc[0], loc[1])
    elif oldloc != loc:
      # ethaddr seen at different place!
      if loc[1] not in adjacency[loc[0]].values():
        # New place is another "plain" port (probably)
        log.debug("%s moved from %s.%i to %s.%i?", packet.src,
                  dpid_to_str(oldloc[0].connection.dpid), oldloc[1],
                  dpid_to_str(   loc[0].connection.dpid),    loc[1])
        if packet.src.is_multicast == False:
          mac_map[packet.src] = loc # Learn position for ethaddr
          log.debug("Learned %s at %s.%i", packet.src, loc[0], loc[1])
      elif packet.dst.is_multicast == False:
        # New place is a switch-to-switch port!
        #TODO: This should be a flood.  It'd be nice if we knew.  We could
        #      check if the port is in the spanning tree if it's available.
        #      Or maybe we should flood more carefully?
        log.warning("Packet from %s arrived at %s.%i without flow",
                    packet.src, dpid_to_str(self.dpid), event.port)
        #drop()
        #return


    if packet.dst.is_multicast:
      log.debug("Flood multicast from %s", packet.src)
      flood()
    else:
      if packet.dst not in mac_map:
        log.debug("%s unknown -- flooding" % (packet.dst,))
        flood()
      else:
        #if self.dpid == mac_map[packet.src][0].dpid:
          dest = mac_map[packet.dst]
          match = of.ofp_match.from_packet(packet)
          #print match
          self.install_path(dest[0], dest[1], match, event)

  def disconnect (self):
    if self.connection is not None:
      log.debug("Disconnect %s" % (self.connection,))
      self.connection.removeListeners(self._listeners)
      self.connection = None
      self._listeners = None

  def connect (self, connection):
    if self.dpid is None:
      self.dpid = connection.dpid
    assert self.dpid == connection.dpid
    if self.ports is None:
      self.ports = connection.features.ports
    self.disconnect()
    log.debug("Connect %s" % (connection,))
    self.connection = connection
    self._listeners = self.listenTo(connection)
    self._connected_at = time.time()

  @property
  def is_holding_down (self):
    if self._connected_at is None: return True
    if time.time() - self._connected_at > FLOOD_HOLDDOWN:
      return False
    return True

  def _handle_ConnectionDown (self, event):
  
    del switches[self.dpid]
    self.disconnect()


class l2_multi (EventMixin):

  _eventMixin_events = set([
    PathInstalled,
  ])

  def __init__ (self):
    # Listen to dependencies
    def startup ():
      core.openflow.addListeners(self, priority=0)
      core.openflow_discovery.addListeners(self)
    core.call_when_ready(startup, ('openflow','openflow_discovery'))

  def _handle_LinkEvent (self, event):
    def flip (link):
      return Discovery.Link(link[2],link[3], link[0],link[1])

    l = event.link
    sw1 = switches[l.dpid1]
    sw2 = switches[l.dpid2]

    # Invalidate all flows and path info.
    # For link adds, this makes sure that if a new link leads to an
    # improved path, we use it.
    # For link removals, this makes sure that we don't use a
    # path that may have been broken.
    #NOTE: This could be radically improved! (e.g., not *ALL* paths break)
    clear = of.ofp_flow_mod(command=of.OFPFC_DELETE)
    for sw in switches.itervalues():
      if sw.connection is None: continue
      sw.connection.send(clear)
    path_map.clear()

    if event.removed:
      # This link no longer okay
      if sw2 in adjacency[sw1]: del adjacency[sw1][sw2]
      if sw1 in adjacency[sw2]: del adjacency[sw2][sw1]

      # But maybe there's another way to connect these...
      for ll in core.openflow_discovery.adjacency:
        if ll.dpid1 == l.dpid1 and ll.dpid2 == l.dpid2:
          if flip(ll) in core.openflow_discovery.adjacency:
            # Yup, link goes both ways
            adjacency[sw1][sw2] = ll.port1
            adjacency[sw2][sw1] = ll.port2
            # Fixed -- new link chosen to connect these
            break
    else:
      # If we already consider these nodes connected, we can
      # ignore this link up.
      # Otherwise, we might be interested...
      if adjacency[sw1][sw2] is None:
        # These previously weren't connected.  If the link
        # exists in both directions, we consider them connected now.
        if flip(l) in core.openflow_discovery.adjacency:
          # Yup, link goes both ways -- connected!
          adjacency[sw1][sw2] = l.port1
          adjacency[sw2][sw1] = l.port2

      # If we have learned a MAC on this port which we now know to
      # be connected to a switch, unlearn it.
      bad_macs = set()
      for mac,(sw,port) in mac_map.iteritems():
        #print sw,sw1,port,l.port1
        if sw is sw1 and port == l.port1:
          if mac not in bad_macs:
            log.debug("Unlearned %s", mac)
            bad_macs.add(mac)
        if sw is sw2 and port == l.port2:
          if mac not in bad_macs:
            log.debug("Unlearned %s", mac)
            bad_macs.add(mac)
      for mac in bad_macs:
        del mac_map[mac]

  #def _handle_ConnectionDown (self, event):
    #print '_handle_ConnectionDown (self, event):'
    #sw = switches.get(event.dpid)
    #sw.disconnect()
    #del switches[event.dpid]
    
  def _handle_ConnectionUp (self, event):
    sw = switches.get(event.dpid)
    if sw is None:
      # New switch
      sw = Switch()
      switches[event.dpid] = sw
      sw.connect(event.connection)
    else:
      sw.connect(event.connection)

  def _handle_BarrierIn (self, event):
    wp = waiting_paths.pop((event.dpid,event.xid), None)
    if not wp:
      #log.info("No waiting packet %s,%s", event.dpid, event.xid)
      return
    #log.debug("Notify waiting packet %s,%s", event.dpid, event.xid)
    wp.notify(event)


def launch ():
  core.registerNew(l2_multi)
  thread.start_new_thread(generate_channel,())   ###get channel thread
  timeout = min(max(PATH_SETUP_TIME, 5) * 2, 15)
  Timer(timeout, WaitingPath.expire_waiting_paths, recurring=True)
