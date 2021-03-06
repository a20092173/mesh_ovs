# Copyright 2012 James McCauley
#
# This file is part of POX.
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
import time
from pox.lib.addresses import IPAddr
from pox.lib.addresses import EthAddr
log = core.getLogger()
import thread
import string

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

#############################mesh
_7_bat = '66:57:55:21:27:26'
_8_bat = 'DE:BD:53:F2:4D:A5'
_9_bat = 'C2:FA:A5:FE:E5:FE' 
srcmac = '30:0E:D5:C1:68:86'
aimmac = '00:21:97:3B:3C:C2'
mesh_bat0_mac = {7:_7_bat,8:_8_bat,9:_9_bat}
mesh_path = {}
mesh_paths = {}
hostmac_toip = {}
#mesh_path = {1:[srcmac , (0 , 4)],2:[8,(4,6)],3:[7,(6,6)],4:[9,(6,3)],5:[aimmac,(3,0)]}
globle_group = {} #{groupid:multicast object}
mesh_groupid = 1    ##mesh_paths id , each path corresponding to a mesh_groupid
mesh_weight = 1
iptomac = {IPAddr('10.0.0.60'):EthAddr('30:0E:D5:C1:68:86'),IPAddr('10.0.0.50'):EthAddr('00:21:97:3B:3C:C2')}
channel = {7:{8:1,9:2},8:{7:2,9:4},9:{7:1,8:5}}  ##dpid : {dpid : linksituation} the larger the value of linksituation is,the worst the linksituation is 
#channel = {7:{8:7,9:6},8:{7:6,9:4},9:{7:6,8:5}}
##################################mesh

def _calc_paths ():
  """
  Essentially Floyd-Warshall algorithm
  """

  def dump ():
    for i in sws:
      for j in sws:
        a = path_map[i][j][0]
        #a = adjacency[i][j]
        if a is None: a = "*"
        print a,
      print

  sws = switches.values()
  path_map.clear()
  for k in sws:
    for j,port in adjacency[k].iteritems():
      if port is None: continue
      path_map[k][j] = (1,None)
    path_map[k][k] = (0,None) # distance, intermediate

  #dump()

  for k in sws:
    for i in sws:
      for j in sws:
        if path_map[i][k][0] is not None:
          if path_map[k][j][0] is not None:
            # i -> k -> j exists
            ikj_dist = path_map[i][k][0]+path_map[k][j][0]
            if path_map[i][j][0] is None or ikj_dist < path_map[i][j][0]:
              # i -> k -> j is better than existing
              path_map[i][j] = (ikj_dist, k)

  #print "--------------------"
  #dump()


def _get_raw_path (src, dst):
  """
  Get a raw path (just a list of nodes to traverse)
  """
  if len(path_map) == 0: _calc_paths()
  if src is dst:
    # We're here!
    return []
  if path_map[src][dst][0] is None:
    return None
  intermediate = path_map[src][dst][1]
  if intermediate is None:
    # Directly connected
    return []
  return _get_raw_path(src, intermediate) + [intermediate] + \
         _get_raw_path(intermediate, dst)


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


def _get_path (src, dst, first_port, final_port):
  """
  Gets a cooked path -- a list of (node,in_port,out_port)
  """
  # Start with a raw path...
  if src == dst:
    path = [src]
  else:
    path = _get_raw_path(src, dst)
    if path is None: return None
    path = [src] + path + [dst]

  # Now add the ports
  r = []
  in_port = first_port
  for s1,s2 in zip(path[:-1],path[1:]):
    out_port = adjacency[s1][s2]
    r.append((s1,in_port,out_port))
    in_port = adjacency[s2][s1]
  r.append((dst,in_port,final_port))
  #generate_graph(adjacency)
  assert _check_path(r), "Illegal path!"

  return r


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

###########################################
###########define event MeshInstallpath
###########################################
class MeshInstallpath(Event):
  '''
  Mesh network
  '''
  def __init__ (self, bat0_mac , weight , path , groupid):
    Event.__init__(self)
    self.bat0_mac = bat0_mac
    self.weight = weight
    self.path = path
    self.groupid = groupid

class MeshChangepath(Event):
  '''
  Mesh network
  '''
  def __init__ (self, bat0_mac , weight , path , groupid):
    Event.__init__(self)
    self.bat0_mac = bat0_mac
    self.weight = weight
    self.path = path
    self.groupid = groupid

class MeshDeletepath(Event):
  '''
  Mesh network
  '''
  def __init__ (self, bat0_mac , weight , path , groupid):
    Event.__init__(self)
    self.bat0_mac = bat0_mac
    self.weight = weight
    self.path = path
    self.groupid = groupid



class handleMesh(object):
  def __init__(self):
    
    core.l2_multi.addListeners(self)
    
  def _handle_MeshInstallpath(self,event):
    if event.groupid in globle_group.keys():
      return
    else :  
      if event.weight is 0 :
        return
      else :
        print '_handle_MeshInstallpath(self,event):^^^^^^^^^^^'
        print 'event.groupid'
        print event.groupid
        bat0_mac = event.bat0_mac
        path = event.path
        globle_group[event.groupid] = Mesh(bat0_mac,path)
        globle_group[event.groupid].Mesh_Installpath()
      
  def _handle_MeshChangepath(self,event):
    if event.groupid not in globle_group.keys():
      return
    else :  
      if event.weight is 0 :
        return
      else :
        #bat0_mac = event.bat0_mac
        #path = event.path
        globle_group[event.groupid].Mesh_Changepath()
  
  def _handle_MeshDeletepath(self,event):
    if event.groupid not in globle_group.keys():
      return
    else :  
      if event.weight is 0 :
        return
      else :
        #bat0_mac = event.bat0_mac
        #path = event.path
        globle_group[event.groupid].MeshDeletepath()
        del globle_group[event.groupid]

class Mesh(object): ##meshpath implement
  def __init__(self, bat0_mac, path):
    self.bat0_mac = bat0_mac
    self.path = path
    
  def Mesh_Installpath(self):
    print self.path
    srcip = self.path.keys()[0]
    dstip = self.path[self.path.keys()[0]].keys()[0]
    mesh_path = self.path[srcip][dstip]
    print mesh_path
    mesh_len = len(mesh_path.keys())
    print 'Mesh_Installpath#######################'
    '''
    for i in switches.keys():##delete pre nonemesh path flow table,we cannot match inport
      msg = of.ofp_flow_mod()
      #msg.match.in_port = self.path[i][1][0] ##match inport
      msg.match.dl_type = 0x800
      msg.match.nw_tos= 0
      msg.match.nw_proto=17  ##match udp
      msg.match.nw_src = EthAddr(self.path[1][0]) ##match src mac
      msg.idle_timeout = 10
      msg.hard_timeout = 30
      #msg.command = of.OFPFC_DELETE ##delete pre flow table
      msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
      switches[i].connection.send(msg)
    '''
    #if len(mesh_path.keys()) == len(m_path.keys()):
    
    if len(mesh_path.keys())>1: ##the sitiation more than one switch connects two hosts
     for i in mesh_path.keys():
     
         print 'mesh_path[i][0]'

       #if  i is not 1 and i is not len(mesh_path.keys()):  #the first is srchost the last is aimhost , other is router 
         
         print i
         print srcip
         '''
         print mesh_path[i][0]
         print mesh_path[1][0]
         if i is mesh_len:
           print mesh_path[i+1][0]
         else:
           print mesh_bat0_mac[int(mesh_path[i+1][0])]
         print hostmac_toip[mesh_path[1][0]]
         print hostmac_toip[mesh_path[len(mesh_path.keys())][0]]    
         '''     
         msg = of.ofp_flow_mod()
         msg.match.in_port = mesh_path[i][1][0]
         #msg.match.dl_type = 0x800
         #msg.match.nw_tos= 0
         #msg.match.nw_proto=17
         #msg.match.tp_src = 50002
         #msg.match.dl_src = EthAddr(mesh_path[1][0]) ##because we match src mac, so we dont change src mac below
         #msg.match.dl_src = mesh_path[1][0]
         msg.match.dl_src = iptomac[srcip]
         #msg.match.nw_src = IPAddr("10.0.0.60")
         #msg.match.nw_src = srcip
         #msg.match.nw_dst = dstip
         #msg.idle_timeout = 10  ##if the two line not included ,the flow table will always exist 
         #msg.hard_timeout = 30
         #msg.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(mesh_bat0_mac[mesh_path[i][0]]))) ##dont must change src mac
         if i is mesh_len:
           msg.actions.append(of.ofp_action_dl_addr.set_dst(iptomac[dstip]))
         else:        
           msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(mesh_bat0_mac[mesh_path[i+1][0]])))
        
         if mesh_path[i][1][0] == mesh_path[i][1][1]: #if inport is outport 
           msg.actions.append(of.ofp_action_output(port = 0xfff8))
         else:#inport is not outport
           msg.actions.append(of.ofp_action_output(port = mesh_path[i][1][1]))  
         switches[mesh_path[i][0]].connection.send(msg)##switches key is dpid whose type is int,so when we build path,we show take care

    else:  ##the sitiation only one switch connects two hosts
         msg = of.ofp_flow_mod()
         msg.match.in_port = mesh_path[1][1][0]
         #msg.match.dl_type = 0x800
         #msg.match.nw_tos= 0
         #msg.match.nw_proto=17   
         msg.match.nw_src = srcip
         msg.match.nw_dst = dstip
         msg.actions.append(of.ofp_action_output(port = mesh_path[1][1][1]))   
         switches[mesh_path[1][0]].connection.send(msg)  
  #def Mesh_Changepath(self):
  
  #def Mesh_Deletepath(self):
  
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
  paths_dic={}
  maxi=0
  whole_maxi={}
  whole_min = 100
  min_hop = 100
  count = {}
  graph = generate_graph(adjacency)
  paths = find_all_paths(graph, start, end, path=[])
  ##print 'paths = find_all_paths(graph, start, end, path=[])'
  #print channel
  #print paths
  for j in range(0,len(paths)):
    paths_dic[j+1] = paths[j] 
  print paths_dic
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
  print whole_min    
  for i in whole_maxi:
    if whole_min == whole_maxi[i]:
      count[i] = whole_min
  print 'count'
  print count    
  if len(count.keys())>1:
    for i in count:
      if len(paths_dic[i])<min_hop:
        min_hop = len(paths_dic[i])
    for i in count:
      if  min_hop ==  len(paths_dic[i]):
          return paths_dic[i]
  else:
    if len(count.keys())==1:
      #print paths_dic[count.keys()[0]]
      return paths_dic[count.keys()[0]]
    else:
      #return paths_dic[0]
      return

def generate_mesh_path(adj,srcmac,dstmac,srcip,dstip):
  #print mac_map[srcmac][0].dpid
  #print mac_map[dstmac][0].dpid
  path = chose_path(mac_map[srcmac][0].dpid,mac_map[dstmac][0].dpid,channel)

  #print 'path = chose_path(mac_map[srcmac][0].dpid,mac_map[dstmac][0].dpid,channel)'
  print path
  mesh_path = {}
  if mac_map[srcmac][0].dpid == mac_map[dstmac][0].dpid:
    mesh_path[1] = [srcmac,(0,mac_map[srcmac][1])]
    mesh_path[2] = [mac_map[srcmac][0],(mac_map[srcmac][1],mac_map[dstmac][1])]
    mesh_path[3] = [dstmac,(mac_map[dstmac][1],0)]
  else:
    mesh_path[1] = [srcmac,(0,mac_map[srcmac][1])]
    mesh_path[2] = [mac_map[srcmac][0].dpid,(mac_map[srcmac][1],adj[switches[path[0]]][switches[path[1]]])]
    mesh_path[len(path)+2] = [dstmac,(mac_map[dstmac][1],0)]
    mesh_path[len(path)+1] = [mac_map[dstmac][0].dpid,(adj[switches[path[len(path)-1]]][switches[path[len(path)-2]]],mac_map[dstmac][1])]
    #print mesh_path
    if len(path)>2:
      for i in range(3,len(path)+1):
        mesh_path[i] = [path[i-2],( adj[switches[path[i-2]]][switches[path[i-3]]] , adj[switches[path[i-2]]][switches[path[i-1]]] )]
  #print mesh_path
  #return mesh_path
  m_path = {}
  g_path = {}
  f_path = {}
  for i in mesh_path :
    if i >=2 and i<len(mesh_path):
      m_path[i-1] = mesh_path[i]
  #print m_path
  f_path[dstip] = m_path
  g_path[srcip] = f_path
  return g_path  

def rasie(packet , mac_match):
    global mesh_bat0_mac,mesh_groupid,mesh_weight,mesh_path,mesh_paths
    m_flag = 0
    print '$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
    #print mac_match
    if packet.dst  in mac_map and packet.src  in mac_map :
      if len(switches.keys()) == len(adjacency.keys()):
        #print adjacency
        mesh_path = generate_mesh_path(adjacency , mac_match.dl_src , mac_match.dl_dst , mac_match.nw_src,mac_match.nw_dst)
        #core.l2_multi.raiseEvent(MeshInstallpath,mesh_bat0_mac,mesh_weight,mesh_path,mesh_groupid)
        if len(mesh_paths.keys()) is not 0:
          print 'if len(mesh_paths) is not 0:' 
          print mesh_paths
          for i in mesh_paths:
            for j in mesh_paths[i]:
              print i
              print mac_match.nw_src
              print j
              print mac_match.nw_dst
              if i == mac_match.nw_src and j == mac_match.nw_dst:
                m_flag = 1
                print 'm_flag = 1'
          if m_flag is 0:##mesh_paths dont have mesh_path
            print 'm_flag is 0:##mesh_paths dont have mesh_path'
            mesh_paths[mac_match.nw_src] = mesh_path[mac_match.nw_src]    
            core.l2_multi.raiseEvent(MeshInstallpath,mesh_bat0_mac,mesh_weight,mesh_path,mesh_groupid)
            mesh_groupid = mesh_groupid+1      
        else: 
          print 'if len(mesh_paths) is  0:'           
          mesh_paths = mesh_path
          #print mesh_bat0_mac
          #print mesh_groupid
          #print mesh_weight
          #core.l2_multi.raiseEvent(MeshInstallpath,mesh_bat0_mac,mesh_weight,mesh_path,mesh_groupid)
          core.l2_multi.raiseEvent(MeshInstallpath,mesh_bat0_mac,mesh_weight,mesh_path,mesh_groupid)
          mesh_groupid = mesh_groupid+1
        print mesh_path
        print mesh_paths
      #print mac_match 
      #print hostmac_toip
      #print mesh_paths
      #print mac_match.nw_src
      #print mac_match.nw_dst 
      #print packet.src
      #print mac_map[packet.src]
      #print packet.dst
      #print mac_map[packet.dst]


def run():
  time.sleep(100)
  imformation = 'I'
  #source = 0
  mesh_bat0_mac = {7:_7_bat,8:_8_bat,9:_9_bat}
  #mesh_path = {1:[srcmac , (0 , 4)],2:[8,(4,6)],3:[7,(6,6)],4:[9,(6,3)],5:[aimmac,(3,0)]}
  print 'runnnnnnnnnnnnnnnnnnnnn'
  print imformation.upper()
  #if str(imformation.upper()) is 'I':

  print 'mesh_bat0_mac'
  print mesh_bat0_mac
  print 'mesh_path'
  print mesh_path
  #core.l2_multi.raiseEvent(MeshInstallpath,mesh_bat0_mac,mesh_weight,mesh_path,mesh_groupid)

class Switch (EventMixin):
  def __init__ (self):
    self.connection = None
    self.ports = None
    self.dpid = None
    self._listeners = None
    self._connected_at = None

  def __repr__ (self):
    return dpid_to_str(self.dpid)

  def _install (self, switch, in_port, out_port, match, buf = None):
    msg = of.ofp_flow_mod()
    msg.match = match
    msg.match.in_port = in_port
    msg.idle_timeout = FLOW_IDLE_TIMEOUT
    msg.hard_timeout = FLOW_HARD_TIMEOUT
    msg.actions.append(of.ofp_action_output(port = out_port))
    msg.buffer_id = buf
    switch.connection.send(msg)

  def _install_path (self, p, match, packet_in=None):
    wp = WaitingPath(p, packet_in)
    for sw,in_port,out_port in p:
      self._install(sw, in_port, out_port, match)
      msg = of.ofp_barrier_request()
      sw.connection.send(msg)
      wp.add_xid(sw.dpid,msg.xid)

  def install_path (self, dst_sw, last_port, match, event):
    """
    Attempts to install a path between this switch and some destination
    """
    p = _get_path(self, dst_sw, event.port, last_port)
    print 'p = _get_path(self, dst_sw, event.port, last_port)'
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
    self._install_path(p, match.flip())


  def _handle_PacketIn (self, event):
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
    
#############################mesh    

    mac_match = of.ofp_match.from_packet(packet)
    #hostmac_toip[mac_match.dl_src] = mac_match.nw_src
    #hostmac_toip[mac_match.dl_dst] = mac_match.nw_dst
    '''
    global mesh_bat0_mac,mesh_groupid,mesh_weight,mesh_path,mesh_paths
    m_flag = 0
    print '$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
    #print mac_match
    if packet.dst  in mac_map and packet.src  in mac_map :
      if len(switches.keys()) == len(adjacency.keys()):
        #print adjacency
        mesh_path = generate_mesh_path(adjacency , mac_match.dl_src , mac_match.dl_dst , mac_match.nw_src,mac_match.nw_dst)
        #core.l2_multi.raiseEvent(MeshInstallpath,mesh_bat0_mac,mesh_weight,mesh_path,mesh_groupid)
        if len(mesh_paths.keys()) is not 0:
          print 'if len(mesh_paths) is not 0:' 
          for i in mesh_paths:
            for j in mesh_paths[i]:
              if i is mac_match.nw_src and j is mac_match.nw_dst:
                m_flag = 1
          if m_flag is 0:##mesh_paths dont have mesh_path
            print 'm_flag is 0:##mesh_paths dont have mesh_path'
            mesh_paths[mac_match.nw_src] = mesh_path[mac_match.nw_src]    
            core.l2_multi.raiseEvent(MeshInstallpath,mesh_bat0_mac,mesh_weight,mesh_path,mesh_groupid)
            mesh_groupid = mesh_groupid+1      
        else: 
          print 'if len(mesh_paths) is  0:'           
          mesh_paths = mesh_path
          #print mesh_bat0_mac
          #print mesh_groupid
          #print mesh_weight
          #core.l2_multi.raiseEvent(MeshInstallpath,mesh_bat0_mac,mesh_weight,mesh_path,mesh_groupid)
          core.l2_multi.raiseEvent(MeshInstallpath,mesh_bat0_mac,mesh_weight,mesh_path,mesh_groupid)
          mesh_groupid = mesh_groupid+1
        print mesh_path
        print mesh_paths
      #print mac_match 
      #print hostmac_toip
      #print mesh_paths
      #print mac_match.nw_src
      #print mac_match.nw_dst 
      #print packet.src
      #print mac_map[packet.src]
      #print packet.dst
      #print mac_map[packet.dst]
    '''#########################mesh

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
        rasie(packet , mac_match)
        #dest = mac_map[packet.dst]
        #match = of.ofp_match.from_packet(packet)
        #self.install_path(dest[0], dest[1], match, event)

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
    self.disconnect()


class l2_multi (EventMixin):

  _eventMixin_events = set([
    PathInstalled,
    MeshInstallpath,
    MeshChangepath,
    MeshDeletepath,
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
  handle = handleMesh()

  timeout = min(max(PATH_SETUP_TIME, 5) * 2, 15)
  Timer(timeout, WaitingPath.expire_waiting_paths, recurring=True)
  thread.start_new_thread(run,())
