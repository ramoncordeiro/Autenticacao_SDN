# Copyright 2012-2013 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
from collections import defaultdict
from pox.openflow.discovery import Discovery
from pox.lib.util import dpid_to_str
import time

#a partir desse import eu q to inserindo
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.packet.udp import udp
from pox.lib.packet.dns import dns

from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
import json


import random


import json
import sys
sys.path.append('pox/pox/forwarding')
sys.path.append('Autenticacao/br/ufpa/labsc')
#sys.path.append('pox/pox')
from forwarding.CodDecJson import CodDecJson
#verificar a pasta desses imports, porque talvez nao funcione

from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.CodDecEGCifra import CodDecEGCifra
from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalSgSK import ElGamalSgSK
from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalSgPK import ElGamalSgPK
from br.ufpa.labsc.libcrypto.misc.CodDecJson import CodDecJson
from br.ufpa.labsc.libcrypto.nizkp.PTAware import PTAware
from br.ufpa.labsc.libcrypto.nizkp.PTEquivTest import PTEquivTest


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
    if adjacency[b[0]][a[0]] != b[1]:
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

  assert _check_path(r), "Illegal path!"

  return r


class WaitingPath (object):
  """
  A path which is waiting for its path to be established
  """
  def __init__ (self, path, packet):
    print "packet in Init Waiting Path: ", packet
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
    print "packet in Init PathInstalled"

class Switch (EventMixin):
  def __init__ (self):
    self.connection = None
    self.ports = None
    print "ports: ",self.ports
    self.dpid = None
    self._listeners = None
    self._connected_at = None

    self.ip_addr = IPAddr('10.0.0.110')
    #self.dl_addr = EthAddr('00:00:00:00:05:05')
    self.hw_addr = EthAddr('00:00:00:00:00:09')#self.set_src('00:00:00:00:05:05')
    print "hw_addr: ", self.hw_addr

    self.cont_pkt_tcp=0
    self.seq_h1 = 0
    self.last_ack_cliente=None
    self.data_client1 = None
    self.data_client2 = None
    self.beta_received = None
    self.alfa_received = None


    #guardar acks enviados
    self.last_ack_cliente=None
    self.last_ack_aut2 = None
    self.last_ack_aut3 = None
    self.last_ack_aut4 = None
    self.last_ack_aut5 = None
    self.last_ack_aut6 = None

    self.mac_client = None
    self.port_client = None
    self.ip_client = None

    #conta para quantos autenticadores flag FIN foi enviada.
    self.contFIN_flag = 0
    self.contPSH_flag = 0
    #guarda dados da computacao dos autenticadores
    self.data_aut2 = []
    self.data_aut3 = []
    self.data_aut4 = []
    self.data_aut5 = []
    self.data_aut6 = []
    self.data_all_aut = []

    self.i2 = 0 #controla quantas vezes foi add dados do autenticador na lista
    self.i3 = 0
    self.i4 = 0
    self.i5 = 0
    self.i6 = 0
        
    self.last_ip=None
        

    # guarda index de cada autenticador que fara a computacao
    self.index_autent = []
    self.autenticadores = {2:'10.0.0.2',3:'10.0.0.3', 4:'10.0.0.4', 5:'10.0.0.5', 6:'10.0.0.6'}

    self.len_data_to_aut=None


    #ALFA E BETA guardados do Cliente 1
    self.ElgAlfa =881395515062685215134221687508086437247886166652208186348118004524042945970938760450044753087854974657415795982731542112603794546333758358341282057755695777949501791883528632953507994368350116881038933232948836272068287831241256302130340876663863499640162773364639034827078561154944479835326045585239144245
    self.ElgaBeta=895121886921517193802040926603312637366348382568919847099005675486567269556797609238082107923962668783978674151653674659457804568680172773322958220028131607062462724728386430325795137417520316613361113650831745705470938380385264164532988375731938566043053283757431310267859227068975511327019434172373575459

    self.ElgAlfa_pet = None
    self.ElgBeta_pet = None


    jsonPK = ''
    with open('/home/ramon/minhaschaves/MinhaChavePublica.json', 'r') as content_file:
        jsonPK = content_file.read()

    # decode PK json
    codDec = CodDecJson()
        
    pk = codDec.deserialize(jsonPK, ElGamalSgPK)

    self.p = pk.getPrimoP()
    self.q = pk.getPrimoQ()
    #print "P: ", self.p
    #print "Q: ", self.q




    jsonSK = ''
    with open('/home/ramon/minhaschaves/MinhaChavePrivada.json', 'r') as content_file:
        jsonSK = content_file.read()
    self.sk = codDec.deserialize(jsonSK, ElGamalSgSK)

  def __repr__ (self):
    return dpid_to_str(self.dpid)

  def _install (self, switch, in_port, out_port, match, buf = None):
    print "in func _install"
    msg = of.ofp_flow_mod()
    msg.match = match
    msg.match.in_port = in_port
    msg.idle_timeout = FLOW_IDLE_TIMEOUT
    msg.hard_timeout = FLOW_HARD_TIMEOUT
    msg.actions.append(of.ofp_action_output(port = out_port))
    msg.buffer_id = buf
    switch.connection.send(msg)

  def _install_path (self, p, match, packet_in=None):
    print "_install_path"
    wp = WaitingPath(p, packet_in)
    for sw,in_port,out_port in p:
      self._install(sw, in_port, out_port, match)
      msg = of.ofp_barrier_request()
      sw.connection.send(msg)
      wp.add_xid(sw.dpid,msg.xid)

  def install_path (self, dst_sw, last_port, match, event):
    print "in func install_path"
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
    self._install_path(p, match.flip())


  def _handle_PacketIn (self, event):
    print "packet in _handle_PacketIn Pure: ", event
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

    ################################################ COMECEI EDITAR DAQUI ################################################
        port = event.port
        self.macToPort[packet.src] = port
        #print "A porta que recebeu e: ", port
        #print "DPID e: ", event.connection.dpid
        if(packet.type == packet.ARP_TYPE):
            #print "PACOTE ARP RECEBIDO: "
            #print "-------------------------------------------------------------------------------------"
            #print packet
            self.handle_arp(packet,port, self.send_Syn_TCP)
        
        #if(packet.type == packet.TCP_TYPE):
        #    print "PACOTE TCP RECEBIDO"
           
        #if(packet.find('ipv4'))
        if(packet.type == packet.IP_TYPE):
            #print "PACOTE IP RECEBIDO"
            pkt_ip = packet.payload
            #print "pacote IPV4: ",pkt_ip
            #print "tamanho PACOTE IP recebido: ", pkt_ip.iplen
            #print "protocolo: ",pkt_ip.protocol

        if(packet.find('tcp')):
            #print "PACOTE TCP recebido:"
            pkt_tcp = pkt_ip.payload
            #print "pkt TCP: ", pkt_tcp
            if((pkt_ip.srcip!='10.0.0.2')&(pkt_ip.srcip!='10.0.0.3')&(pkt_ip.srcip!='10.0.0.4')&(pkt_ip.srcip!='10.0.0.5')&(pkt_ip.srcip!='10.0.0.6')):
                self.handle_tcp(packet,pkt_ip,pkt_tcp,port,self.random_choose,self.send_arp_to_aut,self.PetTest)
            else:
                self.handle_tcp_aut(packet,pkt_ip,pkt_tcp,port, self.insert_ack_aut, self.save_last_ack_aut, self.save_data_aut, self.computeM, self.get_data_aut, self.split_data_aut, self.get_data_one_aut, self.theat_list_data, self.send_flagConfirm_to_client)
                #self.handle_tcp(packet.TCP_TYPE):




   ######################################### ATE AQUI EU Q EDITEI HANDLE########################################################### 

    loc = (self, event.port) # Place we saw this ethaddr
    oldloc = mac_map.get(packet.src) # Place we last saw this ethaddr

    if packet.effective_ethertype == packet.LLDP_TYPE:
      drop()
      return

    if oldloc is None:
      if packet.src.is_multicast == False:
        mac_map[packet.src] = loc # Learn position for ethaddr
        log.debug("Learned %s at %s.%i", packet.src, loc[0], loc[1])
    elif oldloc != loc:
      # ethaddr seen at different place!
      if core.openflow_discovery.is_edge_port(loc[0].dpid, loc[1]):
        # New place is another "plain" port (probably)
        log.debug("%s moved from %s.%i to %s.%i?", packet.src,
                  dpid_to_str(oldloc[0].dpid), oldloc[1],
                  dpid_to_str(   loc[0].dpid),    loc[1])
        if packet.src.is_multicast == False:
          mac_map[packet.src] = loc # Learn position for ethaddr
          log.debug("Learned %s at %s.%i", packet.src, loc[0], loc[1])
      elif packet.dst.is_multicast == False:
        # New place is a switch-to-switch port!
        # Hopefully, this is a packet we're flooding because we didn't
        # know the destination, and not because it's somehow not on a
        # path that we expect it to be on.
        # If spanning_tree is running, we might check that this port is
        # on the spanning tree (it should be).
        if packet.dst in mac_map:
          # Unfortunately, we know the destination.  It's possible that
          # we learned it while it was in flight, but it's also possible
          # that something has gone wrong.
          log.warning("Packet from %s to known destination %s arrived "
                      "at %s.%i without flow", packet.src, packet.dst,
                      dpid_to_str(self.dpid), event.port)


    if packet.dst.is_multicast:
      log.debug("Flood multicast from %s", packet.src)
      flood()
    else:
      if packet.dst not in mac_map:
        log.debug("%s unknown -- flooding" % (packet.dst,))
        flood()
      else:
        dest = mac_map[packet.dst]
        match = of.ofp_match.from_packet(packet)
        self.install_path(dest[0], dest[1], match, event)

  #########################################################################################################################################
  #########################################################################################################################################
  #########################################################################################################################################
  ########################################################################################################################################
  ########################################################################################################################################      
  ########################################################## FUNCOES QUE EU FIZ ###########################################################
  def _send_packet(self,packet_in,out_port):
        '''
        msg = of.ofp_flow_mod()
        msg.data = packet_in
        msg.match.dl_dst = packet.src
        msg.match.dl_src = packet.dst
        msg.actions.append(of.ofp_action_output(port = event.port))
        event.connection.send(msg)
        '''
        
                
        msg = of.ofp_packet_out()
        msg.data = packet_in
        #msg.in_port = out_port
        # Add an action to send to the specified port
        action = of.ofp_action_output(port = out_port)
        msg.actions.append(action)

        # Send message to switch
        self.connection.send(msg)


  def handle_arp(self,packet,port,send_Syn_TCP):
        #if ((packet.payload.opcode==1) & (packet.payload.protodst.toStr() == '10.0.0.110')):
        if ((packet.payload.opcode==1)&(packet.payload.protodst.toStr() == '10.0.0.110')):
            #print "Requisicao ARP"
            arp_reply = arp()
            arp_reply.hwsrc=EthAddr('00:00:00:00:00:09')
            arp_reply.hwdst = packet.src
            arp_reply.opcode = arp.REPLY
            arp_reply.protosrc=packet.payload.protodst
            arp_reply.protodst=packet.payload.protosrc
            eth = ethernet()
            eth.type = ethernet.ARP_TYPE
            eth.dst = packet.src
            eth.src=EthAddr('ff:ff:fff:ff:ff:ff')
            eth.payload=arp_reply
            #"PRINT ENVIANDO RESPOSTA ARP"
            self._send_packet(eth.pack(),of.OFPP_ALL)
        
        if(packet.payload.opcode==2):
            #arp_aut.hwsrc=EthAddr('00:00:00:00:00:09')
            #        arp_aut.hwdst=EthAddr('ff:ff:ff:ff:ff:ff')
                    #arp_aut.hwdst=EthAddr('00:00:00:00:00:00')
            #        arp_aut.protosrc=self.ip_addr
            
            if(packet.payload.protosrc=='10.0.0.2'):
                self.send_Syn_TCP(packet,port)
            if(packet.payload.protosrc=='10.0.0.3'):
                self.send_Syn_TCP(packet,port)
            if(packet.payload.protosrc=='10.0.0.4'):
                self.send_Syn_TCP(packet,port)
            if(packet.payload.protosrc=='10.0.0.5'):
                self.send_Syn_TCP(packet,port)
            if(packet.payload.protosrc=='10.0.0.6'):    
                self.send_Syn_TCP(packet,port)


  def handle_ipv4(self,packet):
        #print "ipv4"
        print

  def handle_tcp(self,packet,pkt_ip,pkt_tcp,port, random_choose,send_arp_to_aut,PetTest):
        self.cont_pkt_tcp=+1
        if(pkt_tcp.SYN==True):
            #print "PACOTE SYN TCP Recebido"
            
            tcp_pk = tcp()
            tcp_pk.SYN = True
            tcp_pk.ACK = True
            tcp_pk.srcport=6633
            tcp_pk.dstport=pkt_tcp.srcport
            tcp_pk.seq=0
            #self.seq_h1=tcp_pk.seq
            tcp_pk.ack = pkt_tcp.seq+1
            self.last_ack_cliente = tcp_pk.ack
            #print "ACK SERA ENVIADO_SYN: ", tcp_pk.ack
            tcp_pk.win=28900
            tcp_pk.off=5
            
            ip_pk = ipv4()
            #ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pk)
            ip_pk.protocol= ipv4.TCP_PROTOCOL
            ip_pk.srcip=IPAddr('10.0.0.110')
            ip_pk.dstip=pkt_ip.srcip
            ip_pk.protocol=6
            ip_pk.set_payload(tcp_pk)
            ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pk)
            ip_pk.csum=0
            
            ether_pk = ethernet()
            ether_pk.set_payload(ip_pk)
            ether_pk.src=EthAddr('00:00:00:00:00:09')
            ether_pk.dst = packet.src
            ether_pk.type= ethernet.IP_TYPE
            
            
            self._send_packet(ether_pk.pack(),port)
        
        
        if(pkt_tcp.PSH==True):
            print "----------------------------------------------------PACOTE PSH ---------------------------------------------------------"
            #print "PACOTE COM DADOS RECEBIDO"
            print pkt_tcp
            #print "DADOS: ", pkt_tcp.payload
            #print "TAMANHO DO PACOTE TODO TCP: ", len(pkt_tcp)
            #print "TAMANHO DOS DADOS RECEBIDOS: ", len(pkt_tcp.payload)
            self.data_client2=pkt_tcp.payload
            #print "DADOS PSH: ", self.data_client1
            print "DADOS PSH: ",pkt_tcp.payload
            print "data_client2: ", self.data_client2
            print "------------------------------------------------------ END PSH  ------------------------------------------------------------"
            
            tcp_pkt1 = tcp()
            tcp_pkt1.ACK = True
            tcp_pkt1.srcport=6633
            tcp_pkt1.dstport = pkt_tcp.srcport
            self.port_client = pkt_tcp.srcport
            tcp_pkt1.seq = 1
            self.seq_h1 = tcp_pkt1.seq
            tcp_pkt1.ack = self.last_ack_cliente+ len(pkt_tcp.payload)
            tcp_pkt1.win=29200
            tcp_pkt1.off=5
            
            '''
            tcp_pk = tcp()
            ##tcp_pk.PSH = True
            tcp_pk.ACK = True
            tcp_pk.srcport=6633
            tcp_pk.dstport=pkt_tcp.srcport
            tcp_pk.seq=1
            self.seq_h1 = tcp_pk.seq
            ack = len(pkt_tcp.payload)+len(self.data_client2)+1#len(self.data_client2)+ len(pkt_tcp.payload)
            tcp_pk.ack = 1
            print "ACK SERA ENVIADO PSH: ", tcp_pk.ack
            tcp_pk.win=28900
            tcp_pk.off=5
            #tcp_pk.payload="Teste"
            '''



            ip_pk = ipv4()
            #ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pk)
            ip_pk.protocol= ipv4.TCP_PROTOCOL
            ip_pk.srcip=IPAddr('10.0.0.110')
            ip_pk.dstip=pkt_ip.srcip
            self.ip_client = ip_pk.dstip
            ip_pk.protocol=6
            ip_pk.set_payload(tcp_pkt1)
            ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pkt1)
            ip_pk.csum=0
            
            ether_pk = ethernet()
            ether_pk.set_payload(ip_pk)
            ether_pk.src=EthAddr('00:00:00:00:00:09')
            ether_pk.dst = packet.src
            self.mac_client = ether_pk.dst
            ether_pk.type= ethernet.IP_TYPE
        
            
            self._send_packet(ether_pk.pack(),port)



            # ---------------------------------------------------------- TRATO DE SEPARA AS ALFA E BETA ----------------------
            #print "DADOS 1: ", self.data_client1
            #print "DADOS 2: ", self.data_client2
            cifra = self.data_client1+self.data_client2
            #print "CIFRA CONCATENADA: ", cifra
            a = cifra.split(",")
            #print "a[0]: ",a[0]
            
            self.beta_received = a[0]
            bet = self.beta_received.split(" ")
            self.beta_received = bet[1]
            
            self.alfa_received = a[1]
            alf = self.alfa_received.split(" ")
            self.alfa_received = alf[2]
            print "BETA RECEBIDO DO CLIENTE: ", self.beta_received
            print "ALFA RECEBIDO DO CLIENTE: ", self.alfa_received
            self.PetTest(self.alfa_received,self.beta_received,self.ElgAlfa,self.ElgaBeta)
            #print "NOVO ALFA RECEIVED: ", self.alfa_received
            # ---------------------------------------------------------- TERMINO TRATAMENTO ALFA E BETA  RECEBIDOS----------------------------


            # VOU INSERIR AQUI A COMPARACAO DAS CIFRAS, MAS DEPOIS POSSO COLCOAR NUMA FUNCAO
            #---------------------------------------------------------------------------------------------------------------------
            #if((long(self.alfa_received)/self.ElgAlfa == 1) & (long(self.beta_received)/self.ElgaBeta == 1)):
            print "CLIENTE correto. Iniciara PROCESSO DE AUTENTICACAO"
            self.index_autent = self.random_choose()
            self.send_arp_to_aut(self.index_autent)
            
            #else:
                #print "CLIENTE NAO CORRETO. PROCESSO DE AUTENTICACAO TERMINARA"


            # --------------------------------------------------------------------------------------------------------------------    

            #PAREI AQUI. PRECISO COPIAR ESSAS FUNCOES DO CODIGO DO RYU E TESTAR DEPOIS AQUI.
            
            #autent = self.random_choose()
            #self.index_autent = autent
            
            #print "ESTA PASSANDO DA  FUNCAO SELF.RANDOM_CHOOSE"
            
            #self.send_arp_to_aut(autent,datapath)


        if((pkt_tcp.ACK==True)&(len(pkt_tcp) > 100) & (pkt_tcp.PSH==False)):
            print "----------------------------------------------------ACK COM DADOS ---------------------------------------------------------"
            #print "PACOTE COM ACK RECEBIDO:"
            print pkt_tcp
            #print "PACOTE TALVEZ tenha DADOS RECEBIDO"
            #print " POSSIVEIS DADOS: ", pkt_tcp.payload
            self.data_client1 = pkt_tcp.payload
            #print "DADOS ACK: ", self.data_client2
            #print "TAMANHO DO PACOTE TODO TCP: ", len(pkt_tcp)
            #print "TAMANHO DOS DADOS RECEBIDOS: ", len(pkt_tcp.payload)
            #print "PACOTE TODO: ", pkt_tcp
            print "DADOS DO ACK RECEBIDO: ", pkt_tcp.payload
            #print packet.packet.packet.payload
            print "----------------------------------------------------END ACK COM DADOS -------------------------------------------------------"
            

            tcp_pkt = tcp()
            tcp_pkt.ACK = True
            tcp_pkt.srcport=6633
            tcp_pkt.dstport=pkt_tcp.srcport
            tcp_pkt.seq=1
            tcp_pkt.ack = len(pkt_tcp.payload)+self.last_ack_cliente
            #print "ACK SERA ENVIADO DO ACK COM DADOS: ", tcp_pkt.ack
            self.last_ack_cliente = tcp_pkt.ack
            tcp_pkt.win=29200
            tcp_pkt.off=5


            
            '''
            #self.data_client.append(pkt_tcp.payload)
            #print "dados todos: ", self.data_client1
            #print "TAMANHO DADOS COMPLETO: ", len(self.data_client)
            tcp_pk = tcp()
            #tcp_pk.PSH = True
            tcp_pk.ACK = True
            tcp_pk.srcport=6633
            tcp_pk.dstport=pkt_tcp.srcport
            tcp_pk.seq=1
            self.seq_h1 = tcp_pk.seq
            ack = len(pkt_tcp.payload)
            tcp_pk.ack = ack+1#len(self.data_client1)+len(self.data_client2)+1
            print "ACK SERA ENVIADO no ACK DADOS: ", tcp_pk.ack
            #self.data_client1 = len(tcp_pk.payload)
            tcp_pk.win=28900
            tcp_pk.off=5
            #tcp_pk.payload="Teste"
            '''
            
            ip_pk = ipv4()
            #ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pk)
            ip_pk.protocol= ipv4.TCP_PROTOCOL
            ip_pk.srcip=IPAddr('10.0.0.110')
            ip_pk.dstip=pkt_ip.srcip
            ip_pk.protocol=6
            #ip_pk.set_payload(tcp_pk)
            ip_pk.set_payload(tcp_pkt)
            ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pkt)
            ip_pk.csum=0
            
            ether_pk = ethernet()
            ether_pk.set_payload(ip_pk)
            ether_pk.src=EthAddr('00:00:00:00:00:09')
            ether_pk.dst = packet.src
            ether_pk.type= ethernet.IP_TYPE
            
            print "----------------------------------------- DADOS 1 e 2   ------------------------------------------------------"
            #print "DADOS 1: ", self.data_client1
            #print "DADOS 2: ", self.data_client2
            
            self._send_packet(ether_pk.pack(),port)
        #print "tcp"

  def handle_tcp_aut(self,packet,pkt_ip,pkt_tcp,port, insert_ack_aut, save_last_ack_aut, save_data_aut, computeM, get_data_aut, split_data_aut, get_data_one_aut, theat_list_data, send_flagConfirm_to_client):
        if((pkt_tcp.SYN==True)&(pkt_tcp.ACK==True)):
            #AQUI VOU ENVIAR O ACK DO SYN-ACK E OS DADOS JA. DEPOIS POSSO COLOCAR O ENVIAR PSH NUMA FUNCAO
            tcp_pkt = tcp()
            tcp_pkt.ACK = True
            tcp_pkt.srcport=6633
            tcp_pkt.dstport=pkt_tcp.srcport
            tcp_pkt.seq=1
            seq = tcp_pkt.seq
            tcp_pkt.ack = pkt_tcp.seq+1
            ack = tcp_pkt.ack
            #self.last_ack_cliente = tcp_pkt.ack
            tcp_pkt.win=29200
            tcp_pkt.off=5

                       
            ip_pk = ipv4()
            #ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pk)
            ip_pk.protocol= ipv4.TCP_PROTOCOL
            ip_pk.srcip=IPAddr('10.0.0.110')
            ip_pk.dstip=pkt_ip.srcip
            ip_pk.protocol=6
            #ip_pk.set_payload(tcp_pk)
            ip_pk.set_payload(tcp_pkt)
            ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pkt)
            ip_pk.csum=0
            
            ether_pk = ethernet()
            ether_pk.set_payload(ip_pk)
            ether_pk.src=EthAddr('00:00:00:00:00:09')
            ether_pk.dst = packet.src
            ether_pk.type= ethernet.IP_TYPE

            self._send_packet(ether_pk.pack(),port)
        
            ###################################################################################################
            #ENVIOU DOS DADOS NO MESMO IF DO ACK                                                              #
            ###################################################################################################
            dados_send = []
            '''
            print "ALFA RECEBIDO: ",self.alfa_received
            print "ALFA GUARDADO: ", self.ElgAlfa
            print "#**#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#**#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#"
            div_alfa = long(self.alfa_received)/long(self.ElgAlfa)
            print "ALFA QUE SERA ENVIADO: ", div_alfa
            '''
            dados_send.append(self.ElgAlfa_pet)
            dados_send.append(self.index_autent)
            tcp_pkt = tcp()
            tcp_pkt.PSH= True
            tcp_pkt.ACK = True
            tcp_pkt.srcport=6633
            tcp_pkt.dstport=pkt_tcp.srcport
            tcp_pkt.seq= seq#1
            tcp_pkt.ack = ack#pkt_tcp.ack
            self.save_last_ack_aut(pkt_ip.srcip,tcp_pkt.ack)# = tcp_pkt.ack
            tcp_pkt.win=29200
            tcp_pkt.off=5
            dados_send= json.dumps(dados_send)
            tcp_pkt.payload=dados_send
            self.len_data_to_aut= len(tcp_pkt.payload)
                       
            ip_pk = ipv4()
            #ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pk)
            ip_pk.protocol= ipv4.TCP_PROTOCOL
            ip_pk.srcip=IPAddr('10.0.0.110')
            ip_pk.dstip=pkt_ip.srcip
            ip_pk.protocol=6
            #ip_pk.set_payload(tcp_pk)
            ip_pk.set_payload(tcp_pkt)
            ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pkt)
            ip_pk.csum=0
            
            ether_pk = ethernet()
            ether_pk.set_payload(ip_pk)
            ether_pk.src=EthAddr('00:00:00:00:00:09')
            ether_pk.dst = packet.src
            ether_pk.type= ethernet.IP_TYPE

            self._send_packet(ether_pk.pack(),port)
            #TERMINA ENVIO DADOS PARA AUTENTICADORES



        if(pkt_tcp.PSH==True):
            if(pkt_ip.srcip!=self.last_ip):
                self.contPSH_flag = self.contPSH_flag +1
            print "contPSH: ",self.contPSH_flag
            print "PACOTE PSH RECEBIDO NO handle_TCP_AUT:"
            print pkt_tcp
            print pkt_tcp.payload
            print"PAYLOAD DIVIDIDO, payload[0]: ", pkt_tcp.payload[0]
            print"PAYLOAD DIVIDIDO, payload[1]: ", pkt_tcp.payload[1]
            self.save_data_aut(pkt_ip.srcip,pkt_tcp.payload)
            
            dat__ = self.get_data_one_aut(pkt_ip.srcip)
            
            dat__2 = self.split_data_aut(dat__)
            print "DAT__", dat__
            
            
            #print "separado 1: ", dat__2[0]
            #print "separado 2: ", dat__2[1] 
            
            my_lst = ''.join(map(str, dat__2[0]))
            my_lst = long(my_lst)
            print(my_lst)
            
            my_lst_str = ''.join(map(str, dat__2[1]))
            my_lst_str = long(my_lst_str)
            print(my_lst_str)

            self.data_all_aut.append(my_lst)
            self.data_all_aut.append(my_lst_str)

            #self,di,l0,dj,l1,dk,l2,c,p
            
            '''
            if(self.contPSH_flag==3):
                self.data_all_aut = long(self.data_all_aut)
                m = self.computeM(self.data_all_aut[1],self.data_all_aut[0],self.data_all_aut[3],self.data_all_aut[2],self.data_all_aut[5],self.data_all_aut[4],long(self.ElgaBeta),long(p))
                print "*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#"
                print "MENSAGEM FINAL COMPUTADA: ", m
                print "*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#"
            '''
            '''
            ab1 = self.theat_list_data(dat__2[0])
            ab2 = self.theat_list_data(dat__2[1])
            print "ab1: ",ab1
            print "ab2: ",ab2
            
            
            print "DADOS DEPOIS DE FEITO TRATAMENTO: ", dat__
            #print "DADOS DEPOIS DE SPLIT: ", dat__2
            #print "INDICE 1 DADOS depois do tratamento: ", dat__[1]
            #print "INDICE 2 DADOS depois do tratamento: ", dat__[2]
            part1 = dat__[1]
            part2 = self.theat_list_data(dat__[3:])
            print "DADOS SEPARADOS 1 : ",part1
            print "DADOS SEPARADOS 2 : ",part2
            '''
            #a__ = self.get_data_one_aut(pkt_ip.srcip)
            #print "recuperando DADOS do autenticador: ", a__
            #ata = self.split_data_aut(a__)
            #self.data_all_aut.append(ata)
            #print "DADOS AUTENTICADOR,POS SPLIT: ", ata
            
            ack_ = len(pkt_tcp.payload)
            tcp_pkt = tcp()
            tcp_pkt.ACK = True
            tcp_pkt.srcport=6633
            tcp_pkt.dstport=pkt_tcp.srcport
            tcp_pkt.seq= self.len_data_to_aut+1
            tcp_pkt.ack = self.insert_ack_aut(pkt_ip.srcip)+ack_            #len(pkt_tcp.payload)+1 #AQUI VAI ENTRAR A FUNCAO QUE INSERE O ACK DE ACORDO COM AUTENTICADOR
            self.save_last_ack_aut(pkt_ip.srcip,tcp_pkt.ack) #= tcp_pkt.ack
            tcp_pkt.win=29200
            tcp_pkt.off=5

                       
            ip_pk = ipv4()
            #ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pk)
            ip_pk.protocol= ipv4.TCP_PROTOCOL
            ip_pk.srcip=IPAddr('10.0.0.110')
            ip_pk.dstip=pkt_ip.srcip
            ip_pk.protocol=6
            #ip_pk.set_payload(tcp_pk)
            ip_pk.set_payload(tcp_pkt)
            ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pkt)
            ip_pk.csum=0
            self.last_ip = ip_pk.srcip

            ether_pk = ethernet()
            ether_pk.set_payload(ip_pk)
            ether_pk.src=EthAddr('00:00:00:00:00:09')
            ether_pk.dst = packet.src
            ether_pk.type= ethernet.IP_TYPE

            self._send_packet(ether_pk.pack(),port)

            #FAZER COM QUE ENTRE NESSA FUNCAO E COMPUTE O FINAL.
            
            if(self.contPSH_flag>=3):
                #if(self.contPSH_flag==3):
                print "*****************************************##########################################******************************"
                #self.data_all_aut = long(self.data_all_aut)
                print "TODOS OS LAGRANGES E COMPUT AUTENTICADORES: ", self.data_all_aut
                print "self.data_all_aut[1]: ", self.data_all_aut[1]
                print "self.data_all_aut[3]: ", self.data_all_aut[3]
                print "self.data_all_aut[5]: ", self.data_all_aut[5]
                m = self.computeM(self.data_all_aut[1],self.data_all_aut[0],self.data_all_aut[3],self.data_all_aut[2],self.data_all_aut[5],self.data_all_aut[4],long(self.ElgaBeta),long(self.p))
                #print "*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#"
                print "MENSAGEM FINAL COMPUTADA: ", m
                self.send_flagConfirm_to_client(m)
                #print "*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#*#"
                
                '''
                self.get_data_aut()
                print"#####################---------------------------------#######################################################"
                print "DADOS DE TODOS OS AUTENTICADORES:"
                print "aqui: ", self.data_all_aut
                #mensagem_final = self.computeM(di,l0,dj,l1,dk,l2,c,p)
                #mensagem_final = self.computeM(self.data_all_aut[1],self.data_all_aut[0],self.data_all_aut[3],self.data_all_aut[2],self.data_all_aut[5],self.data_all_aut[4],self.beta_received,self.p)
                #print "MENSAGEM FINAL COMPUTADA PELO CONTROLADOR: ",mensagem_final
                print"#####################---------------------------------#######################################################"
                '''
            
            
            ## ENVIAR FIN-ACK AQUI
        if(pkt_tcp.FIN ==True):
            fin = tcp()
            #tcp_pkt = tcp()
            fin.FIN = True
            fin.ACK = True
            fin.srcport=6633
            fin.dstport=pkt_tcp.srcport
            fin.seq= pkt_tcp.ack#pkt_tcp.seq
            fin.ack = pkt_tcp.seq#pkt_tcp.ack+1            
            self.save_last_ack_aut(pkt_ip.srcip,fin.ack) #= tcp_pkt.ack
            fin.win=29200
            fin.off=5


            ip_pk = ipv4()
            #ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pk)
            ip_pk.protocol= ipv4.TCP_PROTOCOL
            ip_pk.srcip=IPAddr('10.0.0.110')
            ip_pk.dstip=pkt_ip.srcip
            ip_pk.protocol=6
            #ip_pk.set_payload(tcp_pk)
            ip_pk.set_payload(fin)
            ip_pk.iplen = ipv4.MIN_LEN + len(fin)
            ip_pk.csum=0
            
            ether_pk_ = ethernet()
            ether_pk_.set_payload(ip_pk)
            ether_pk_.src=EthAddr('00:00:00:00:00:09')
            ether_pk_.dst = packet.src
            ether_pk_.type= ethernet.IP_TYPE

            self._send_packet(ether_pk_.pack(),port)
        


        if((pkt_tcp.ACK==True)&(len(pkt_tcp) > 150) & (pkt_tcp.PSH==False)):
            #print "---------------------------------------ACK COM DADOS  DO AUTENTICADOR ---------------------------------------------"
            #print "PACOTE COM ACK RECEBIDO:"
            print pkt_tcp
            #print "PACOTE TALVEZ tenha DADOS RECEBIDO"
            self.save_data_aut(pkt_ip.srcip,pkt_tcp.payload)
            #print " POSSIVEIS DADOS: ", pkt_tcp.payload
            #self.data_client1 = pkt_tcp.payload
            #print "DADOS ACK: ", self.data_client2
            ack_ack = len(pkt_tcp.payload)
            #print "TAMANHO DO PACOTE TODO TCP: ", len(pkt_tcp)
            #print "TAMANHO DOS DADOS RECEBIDOS: ", len(pkt_tcp.payload)
            #print "PACOTE TODO: ", pkt_tcp
            #print "DADOS DO ACK RECEBIDO: ", pkt_tcp.payload
            #print packet.packet.packet.payload
            #print "--------------------------------------------END ACK COM DADOS do Autenticador -----------------------------------"
            

            tcp_pkt = tcp()
            tcp_pkt.ACK = True
            tcp_pkt.srcport=6633
            tcp_pkt.dstport=pkt_tcp.srcport
            tcp_pkt.seq=self.len_data_to_aut+1
            tcp_pkt.ack = self.insert_ack_aut(pkt_ip.srcip)+ack_ack #AQUI VAI ENTRAR A FUNCAO QUE INSERE ACK DE ACORDO COM IP AUTENTICADOR
            self.save_last_ack_aut(pkt_ip.srcip,tcp_pkt.ack)
            #self.last_ack_aut3 = tcp_pkt.ack
            print "ACK SERA ENVIADO DO ACK COM DADOS: ", tcp_pkt.ack
            #self.last_ack_cliente = tcp_pkt.ack
            tcp_pkt.win=29200
            tcp_pkt.off=5


                       
            ip_pk = ipv4()
            #ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pk)
            ip_pk.protocol= ipv4.TCP_PROTOCOL
            ip_pk.srcip=IPAddr('10.0.0.110')
            ip_pk.dstip=pkt_ip.srcip
            ip_pk.protocol=6
            #ip_pk.set_payload(tcp_pk)
            ip_pk.set_payload(tcp_pkt)
            ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pkt)
            ip_pk.csum=0
            
            ether_pk = ethernet()
            ether_pk.set_payload(ip_pk)
            ether_pk.src=EthAddr('00:00:00:00:00:09')
            ether_pk.dst = packet.src
            ether_pk.type= ethernet.IP_TYPE
            
                       
            self._send_packet(ether_pk.pack(),port)


  

  def random_choose(self):
        controllers = random.sample(range(2,6), 3) #porque o ID dos autenticadores esta entre 2 e 6
        print "------------------------------------------- controladores escolhidos: ----------------------------------------------"
        print "controladores escolhidos: ", controllers
        #print "tipo :", type(controllers[0])
        return controllers

  def send_arp_to_aut(self,vector):
        #print "ESTA ENTRANDO NA FUNCAO SEND_ARP_TO_AUT ----------------------------------------------------------------"
        for i in vector:
            #print "ENTRANDO primeiro FOR"
            #print "valor de i: ",i
            for j in self.autenticadores.keys():
                #print "Entrando segundo for"
                #print "valor de J: ",j
                #print "valor de I dentro de for j: ",i
                if (i == j):
                    ip = self.autenticadores[j]
                    print "-------------------------------------------------IP sera enviado ARP REQ ----------------------------------------------- ", ip
                    port = i
                    print "porta e: ", port
                    arp_aut = arp()
                    arp_aut.opcode=1 #request
                    arp_aut.hwsrc=EthAddr('00:00:00:00:00:09')
                    arp_aut.hwdst=EthAddr('ff:ff:ff:ff:ff:ff')
                    #arp_aut.hwdst=EthAddr('00:00:00:00:00:00')
                    arp_aut.protosrc=self.ip_addr
                    arp_aut.protodst=IPAddr(ip)

                    ether = ethernet()
                    ether.type=ethernet.ARP_TYPE
                    ether.dst=EthAddr('ff:ff:ff:ff:ff:ff')
                    ether.src=EthAddr('00:00:00:00:00:09')
                    ether.payload=arp_aut
                    self._send_packet(ether.pack(),port)
    


    
  def send_flagConfirm_to_client(self, m):
        tcp_pkt = tcp()
        m = json.dumps(m)
        tcp_pkt.set_payload("sim")
        tcp_pkt.PSH = True
        tcp_pkt.ACK = True
        tcp_pkt.srcport=6633
        tcp_pkt.dstport=self.port_client
        tcp_pkt.seq= self.seq_h1
        #seq = tcp_pkt.seq
        tcp_pkt.ack = self.last_ack_cliente     #pkt_tcp.seq+1
        #ack = tcp_pkt.ack
        #self.last_ack_cliente = tcp_pkt.ack
        tcp_pkt.win=29200
        tcp_pkt.off=5

                       
        ip_pk = ipv4()
        #ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pk)
        ip_pk.protocol= ipv4.TCP_PROTOCOL
        ip_pk.srcip=IPAddr('10.0.0.110')
        ip_pk.dstip= self.ip_client
        ip_pk.protocol=6
        #ip_pk.set_payload(tcp_pk)
        ip_pk.set_payload(tcp_pkt)
        ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pkt)
        ip_pk.csum=0
            
        ether_pk = ethernet()
        ether_pk.set_payload(ip_pk)
        ether_pk.src=EthAddr('00:00:00:00:00:09')
        ether_pk.dst = self.mac_client
        ether_pk.type= ethernet.IP_TYPE

        self._send_packet(ether_pk.pack(),self.port_client)





  


  #########################################################################################################################################
  #########################################################################################################################################
  #########################################################################################################################################
  ########################################################################################################################################
  ########################################################################################################################################      
  ################################################### END  FUNCOES QUE EU FIZ  TRATAMENTO PACOTES ##########################################




  ########################################################################################################################################
  ################################################# HERE THREAT SOME CASES OF AUTENTICATORS TCP PACKETS ##################################
  ########################################################################################################################################
  ########################################################################################################################################
  ########################################################################################################################################
  ########################################################################################################################################

  def send_Syn_TCP(self,packet,port):
        tcp_pk = tcp()
        tcp_pk.SYN = True
        tcp_pk.srcport=6633
        tcp_pk.dstport=5000
        tcp_pk.seq=0
        #self.seq_h1=tcp_pk.seq
        tcp_pk.ack = 0
        #self.last_ack_cliente = tcp_pk.ack
        #print "ACK SERA ENVIADO_SYN: ", tcp_pk.ack
        tcp_pk.win=28900
        tcp_pk.off=5
            
        ip_pk = ipv4()
        #ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pk)
        ip_pk.protocol= ipv4.TCP_PROTOCOL
        ip_pk.srcip=IPAddr('10.0.0.110')
        ip_pk.dstip=packet.payload.protosrc
        ip_pk.protocol=6
        ip_pk.set_payload(tcp_pk)
        ip_pk.iplen = ipv4.MIN_LEN + len(tcp_pk)
        ip_pk.csum=0
            
        ether_pk = ethernet()
        ether_pk.set_payload(ip_pk)
        ether_pk.src=EthAddr('00:00:00:00:00:09')
        ether_pk.dst = packet.src
        ether_pk.type= ethernet.IP_TYPE
            
        print "SEND SYN PARA : ",ip_pk.dstip
        self._send_packet(ether_pk.pack(),port)

    
    
  def insert_ack_aut(self,ip):
        if(ip=='10.0.0.2'):
            return self.last_ack_aut2

        if(ip=='10.0.0.3'):
            return self.last_ack_aut3

        if(ip=='10.0.0.4'):
            return self.last_ack_aut4

        if(ip=='10.0.0.5'):
            return self.last_ack_aut5

        if(ip=='10.0.0.6'):
            return self.last_ack_aut6

    
    
  def save_last_ack_aut(self,ip,ack):
        if(ip=='10.0.0.2'):
            self.last_ack_aut2 = ack
        
        if(ip=='10.0.0.3'):
            self.last_ack_aut3 = ack

        if(ip=='10.0.0.4'):
            self.last_ack_aut4 = ack

        if(ip=='10.0.0.5'):
            self.last_ack_aut5 = ack

        if(ip=='10.0.0.6'):
            self.last_ack_aut6 = ack



  def save_data_aut(self,ip,data):
        if(ip=='10.0.0.2'):
            self.i2+=1
            self.data_aut2.append(data)
            if(self.i2==2):
                self.data_aut2 = self.data_aut2[0]+self.data_aut2[1]
        if(ip=='10.0.0.3'):
            self.i3+=1
            self.data_aut3.append(data)
            if(self.i3==2):
                self.data_aut3 = self.data_aut3[0]+self.data_aut3[1]

        if(ip=='10.0.0.4'):
            self.i4+=1
            self.data_aut4.append(data)
            if(self.i4==2):
                self.data_aut4 = self.data_aut4[0]+self.data_aut4[1]

        if(ip=='10.0.0.5'):
            self.i5+=1
            self.data_aut5.append(data)
            if(self.i5==2):
                self.data_aut5 = self.data_aut5[0]+self.data_aut5[1]

        if(ip=='10.0.0.6'):
            self.i6+=1
            self.data_aut6.append(data)
            if(self.i6==2):
                self.data_aut6 = self.data_aut6[0]+self.data_aut6[1]
        

  def order_data_aut(self,ip):
        if(ip=='10.0.0.2'):
            cifra = self.data_aut2[0]+self.data_aut2[1]
            #print "CIFRA CONCATENADA: ", cifra
            a = cifra.split(",")
            #print "a[0]: ",a[0]
            
            self.beta_received = a[0]
            self.data_aut2 = a[0]

            bet = self.beta_received.split(" ")
            dat = self.data_aut2.split(" ")

            self.beta_received = bet[1]
            
            self.alfa_received = a[1]
            alf = self.alfa_received.split(" ")
            self.alfa_received = alf[2]

    
  def split_data_aut(self,data):
        data_threated = []
        part1 = []
        part2 = []
        a = data[0:data.index(",")]
        b = data[data.index(","):]
        for n in a:#a[0]:
            try:
                part1.append(int(n)) 
            except:
                pass

        for j in b:#a[1]:
            try:
                part2.append(int(j)) 
            except:
                pass
        
        #print "PART1: ", part1
        #print "PART2: ",part2

        data_threated.append(part1)
        data_threated.append(part2)
        return data_threated


  def get_data_aut(self):
        for i in self.autenticadores.keys():
            for j in self.index_autent:
                if((j==i)&(i==2)):
                    self.data_all_aut.append(self.data_aut2[0])
                    self.data_all_aut.append(self.data_aut2[1])
                if((j==i)&(i==3)):
                    self.data_all_aut.append(self.data_aut3[0])
                    self.data_all_aut.append(self.data_aut3[1])
                if((j==i)&(i==4)):
                    self.data_all_aut.append(self.data_aut4[0])
                    self.data_all_aut.append(self.data_aut4[1])
                if((j==i)&(i==5)):
                    self.data_all_aut.append(self.data_aut5[0])
                    self.data_all_aut.append(self.data_aut5[1])
                if((j==i)&(i==6)):
                    self.data_all_aut.append(self.data_aut6[0])
                    self.data_all_aut.append(self.data_aut6[1])
                #if(self.autenticadores.keys==2):
                #    self.data_all_aut.append(self.data_aut6)
    


  def get_data_one_aut(self,ip):
        if(ip=='10.0.0.2'):
            return self.data_aut2
        
        if(ip=='10.0.0.3'):
            return self.data_aut3

        if(ip=='10.0.0.4'):
            return self.data_aut4

        if(ip=='10.0.0.5'):
            return self.data_aut5

        if(ip=='10.0.0.6'):
            return self.data_aut6



  def theat_list_data(self,lista):
        
        #print "LISTA DENTRO get_index_aut: ", lista
        #print "Lista[0]: ", lista[0]
        #print "Lista[1]: ", lista[1]
        #print "Lista[2]: ", lista[2]
        aut_index=[]
        
        for n in lista-1:
            try:
                aut_index.append(int(n)) 
            except:
                pass
        return aut_index
  ### ------------------------------------------------ FUNCOES DE CRIPTOGRAFIA --------------------------------------------------###
  def computeM(self,di,l0,dj,l1,dk,l2,c,p):
        print "**************************************************************************************************************************"
        print "*--------------------------------------------- Dentro da funcao computerM ----------------------------------------------**"
        print "##########################################################################################################################"
        print "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$"
        print "di: ", di
        print "l0: ", l0
        print
        print "dj: ", dj
        print "l1: ", l1
        print
        print "dk: ", dk
        print "l2: ", l2
        print
        da = pow(di,l0,p)
        db = pow(dj, l1,p)
        dc = pow(dk, l2,p)
        j = (da*db*dc)
        m = (pow(j,p-2,p)*c)%p
        print "MENSAGEM COMPUTADA: ", m
        print "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$"
        print "##########################################################################################################################" 
        print "**************************************************************************************************************************"
        return m


  def PetTest(self,alfaReceived,betaReceived,alfaSaved,betaSaved):
        self.ElgAlfa_pet = long(self.alfa_received) * pow(long(self.ElgAlfa),long(self.sk.p)-2,long(self.sk.p))
        self.ElgBeta_pet = long(self.beta_received) * pow(long(self.ElgaBeta),long(self.sk.p)-2,long(self.sk.p))






  ########################################################################################################################################
  ################################################# END HERE THREAT SOME CASES OF AUTENTICATORS TCP PACKETS ##############################
  ########################################################################################################################################
  ########################################################################################################################################
  ########################################################################################################################################
  ########################################################################################################################################


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
        if sw is sw1 and port == l.port1: bad_macs.add(mac)
        if sw is sw2 and port == l.port2: bad_macs.add(mac)
      for mac in bad_macs:
        log.debug("Unlearned %s", mac)
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

  timeout = min(max(PATH_SETUP_TIME, 5) * 2, 15)
  Timer(timeout, WaitingPath.expire_waiting_paths, recurring=True)
