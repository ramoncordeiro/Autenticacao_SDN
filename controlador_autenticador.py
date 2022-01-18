# Copyright 2012 James McCauley
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
This component is for use with the OpenFlow tutorial.

It acts as a simple hub, but can be modified to act like an L2
learning switch.

It's roughly similar to the one Brandon Heller did for NOX.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.packet.udp import udp
from pox.lib.packet.dns import dns

from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
import json
'''
from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.CodDecEGCifra import CodDecEGCifra
from br.ufpa.labsc.libcrypto.cryptosys.elgamalsg.ElGamalSgSK import ElGamalSgSK
from br.ufpa.labsc.libcrypto.misc.CodDecJson import CodDecJson
from br.ufpa.labsc.libcrypto.nizkp.PTAware import PTAware
from br.ufpa.labsc.libcrypto.nizkp.PTEquivTest import PTEquivTest
import MySQLdb as mysqldb
'''
log = core.getLogger()



class Tutorial (object):
  """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.mac_to_port = {}

    self.count_dns = 0
    self.count_arp = 0
    self.logados = ['00:00:00:00:00:02']
    self.lastACK = {}
    self.lastSEQ = {}
    self.data_to_auth = {}
    self.count = {}


  def resend_packet (self, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)


  def act_like_hub (self, packet, packet_in):
    """
    Implement hub-like behavior -- send all packets to all ports besides
    the input port.
    """

    # We want to output to all ports -- we do that using the special
    # OFPP_ALL port as the output port.  (We could have also used
    # OFPP_FLOOD.)
    self.resend_packet(packet_in, of.OFPP_ALL)

    # Note that if we didn't get a valid buffer_id, a slightly better
    # implementation would check that we got the full data before
    # sending it (len(packet_in.data) should be == packet_in.total_len)).


  def act_like_switch (self, packet, packet_in):
    """
    Implement switch-like behavior.
    """

    """ # DELETE THIS LINE TO START WORKING ON THIS (AND THE ONE BELOW!) #

    # Here's some psuedocode to start you off implementing a learning
    # switch.  You'll need to rewrite it as real Python code.

    # Learn the port for the source MAC
    self.mac_to_port ... <add or update entry>

    if the port associated with the destination MAC of the packet is known:
      # Send packet out the associated port
      self.resend_packet(packet_in, ...)

      # Once you have the above working, try pushing a flow entry
      # instead of resending the packet (comment out the above and
      # uncomment and complete the below.)

      log.debug("Installing flow...")
      # Maybe the log statement should have source/destination/port?

      #msg = of.ofp_flow_mod()
      #
      ## Set fields to match received packet
      #msg.match = of.ofp_match.from_packet(packet)
      #
      #< Set other fields of flow_mod (timeouts? buffer_id?) >
      #
      #< Add an output action, and send -- similar to resend_packet() >

    else:
      # Flood the packet out everything but the input port
      # This part looks familiar, right?
      self.resend_packet(packet_in, of.OFPP_ALL)

    """ # DELETE THIS LINE TO START WORKING ON THIS #

  def handle_arp(self, packet):
    if packet.type == packet.ARP_TYPE:
      #print type(packet.payload.protosrc)
      #print type(packet.payload.protodst)
      if packet.payload.opcode == arp.REQUEST and packet.payload.protodst.toStr() == '10.0.2.3' :
        print "It's an ARP packet - REQUEST!"
        print packet.payload
        arp_reply = arp()
        arp_reply.hwsrc = EthAddr('00:00:00:00:00:00')
        arp_reply.hwdst = packet.src
        arp_reply.opcode = arp.REPLY
        arp_reply.protosrc = packet.payload.protodst
        arp_reply.protodst = packet.payload.protosrc
        ether = ethernet()
        ether.type = ethernet.ARP_TYPE
        ether.dst = packet.src
        ether.src = EthAddr('00:00:00:00:00:00')
        ether.payload = arp_reply

        self.act_like_hub(packet, ether.pack())
        print 'ARP REPLY SENT!!!'
      elif packet.payload.opcode == arp.REQUEST and packet.payload.protodst.toStr() == '10.0.0.5' :
        print "It's an ARP packet - REQUEST!"
        print packet.payload
        arp_reply = arp()
        arp_reply.hwsrc = EthAddr('00:00:00:00:00:05')
        arp_reply.hwdst = packet.src
        arp_reply.opcode = arp.REPLY
        arp_reply.protosrc = packet.payload.protodst
        arp_reply.protodst = packet.payload.protosrc
        ether = ethernet()
        ether.type = ethernet.ARP_TYPE
        ether.dst = packet.src
        ether.src = EthAddr('00:00:00:00:00:05')
        ether.payload = arp_reply

        self.act_like_hub(packet, ether.pack())
        print 'ARP REPLY SENT!!!'
      elif packet.payload.opcode == arp.REQUEST:
        print "It's an ARP packet - REQUEST!"
        print packet.payload
      elif packet.payload.opcode == arp.REPLY:
        print "It's an ARP packet - REPLY"

  def handle_tcp_handshake(self, packet):
    tcp_ver = packet.find('tcp')
    if tcp_ver is None:
      print "Not tcp..."
    else:
      #print "Yes! It's tcp!"
      #print packet.payload
      #print packet.payload.payload
      #print packet.payload.payload.payload
      
      #payload = "MESSAGE"
      tcp_packet = tcp()
      tcp_packet.srcport = 5000
      tcp_packet.dstport = packet.payload.payload.srcport
      #tcp_packet.payload = payload
      #tcp_packet.seq = packet.payload.payload.seq + 100
      tcp_packet.seq = 1
      tcp_packet.ack = packet.payload.payload.seq + 1
      self.lastACK[packet.src.toStr()] = packet.payload.payload.seq + 1
      self.lastSEQ[packet.src.toStr()] = packet.payload.payload.seq
      tcp_packet.SYN = True
      tcp_packet.ACK = True
      tcp_packet.win = 28960
      tcp_packet.off = 5

      ipv4_packet = ipv4()
      ipv4_packet.iplen = ipv4.MIN_LEN + len(tcp_packet)
      ipv4_packet.protocol = ipv4.TCP_PROTOCOL
      #ipv4_packet.dstip = IPAddr('10.0.0.2')
      ipv4_packet.dstip = packet.payload.srcip
      ipv4_packet.srcip = IPAddr('10.0.0.5')
      ipv4_packet.set_payload(tcp_packet)

      eth_packet = ethernet()
      eth_packet.set_payload(ipv4_packet)
      #eth_packet.dst = EthAddr('00:00:00:00:00:02')
      eth_packet.dst = packet.src
      eth_packet.src = EthAddr('00:00:00:00:00:05')
      eth_packet.type = ethernet.IP_TYPE

      self.act_like_hub(packet, eth_packet.pack())
      #print eth_packet.payload
      #print eth_packet.payload.csum
      print eth_packet.payload.payload
      #print eth_packet.payload.payload.csum

  def handle_tcp_ack(self, packet):
    tcp_ver = packet.find('tcp')
    if tcp_ver is None:
      print "Not tcp..."
    else:
      #print "Yes! It's tcp!"
      #print packet.payload
      #print packet.payload.payload
      #print packet.payload.payload.payload
      
      #print 'Data to auth: ' + self.data_to_auth

      #payload = "MESSAGE"
      tcp_packet = tcp()
      #tcp_packet.payload = "REPLY MESSAGE"
      tcp_packet.srcport = 5000
      tcp_packet.dstport = packet.payload.payload.srcport
      #tcp_packet.payload = payload
      #tcp_packet.seq = packet.payload.payload.seq + 100
      tcp_packet.seq = 2
      tcp_packet.ack = len(packet.payload.payload.payload) + self.lastACK[packet.src.toStr()]
      self.lastACK[packet.src.toStr()] = len(packet.payload.payload.payload) + self.lastACK[packet.src.toStr()]
      #tcp_packet.SYN = True
      tcp_packet.ACK = True
      tcp_packet.win = 28960
      tcp_packet.off = 5

      ipv4_packet = ipv4()
      ipv4_packet.iplen = ipv4.MIN_LEN + len(tcp_packet)
      ipv4_packet.protocol = ipv4.TCP_PROTOCOL
      #ipv4_packet.dstip = IPAddr('10.0.0.2')
      ipv4_packet.dstip = packet.payload.srcip
      ipv4_packet.srcip = IPAddr('10.0.0.5')
      ipv4_packet.set_payload(tcp_packet)

      eth_packet = ethernet()
      eth_packet.set_payload(ipv4_packet)
      #eth_packet.dst = EthAddr('00:00:00:00:00:02')
      eth_packet.dst = packet.src
      eth_packet.src = EthAddr('00:00:00:00:00:05')
      eth_packet.type = ethernet.IP_TYPE

      self.act_like_hub(packet, eth_packet.pack())
      #print eth_packet.payload
      #print eth_packet.payload.csum
      print eth_packet.payload.payload
      #print eth_packet.payload.payload.csum


  def handle_tcp(self, packet, payload):
      
      #payload = "MESSAGE"
      tcp_packet = tcp()
      tcp_packet.payload = payload
      tcp_packet.srcport = 5000
      tcp_packet.dstport = packet.payload.payload.srcport
      #tcp_packet.payload = payload
      #tcp_packet.seq = packet.payload.payload.seq + 100
      tcp_packet.seq = 2
      tcp_packet.ack = self.lastACK[packet.src.toStr()]
      #tcp_packet.SYN = True
      tcp_packet.ACK = True
      tcp_packet.win = 28960
      tcp_packet.off = 5

      ipv4_packet = ipv4()
      ipv4_packet.iplen = ipv4.MIN_LEN + len(tcp_packet)
      ipv4_packet.protocol = ipv4.TCP_PROTOCOL
      #ipv4_packet.dstip = IPAddr('10.0.0.2')
      ipv4_packet.dstip = packet.payload.srcip
      ipv4_packet.srcip = IPAddr('10.0.0.5')
      ipv4_packet.set_payload(tcp_packet)

      eth_packet = ethernet()
      eth_packet.set_payload(ipv4_packet)
      #eth_packet.dst = EthAddr('00:00:00:00:00:02')
      eth_packet.dst = packet.src
      eth_packet.src = EthAddr('00:00:00:00:00:05')
      eth_packet.type = ethernet.IP_TYPE

      self.act_like_hub(packet, eth_packet.pack())
      #print eth_packet.payload
      #print eth_packet.payload.csum
      print eth_packet.payload.payload
      #print eth_packet.payload.payload.csum

  def handle_tcp_teardown(self, packet):
      
      #payload = "MESSAGE"
      tcp_packet = tcp()
      #tcp_packet.payload = payload
      tcp_packet.srcport = 5000
      tcp_packet.dstport = packet.payload.payload.srcport
      #tcp_packet.payload = payload
      #tcp_packet.seq = packet.payload.payload.seq + 100
      tcp_packet.seq = packet.payload.payload.ack
      tcp_packet.ack = packet.payload.payload.seq + 1
      tcp_packet.FIN = True
      tcp_packet.ACK = True
      tcp_packet.win = 28960
      tcp_packet.off = 5

      ipv4_packet = ipv4()
      ipv4_packet.iplen = ipv4.MIN_LEN + len(tcp_packet)
      ipv4_packet.protocol = ipv4.TCP_PROTOCOL
      #ipv4_packet.dstip = IPAddr('10.0.0.2')
      ipv4_packet.dstip = packet.payload.srcip
      ipv4_packet.srcip = IPAddr('10.0.0.5')
      ipv4_packet.set_payload(tcp_packet)

      eth_packet = ethernet()
      eth_packet.set_payload(ipv4_packet)
      #eth_packet.dst = EthAddr('00:00:00:00:00:02')
      eth_packet.dst = packet.src
      eth_packet.src = EthAddr('00:00:00:00:00:05')
      eth_packet.type = ethernet.IP_TYPE

      self.act_like_hub(packet, eth_packet.pack())
      #print eth_packet.payload
      #print eth_packet.payload.csum
      print eth_packet.payload.payload
      #print eth_packet.payload.payload.csum
      

  def handle_dns(self, packet):
    print packet.payload
    print packet.payload.payload
    print packet.payload.payload.payload
    ip_packet = packet.payload
    udp_packet = packet.payload.payload
    dns_request = packet.payload.payload.payload
    print dns_request.questions[0].name
    print dns_request.questions[0].qtype
    print dns_request.questions[0].qclass
    #self.handle_arp(packet)
    #print packet.payload.payload.payload
    
    #print len(dns_request.questions)

    if dns_request.questions[0].qtype == 1:
      answer = dns.rr(dns_request.questions[0].name, dns_request.questions[0].qtype, dns_request.questions[0].qclass, 86400, len('000.000.000.000'), IPAddr('10.0.0.5'))
    elif dns_request.questions[0].qtype == 12:
      answer = dns.rr(dns_request.questions[0].name, dns_request.questions[0].qtype, dns_request.questions[0].qclass, 86400, len('www.ufrj.br'), 'www.ufrj.br')

    dns_resp = dns()
    dns_resp.qr = 1
    dns_resp.aa = 1
    dns_resp.answers.append(answer)
    dns_resp.questions = dns_request.questions
    dns_resp.id = dns_request.id
    #dns_resp.total_questions = dns.total_questions
    #dns_resp.total_answers = 1

    udp_resp = udp()
    udp_resp.srcport = udp_packet.dstport
    udp_resp.dstport = udp_packet.srcport
    udp_resp.len = len(dns_resp) + udp.MIN_LEN
    #udp_resp.csum = udp.checksum()
    udp_resp.set_payload(dns_resp)

    ipv4_packet = ipv4()
    ipv4_packet.iplen = ipv4.MIN_LEN + len(udp_resp)
    ipv4_packet.protocol = ipv4.UDP_PROTOCOL
    #ipv4_packet.dstip = IPAddr('10.0.0.2')
    ipv4_packet.dstip = packet.payload.srcip
    ipv4_packet.srcip = IPAddr('10.0.2.3')
    ipv4_packet.set_payload(udp_resp)

    eth_packet = ethernet()
    eth_packet.set_payload(ipv4_packet)
    #eth_packet.dst = EthAddr('00:00:00:00:00:02')
    eth_packet.dst = packet.src
    eth_packet.src = EthAddr('00:00:00:00:00:00')
    eth_packet.type = ethernet.IP_TYPE

    self.act_like_hub(packet, eth_packet.pack())
    print 'DNS response sent!!!'

  
  def authenticate(self, received_data):
    jsonSK = ''
    with open('/home/user/MinhaChavePrivada.json', 'r') as content_file:
        jsonSK = content_file.read()

    # decode SK json
    codDec = CodDecJson()
    sk = codDec.deserialize(jsonSK, ElGamalSgSK)

    data = received_data.split(';')

    # data[1] -> plaintext aware challenge
    pt_aware = PTAware()
    pt_aware_challenge = json.loads(data[1])
    #result = 'Plaintext Aware = ' + str(pt_aware.verify(pt_aware_challenge))
    result1 = pt_aware.verify(pt_aware_challenge)

    # data[0] -> password ciphertext
    c1 = codDec.deserialize(data[0], CodDecEGCifra)

    c2 = None
    if c1.desc == "cadastro":
        print "Cadastro!!!"
        con = mysqldb.connect('localhost', 'root', 'root', 'autenticacao')
        cur = con.cursor()
        sql = "INSERT INTO usuario(nomeusuario, senha) VALUES(%s, %s)"
        args = ('nomeusuario', data[0])
        cur.execute(sql, args)
        con.commit()
        c2 = c1
    elif c1.desc == "autentica":
        print "Autentica!!!"
        con = mysqldb.connect('localhost', 'root', 'root', 'autenticacao')
        cur = con.cursor()
        sql = "SELECT senha FROM usuario WHERE id=1"
        #args = ('nomeusuario', data[0])
        cur.execute(sql)
        c2_json = cur.fetchone()[0]
        c2 = codDec.deserialize(c2_json, CodDecEGCifra)

    pet = PTEquivTest(sk)
    #result = result + '\n' + 'PET = ' + str(pet.PET(c1, c2))
    result2 = pet.PET(c1, c2)

    result_dic = None
    if result1 and result2:
        result_dic = {'desc': 'autentica' , 'result': 'OK'}
    else:
        result_dic = {'desc': 'autentica' , 'result': 'NOT OK'}

    result = json.dumps(result_dic)
    return result


  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """
    
    packet = event.parsed # This is the parsed packet data.    
    print "PACOTE RECEBIDO: ",packet
    '''
    if packet.src.toStr() == '00:00:00:00:00:05':
			if packet.find('tcp'):
				try:
					result_json = packet.payload.payload.payload
					result_dic = json.loads(result_json)
					if result_dic['desc'] == 'autentica':
						if result_dic['result'] == 'OK':
							self.logados.append(packet.dst.toStr())
							print "ADICIONOU!!!"
							print self.logados
				except (RuntimeError, TypeError, NameError, AttributeError, ValueError):
					pass

			packet_in = event.ofp # The actual ofp_packet_in message.
			self.act_like_hub(packet, packet_in)
    '''
    if packet.dst.toStr() == '00:00:00:00:00:05':
      if packet.find('tcp'):
        if packet.payload.payload.SYN == True:
          self.count[packet.src.toStr()] = 0
          self.data_to_auth[packet.src.toStr()] = ''
          print packet.payload.payload
          self.handle_tcp_handshake(packet)
        elif packet.payload.payload.FIN == True:
          print "Finalizando conexao de " + packet.src.toStr()
          self.logados.remove(packet.src.toStr())
          print "DELETOU!!!"
          print self.logados
          print packet.payload.payload
          self.handle_tcp_teardown(packet)
        else:
					print packet.payload.payload
					print str(packet.payload.payload.seq) + ' : ' + packet.payload.payload.payload        

        if packet.payload.payload.seq > self.lastSEQ[packet.src.toStr()]:
          if self.count[packet.src.toStr()] == 0:
            self.count[packet.src.toStr()] = 1
          else:
            # cria conexao tcp com aplicacao local para fazer autenticacao
            #print 'Vai enviar resposta pra esse ultimo PACKET!!! SEQ = ' + str(packet.payload.payload.seq)
            #print str(packet.payload.payload.seq) + ' : ' + packet.payload.payload.payload
            #result = self.authenticate(str(packet.payload.payload.payload))
            #print 'Sending result: ' + result
            #self.lastACK = len(packet.payload.payload.payload) + self.lastACK
            
            if self.count[packet.src.toStr()] == 1:
              self.data_to_auth[packet.src.toStr()] = self.data_to_auth[packet.src.toStr()] + str(packet.payload.payload.payload)
              print 'DATA TO AUTH: ' + self.data_to_auth[packet.src.toStr()]
              self.handle_tcp_ack(packet)
              if self.data_to_auth[packet.src.toStr()][len(self.data_to_auth[packet.src.toStr()]) - 1] == '}':
                result = self.authenticate(self.data_to_auth[packet.src.toStr()])
                #print result

                result_dic = json.loads(result)
                if result_dic['desc'] == 'autentica':
                  if result_dic['result'] == 'OK':
                    self.logados.append(packet.src.toStr())
                    print "ADICIONOU!!!"
                    print self.logados

                self.count[packet.src.toStr()] = 2
                self.handle_tcp(packet, result)
            #print 'BYTES RECEIVED: ' + str(self.lastACK - self.lastSEQ)
            #if self.lastACK > self.lastSEQ + 2000:
            #self.handle_tcp(packet, 'REPLY MESSAGE')


    if packet.type == ethernet.ARP_TYPE:
		  if (packet.src.toStr() in self.logados) == False:
		    #if self.count_arp == 0:
		    #if packet.find('arp'):
				self.handle_arp(packet)
					#self.count_arp = self.count_arp + 1
					#pass
		  else:
			  packet_in = event.ofp # The actual ofp_packet_in message.
			  self.act_like_hub(packet, packet_in)

    elif packet.type == ethernet.IP_TYPE:
			if (packet.src.toStr() in self.logados) == False:
				#if self.count_dns == 0:
				if packet.find('dns'):
					self.handle_dns(packet)
					#self.count_dns = self.count_dns + 1
					#pass
			elif (packet.dst.toStr() in self.logados) == True and packet.find('icmp'):
				print 'ENTROU ICMP!!!'
				packet_in = event.ofp # The actual ofp_packet_in message.
				self.act_like_hub(packet, packet_in)
    

    
      
      #import socket
      #HOST = '127.0.0.1'     # Endereco IP do Servidor
      #PORT = 5000            # Porta que o Servidor esta
      #tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      #dest = (HOST, PORT)
      #tcp.connect(dest)
      #print 'Conectou!'
      #print 'Para sair use CTRL+X\n'
      #msg = raw_input()
      #while msg <> '\x18':
      #tcp.send (packet.payload.payload)
        #msg = raw_input()
      #tcp.close()


    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.

    # Comment out the following line and uncomment the one after
    # when starting the exercise.
    #self.act_like_hub(packet, packet_in)
    #self.act_like_switch(packet, packet_in)



def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Tutorial(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
#a = Tutorial('10.0.0.110')
#a('10.0.0.110')