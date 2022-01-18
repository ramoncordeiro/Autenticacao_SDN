#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info


import time
def myNet():


    #OpenDayLight controller
    ODL_CONTROLLER_IP='0.0.0.0'

    #Floodlight controller
    #FL_CONTROLLER_IP='0.0.0.0'
    

    net = Mininet( topo=None, build=False)

    # Create nodes
    h1 = net.addHost( 'h1', mac='01:00:00:00:01:00', ip='10.0.0.1' )
    h2 = net.addHost( 'h2', mac='01:00:00:00:02:00', ip='10.0.0.2' )
    h3 = net.addHost( 'h3', mac='01:00:00:00:03:00', ip='10.0.0.3' )
    h4 = net.addHost( 'h4', mac='01:00:00:00:04:00', ip='10.0.0.4' )
    h5 = net.addHost( 'h5', mac='01:00:00:00:05:00', ip='10.0.0.5' )
    h6 = net.addHost( 'h6', mac='01:00:00:00:06:00', ip='10.0.0.6' )

    # Create switches
    s1 = net.addSwitch( 's1', listenPort=6633, mac='00:00:00:00:00:09' )
    #s2 = net.addSwitch( 's2', listenPort=6635, mac='00:00:00:00:00:02' )

    print "*** Creating links"
    net.addLink(h1, s1, )
    net.addLink(h2, s1, )
    net.addLink(h3, s1, )
    net.addLink(h4, s1, )
    net.addLink(h5, s1, )
    net.addLink(h6, s1, )   
    #net.addLink(s1, s2, )  

    # Add Controllers
    odl_ctrl = net.addController( 'c0', controller=RemoteController, ip=ODL_CONTROLLER_IP, port=6633)

    #fl_ctrl = net.addController( 'c1', controller=RemoteController, ip=FL_CONTROLLER_IP, port=6633)


    net.build()

    # Connect each switch to a different controller
    s1.start( [odl_ctrl] )
    #s2.start( [fl_ctrl] )

    #print h1.cmd('ping -c3', ping h2)
    s1.cmdPrint('ovs-vsctl show')
    #h1.cmd('xterm -e') #funciona, mas em segundo plano (nao aparece tela)
    
    #h1.cmd('xterm &') #abre a janela. Ta funcionando
    #h1.cmd('xterm -e python pox/pox/forwarding/autenticador_rec.py &')
    h2.cmd('xterm -title "h2" -e python pox/pox/forwarding/autenticador_rec.py &')
    h3.cmd('xterm -title "h3" -e python pox/pox/forwarding/autenticador_rec.py &')
    h4.cmd('xterm -title "h4" -e python pox/pox/forwarding/autenticador_rec.py &')
    h5.cmd('xterm -title "h5" -e python pox/pox/forwarding/autenticador_rec.py &')
    h6.cmd('xterm -title "h6" -e python pox/pox/forwarding/autenticador_rec.py &')
    
    time.sleep(3)
    h1.cmd('xterm -title "h1" -e python pox/pox/forwarding/cliente2.py &')
    #h1.cmd('python pox/pox/forwarding/cliente2.py') #nao funcionou
    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNet()