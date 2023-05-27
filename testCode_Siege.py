#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch, Host
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from subprocess import call

# Import SimpleHTTPServer module
import SimpleHTTPServer
import time
import re
import logging

# Set up logging
logging.basicConfig( level=logging.INFO)


def myNetwork(num_clients):
    # Add a log message to indicate that we're starting the network setup
    logging.info('Setting up network for {} clients'.format(num_clients))

    try:
        # Create the network
        logging.info('Creating network...')
        net = Mininet(topo=None,
                      build=False,
                      link=TCLink,
                      ipBase='10.0.0.0/8')

        # Add the controller
        logging.info('Adding controller...')
        c0 = net.addController(name='c0',
                               controller=RemoteController,
                               ip='127.0.0.1',
                               protocol='tcp',
                               port=6633)

        # Add the switches and hosts
        logging.info('Adding switches and hosts...')
        s1 = net.addSwitch('s1', cls=OVSKernelSwitch)
        h1 = net.addHost('h1', cls=Host, ip='10.0.0.1', defaultRoute=None,
                         mac='00:00:00:00:00:01')
        h2 = net.addHost('h2', cls=Host, ip='10.0.0.2', defaultRoute=None,
                         mac='00:00:00:00:00:02')
        h3 = net.addHost('h3', cls=Host, ip='10.0.0.3', defaultRoute=None,
                         mac='00:00:00:00:00:03')
        h4 = net.addHost('h4', cls=Host, ip='10.0.0.4', defaultRoute=None,
                         mac='00:00:00:00:00:04')

        # Add links
        logging.info('Adding links...')
        net.addLink(h1, s1)
        net.addLink(h2, s1)
        net.addLink(h3, s1)
        net.addLink(h4, s1)

        # Start the network
        logging.info('Starting network...')
        net.build()
        c0.start()
        s1.start([c0])

        # Start the HTTP servers on h1, h2, and h3
        logging.info('Starting HTTP servers...')
        h1.cmd('python -m SimpleHTTPServer 80 &')
        h2.cmd('python -m SimpleHTTPServer 80 &')
        h3.cmd('python -m SimpleHTTPServer 80 &')

        # Wait a bit for servers to start
        logging.info('Waiting for servers to start...')
        time.sleep(3)

        # Run siege on h4 with the specified number of clients
        logging.info('Running siege with {} clients...'.format(num_clients))
        siege_cmd = 'siege -c {} -t 60s --delay=3 --timeout=20 http://10.0.2.1'.format(num_clients)
        output = h4.cmd(siege_cmd)
        #logging.info(output)

        # Extract the response time and throughput data from the siege output
        logging.info('Extracting response times and throughputs...')
        response_time_pattern = r'Response time:\s*(\d+\.\d+)\s*secs'
        throughput_pattern = r'Throughput:\s*(\d+\.\d+)\s*MB\/sec'

        response_time_value = 0.0
        throughput_value = 0.0

        for line in output.splitlines():
            response_time_match = re.match(response_time_pattern, line)
            if response_time_match:
                response_time_value = float(response_time_match.group(1))

            throughput_match = re.match(throughput_pattern, line)
            if throughput_match:
                throughput_value = float(throughput_match.group(1))
           
            logging.info("Response Time  {}    and Throughput   {} ".format(response_time_value,throughput_value))

'''
        # Write the results to a file
        logging.info('Writing results to file...')
        with open('/tmp/siege_h4.txt', 'a') as f:
            f.write('{} {} {} {} {}\n'.format(num_clients, min(response_times), max(throughputs),
                                               max(response_times), min(throughputs)))
'''

    except Exception as e:
        logging.exception('An error occurred while setting up the network: {}'.format(e))

    finally:
        # Stop the network
        logging.info('Stopping network...')
        net.stop()

    # Add a log message to indicate that we're done with the network setup
    logging.info('Finished setting up network for {} clients'.format(num_clients))


if __name__ == '__main__':
    # Perform the tests with different numbers of clients
    num_clients_list = [50, 100, 200, 400]
    
    # Call the myNetwork function for each number of clients
    for num_clients in num_clients_list:
        myNetwork(num_clients)
