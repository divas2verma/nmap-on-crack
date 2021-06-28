import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
import os
from datetime import datetime


service_mappings = {
    'ms-wbt-server' : 'rdp',
    'domain'    : 'dns'
}


def initnmap(IP):

    os.system (f"nmap -p- {IP} -oX result_{IP}_{datetime.date(datetime.now())}.xml")
    
    return (f"result_{IP}_{datetime.date(datetime.now())}.xml")




def treeparse(file):

    tree = ET.parse(file)
    root = tree.getroot()
    hosts = defaultdict(list)

    for child in root:

        if child.tag != 'host': continue
        e_address = child.find('address')
        e_ports = child.find('ports')
        ip_addr = e_address.get('addr')

        for e_port in e_ports:

            if e_port.tag != 'port': continue
            port = int(e_port.get('portid'))
            # state is always present for a port
            e_state = e_port.find('state')
            state = e_state.get('state')
            e_service = e_port.find('service')
            service_name = 'n/a'
            # service is not always present
            if e_service is not None:

                service_name = e_service.get('name')
                if service_name in service_mappings:
                
                    service_name = service_mappings[service_name]

            if state == 'open':

                hosts[ip_addr].append((port, service_name))

    return (hosts)




def scripts(resolved_hosts):

    for ip, ports in resolved_hosts.items():

        print(f'[*] ip : {ip}')
        portlist = []
        
        for (port, service_name) in ports:

            if service_name == 'n/a': continue
            portlist.append((port,service_name))

        for i in portlist:
            print(f'\t{i}')

        input("Press Enter to continue...")

        for j in portlist:
            os.system(f'nmap -Pn -sS -p{j[0]} --script "{j[1]}*" -v {ip}')

IP = sys.argv[1]
path = initnmap(IP)
clean = treeparse(path)
script_results = scripts(clean)