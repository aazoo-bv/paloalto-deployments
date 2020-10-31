#!/usr/bin/env python3
#
# This script imports interfaces from a CSV file and builds subinterfaces accordingly.
#
# Script was developed by Gert-Jan de Boer of aaZoo Network Solutions
# 

import datetime
import random
import sys

from panos import device, firewall, network
from csv import reader

# Define hostname and ha-peer's hostname so we can deploy always to the active node.
HOSTNAME = ""
HA_HOSTNAME = ""
# Login credentials
USERNAME = "admin"
PASSWORD = ""
# Define the base interface that hosts the sub interfaces
INTERFACE = "ae1"

def main():
    # Connect to the firewall and it's HA Peer
    fw = firewall.Firewall(HOSTNAME, USERNAME, PASSWORD)
    fw.set_ha_peers(Firewall(HOSTNAME, USERNAME, PASSWORD))
    print("Firewall system info: {0}".format(fw.refresh_system_info()))
    fw.refresh_ha_active()

    # Check if synchronised, if not do so
    if not fw.config_synced():
        fw.synchronize_config()

    # This script will only work on single vsys systems
    vsys_list = device.Vsys.refreshall(fw, name_only=True)
    vsys = vsys_list[0]

    eth = None

    # Add the base interface to the config tree
    base = network.EthernetInterface(INTERFACE, "layer3")
    fw.add(base)

    # Open CSV file
    with open('interfaces.csv', 'r') as read_obj:
        csv_reader = reader(read_obj)
        # Skip the headers
        headers = next(csv_reader)
        for row in csv_reader:
            # Build interface name, IP and comment the zone
            name = "{0}.{1}".format(INTERFACE, row[0])
            eth = network.Layer3Subinterface(name, tag=row[0], ip=row[2], comment=row[1])
            vsys.add(eth)
            # Set the zone for the interface
            eth.set_zone(row[1],mode="layer3",update=True)
            eth.set_virtual_router(row[3],update=True)

        # Create and apply the configuration
        eth.create_similar()
        eth.apply_similar()

    fw.organize_into_vsys()

    # Commit the configuration
    fw.commit(sync=True)

if __name__ == "__main__":
    if len(sys.argv) != 1:
        print(__doc__)
    else:
        main()
