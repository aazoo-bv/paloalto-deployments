#!/usr/bin/env python3
#
# This script imports policies from a CSV file and builds the policy ruleset accordingly. If address and/or service objects don't exists they will be created.
# A firewall commit will not be done by this script so you have to manually verify if the configuration matches your expectations before you commit. This is intentionally to prevent disasters.
#
# Script was developed by Gert-Jan de Boer of aaZoo Network Solutions
# 


import datetime
import random
import sys

from panos import device, firewall, network, objects, policies
from csv import reader

# Define hostname and ha-peer's hostname so we can deploy always to the active node.
HOSTNAME = ""
HA_HOSTNAME = ""
# Login credentials
USERNAME = "admin"
PASSWORD = ""

def main():
    # Connect to the firewall
    fw = firewall.Firewall(HOSTNAME, USERNAME, PASSWORD)
    fw.set_ha_peers(firewall.Firewall(HA_HOSTNAME, USERNAME, PASSWORD))
    print("Firewall system info: {0}".format(fw.refresh_system_info()))

    fw.refresh_ha_active()

    # Check if firewall is synchronized, otherwise sync first
    if not fw.config_synced():
        fw.synchronize_config()

    vsys_list = device.Vsys.refreshall(fw, name_only=True)
    vsys = vsys_list[0]

    net = []
    proto = []
    svc = []

    # Read original address objects from the firewall
    original_networks = objects.AddressObject.refreshall(fw, add=False)
    original_services = objects.ServiceObject.refreshall(fw, add=False)

    # Fetch objects from the CSV file and make them unique
    # row[0]        | row[1]            | row[2]        | row[3]            | row[4]        | row[5]    | row[6]    | row[7] | row[8]       | row[9]
    # source zone   | destination zone  | source net    | destination net   | application   | protocol  | service   | action | policy group | name
    with open('policies.csv', 'r') as read_obj:
        # Read CSV and put them in lists
        csv_reader = reader(read_obj)
        headers = next(csv_reader) 
        for row in csv_reader:
            if row[2] != "any":
                if row[2] not in net:
                    if row[2] not in original_networks:
                        net.append(row[2])
            if row[3] != "any":
                if row[3] not in net:
                    if row[3] not in original_networks:
                        net.append(row[3])
            if "application-default" not in row[6]:
                if "any" not in row[6]:
                    svc_obj = row[5] + "-" + row[6]
                    if svc_obj not in svc:
                        if svc_obj not in original_services:
                            svc.append(svc_obj)

    # Add the original objects back to the object tree
    for org_nets in original_networks:
        fw.add(org_nets)
    for org_svc in original_services:
        fw.add(org_svc)

    # Walk through the network address objects and define HOST-$IP for the host objects and NET-$IP-$MASK for networks
    for net_obj in net:
        net_obj_split = net_obj.split('/')
        if net_obj_split[1] == "32":
            print("HOST-"+net_obj_split[0])
            addr_objects = objects.AddressObject("HOST-"+net_obj_split[0], net_obj)
        else:
            print("NET-"+net_obj_split[0]+"-"+net_obj_split[1])
            addr_objects = objects.AddressObject("NET-"+net_obj_split[0]+"-"+net_obj_split[1], net_obj)
        # Add the address objects to the config tree
        fw.add(addr_objects)

    # Create similar objects in one go
    addr_objects.create_similar()

    # Add service objects to the config tree
    for svc_obj in svc:
        print("SERVICE: " + svc_obj)
        svc_obj_split = svc_obj.split('-')
        svc_objects = objects.ServiceObject(svc_obj,protocol=svc_obj_split[0],destination_port=svc_obj_split[1])
        fw.add(svc_objects)

    # Create similar objects in one go
    svc_objects.create_similar()

    # Initialize the current rulebase and add it to the config tree so we don't create duplicate policies
    rulebase = policies.Rulebase()
    fw.add(rulebase)
    current_security_rules = policies.SecurityRule.refreshall(rulebase)

    # Walk through the policies CSV and build policies.
    with open('policies.csv', 'r') as read_obj:
        csv_reader = reader(read_obj)
        # Skip the headers
        headers = next(csv_reader)
        for row in csv_reader:
            # If source is not any use the address object
            if "any" not in row[2]:
                src_split = row[2].split('/')
                if src_split[1] == "32":
                    src_net = "HOST-"+src_split[0]
                else:
                    src_net = "NET-"+src_split[0]+"-"+src_split[1]
            else:
                src_net = row[2]

            # If destination is not any use the address object
            if "any" not in row[3]:
                dst_split = row[3].split('/')
                if dst_split[1] == "32":
                    dst = "HOST-"+dst_split[0]
                else:
                    dst_net = "NET-"+dst_split[0]+"-"+dst_split[1]
            else:
                dst_net = row[3]

            # Check for service any or appplication-default, otherwise use the protocol and port
            if row[6] == "any":
                svc_obj = row[6]
            elif row[6] == "application-default":
                svc_obj = row[6]
            else:
                svc_obj = row[5] + "-" + row[6]

            dst_split = row[3].split('/')

            # If the security profile field is empty don't add the group property to the policy
            if row[8] == "none":
                desired_rule_params = {
                    "name": row[9],
                    "fromzone": row[0],
                    "source": src_net,
                    "destination": dst_net,
                    "tozone": row[1],
                    "application": row[4],
                    "service": svc_obj,
                    "action": row[7],
                    "tag": "imported",
                    "log_end": True,
                }
            else:
                desired_rule_params = {
                    "name": row[9],
                    "fromzone": row[0],
                    "source": src_net,
                    "destination": dst_net,
                    "tozone": row[1],
                    "application": row[4],
                    "service": svc_obj,
                    "action": row[7],
                    "group": row[8],
                    "tag": "imported",
                    "log_end": True,
                }

            # Check if the ruleset already exists
            is_present = False
            for rule in current_security_rules:
                if rule.name == desired_rule_params["name"]:
                    is_present = True

            # If the rule is not present add it to the rulebase
            if is_present == False:
                new_rule = policies.SecurityRule(**desired_rule_params)
                rulebase.add(new_rule)
                new_rule.create()

# Run main program    
if __name__ == "__main__":
    if len(sys.argv) != 1:
        print(__doc__)
    else:
        main()
