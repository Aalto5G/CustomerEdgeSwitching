#!/usr/bin/python3

class NetworkInfo:
    def __init__(self, name):
        self.network_id = name
        self.container = None

class ContainerManager:
    def __init__(self):
        self.containers = {}            # Container name & ContainerInfo instance

    def getContainerManager(self):
        return self.containers

    def numOfContainers(self):
        return len(self.containers)

    def getContainer(self, name):
        if self.hasContainer(name):
            return self.containers[name]
        return None

    def hasContainer(self, name):
        return name in self.containers

    def addContainer(self, name, ct_info):
        self.containers[name] = ct_info

    def removeContainer(self, name):
        del self.containers[name]

class ContainerInfo:
    def __init__(self, name, ct_type="", domain_name="", bridge_info=[], iface_info={}, iface_bridge_map={}, iface_to_ip_map={}):
        self.name = name
        self.container_type = ct_type
        self.domain_name = domain_name
        self.bridge_info = bridge_info                  # List of connected bridges on interfaces
        self.iface_info = iface_info                    # Interface and their type
        self.iface_bridge_map = iface_bridge_map        # Keeps iface to bridge mapping.
        self.iface_to_ip_map = iface_to_ip_map

    def get_name(self):
        return self.name

    def get_container_type(self):
        return self.container_type

    def get_domain_name(self):
        return self.domain_name

    def get_iface_ip_mapping(self):
        return self.iface_to_ip_map

    def get_iface_bridge_map(self):
        return self.iface_bridge_map

    def get_bridge_for_interface(self, br_name):
        return self.iface_bridge_map[br_name]

    def get_ip_for_interface(self, iface):
        return self.iface_to_ip_map[iface]

    def has_interface(self, iface_name):
        return iface_name in self.iface_info

    def has_bridge_name(self, iface_name):
        return iface_name in self.iface_bridge_map

    def get_interface_by_type(self, iface_type):
        for k, v in self.iface_info.items():
            if v == iface_type:
                return k
        return None

    def get_interface_type(self, iface_name):
        if self.has_interface(iface_name):
            return self.iface_info[iface_name]
        return None

    def get_iface_bridge(self, iface_name):
        if self.has_bridge_name(iface_name):
            return self.iface_bridge_map[iface_name]
        return None

    def register_bridge(self, br_name):
        self.bridge_info.append(br_name)

    def register_interface_type(self, iface_name, iface_type):
        self.iface_info[iface_name] = iface_type

    def register_iface_ipaddr_list_mapping(self, iface, ip_addr_list):
        self.iface_to_ip_map[iface] = ip_addr_list

    def register_iface_bridge(self, iface, br_name):
        self.iface_bridge_map[iface] = br_name
        if br_name not in self.bridge_info:
            self.register_bridge(br_name)

    def register_iface_ip_mapping(self, iface, ip_addr):
        """ Unused """
        if iface not in self.iface_to_ip_map:
            self.iface_to_ip_map[iface] = []
        self.iface_to_ip_map[iface].append(ip_addr)

    def dump_configs(self):
        return [self.name, self.container_type, self.domain_name, self.bridge_info, \
         self.iface_info, self.iface_bridge_map, self.iface_to_ip_map]

    def load_configs(self, container_info):
        try:
            [name, ct_type, domain_name, bridge_info, iface_info, \
             iface_bridge_map, iface_to_ip_map ] = container_info

            self.name = name
            self.container_type = ct_type
            self.domain_name = domain_name
            self.bridge_info = bridge_info                  # List of connected bridges on interfaces
            self.iface_info = iface_info                    # Interface and their type
            self.iface_bridge_map = iface_bridge_map        # Keeps iface to bridge mapping.
            self.iface_to_ip_map = iface_to_ip_map
            return True
        except:
            return False


if __name__=="__main__":
    print("Test")