#!/usr/bin/python3

from aiohttp import web
import json
import asyncio
import pymysql
import logging
import io
import os
import lxc
import sys
import time
import traceback
import stat
import yaml

import ContainerManager
from ContainerManager import ContainerManager, ContainerInfo

LOGLEVEL = logging.DEBUG
logging.basicConfig(level=LOGLEVEL, filename="lxcenv.log", filemode='w')

CTUSER                  = 'ubuntu'
CTPASSWORD              = 'ubuntu'
LXC_CT_BASENAME         = 'ctbase'
CT_CONFIG_DIR           = 'ct_files'
SCRIPT_PRE_UP           = './pre-up.sh'
CTBASE_CREATE_CONFIG    = os.path.join(CT_CONFIG_DIR, 'ctbase_create_config')

CONTAINER_BASE_PATH         = "/var/lib/lxc"
CONTAINER_CREATION_SUCCESS  = 1
CONTAINER_EXISTS            = 2
CONTAINER_CREATION_FAILED   = 3
SYSEXEC_BACKOFF             = 0.25

def sanitize_line(text, comment='#', token=''):
    if text.startswith(comment):
        return False
    if token not in text:
        return False
    return True

def get_key_value(text, token=''):
    k = text.strip().split('=')[0].strip()
    v = text.strip().split('=')[1].strip()
    return (k,v)

class LxcEnv:
    def __init__(self):
        self.logger = logging.getLogger()
        self.ct_clone   = self._ct_clone_exec
        self.ct_start   = self._ct_start_exec
        self.ct_stop    = self._ct_stop_exec
        self.ct_destroy = self._ct_destroy_exec
        self.ctbase_create_config = yaml.load(open(CTBASE_CREATE_CONFIG, 'r'))
        self.network_bridges = []                       # List of bridge names
        self.bridge_creation_status = {}                # Dictionary stating if bridges are created or not.
        self.default_iface = "mgt0"                     # To be set by HTTP query from Web front-end
        self.base_ct_name = None
        self.base_ct_created = False
        self.num_of_gateways = 0
        self.container_mgr = ContainerManager()

    def has_bridge(self, br_name):
        return br_name in self.network_bridges

    def register_bridge_name(self, br_name):
        if not self.has_bridge(br_name):
            self.network_bridges.append(br_name)

    def remove_bridge_names(self, br_name):
        if self.has_bridge(br_name):
            self.network_bridges.remove(br_name)

    def check_bridge_creation_status(self, br_name):
        if br_name not in self.bridge_creation_status:
            return False

        if self.bridge_creation_status[br_name] == True:
            return True

    def create_bridge(self, br_name):
        """ Creates the bridge, if not already created """
        self.logger.debug("Checking bridge '{}' status.".format(br_name))
        if self.check_bridge_creation_status(br_name) is True:
            return

        bridge_up_cmd = ""
        self.logger.debug("Bridge '{}' doesn't exist - to be created".format(br_name))
        if br_name in self.network_bridges:
            self.logger.debug("Setting up bridge '{}'".format(br_name))
            #bridge_up_cmd = "Setting up {}".format(br_name)
            bridge_up_cmd += "ip link del dev {};".format(br_name)
            bridge_up_cmd += "ip link add dev {} type bridge forward_delay 0;".format(br_name)
            bridge_up_cmd += "ip link set dev {} up;".format(br_name)
            self.bridge_creation_status[br_name] = True
            if br_name == self.default_br_name:
                ip_address_from_same_subnet = "172.31.255.1/24"             # To be set from web front end
                bridge_up_cmd += "ip address add {} dev {}".format(ip_address_from_same_subnet, br_name)

        self._sysexec(bridge_up_cmd)

    def set_default_iface(self, iface_name):
        self.default_iface = iface_name

    def _ct_clone_exec(self, src, dst):
        ct_dst = lxc.Container(dst)
        if ct_dst.defined:
            self.logger.warning('Destination clone already exists: {}'.format(dst))
            return

        # Clone base container with snapshot
        command = 'lxc-copy -n {} -N {} -s -F'.format(src, dst) # Ubuntu 16.04
        self._sysexec(command, 'host')

    def _ct_start_exec(self, name, verbose = False):
        command = 'lxc-start -n {}'.format(name)
        self._sysexec(command, 'host')

    def _ct_stop_exec(self, name, verbose = False):
        ct = lxc.Container(name)
        if not ct.running:
            self.logger.warning('Not running container cannot be stopped: {}'.format(name))
            return
        command = 'lxc-stop -n {}'.format(name)
        self._sysexec(command, 'host')

    def ct_restart(self, name, verbose = False):
        self.ct_stop(name, verbose)
        self.ct_start(name, verbose)

    def _ct_destroy_exec(self, name, verbose = False):
        ct = lxc.Container(name)
        self.logger.debug("Container '{}' definition status: {}".format(name, ct.defined))
        if not ct.defined:
            self.logger.warning('Not defined container cannot be destoryed: {}'.format(name))
            return
        command = 'lxc-destroy -n {}'.format(name)
        self._sysexec(command, 'host')

    def _create_ctbase(self, name, verbose = False):
        """ Creating base container and setting up bridges """
        try:
            self.logger.info("Creating ctbase")
            ctbase = lxc.Container(name)
            if ctbase.defined:
                self.logger.info('Base conatiner {} already exists'.format(name))
                return CONTAINER_EXISTS

            #self.logger.info("Before executing pre-up.sh script")
            self._sysexec(SCRIPT_PRE_UP)
            #self.logger.info("After executing pre-up.sh script")

            # Set verbose level
            verbosity = 1
            if not verbose:
                verbosity = lxc.LXC_CREATE_QUIET
            # Create the container rootfs
            #'packages': ','.join(p for p in config.setdefault('apt_packages', []))
            start_time = time.time()
            config = self.ctbase_create_config[LXC_CT_BASENAME]
            print("config: ", config)
            pkgs1 = ','.join(p for p in config.setdefault('apt_packages', []))
            print("pkgs1: ", pkgs1)
            #pkgs = ','.join(p for p in config.setdefault('apt_packages', []))

            self.logger.info("Initiating the process to create '{}' container".format(name))
            if not ctbase.create('ubuntu', verbosity, {'user': CTUSER, 'password': CTPASSWORD, 'packages': ','.join(p for p in config.setdefault('apt_packages', [])) }):
                #if not ctbase.create('ubuntu', verbosity, {'user': CTUSER, 'password': CTPASSWORD }):
                self.logger.error("Failed to create the container '{}'".format(name))
                return CONTAINER_CREATION_FAILED

            elapsed_time = time.time() - start_time

            # HACK - APPARMOR issues with kernel feature
            if True:
                ctbase.append_config_item('lxc.apparmor.allow_incomplete', '1')
                ctbase.save_config()

            # Start the container
            self.ct_start(name)
            #self.logger.info("\nHAKA 111 in create_ctbase\ŋ")
            self.sync_rootfs_container(name, os.path.join('ct_files', 'ctbase/rootfs'))
            #self.logger.info("\nHAKA 222 in create_ctbase\ŋ")
            self.fix_home_permissions(name)
            #self.logger.info("\nHAKA 333 in create_ctbase\ŋ")

            """
            # Install apt packages
            self.ct_apt_install(name, config.setdefault('apt_packages', []))
            """
            #"""
            # Install pip3 packages
            self.logger.info("Initiating pip package in '{}' container".format(name))
            self.ct_pip3_install(name, config.setdefault('pip3_packages', []))
            # Reload services
            self.ct_reload_services(name)
            #"""

            #"""
            for service in config.setdefault('enabled_services', []):
                self.ct_enable_service(name, service)
            # Disable services in container
            for service in config.setdefault('disabled_services', []):
                self.ct_disable_service(name, service)

            print("Created the base container {} in {} sec".format(name, elapsed_time))
            #"""

            self.ct_stop(name)

            # Clear all network configuration
            ctbase = lxc.Container(name)
            ctbase.clear_config_item('lxc.net.0')
            ctbase.save_config()

            self.base_ct_name = name
            self.base_ct_created = True
            return CONTAINER_CREATION_SUCCESS

        except Exception as ex:
            self.logger.error('Failed to create the container rootfs {}'.format(name))
            traceback.print_exc()
            return CONTAINER_CREATION_FAILED

        # Sync container rootfs
        """
        self.sync_rootfs_container(name, os.path.join(RESOURCE_PATH, config['rootfs']))
        self.fix_home_permissions(name)

        # Install apt packages
        self.ct_apt_install(name, config.setdefault('apt_packages', []))
        # Install pip3 packages
        self.ct_pip3_install(name, config.setdefault('pip3_packages', []))

        # Reload services
        self.ct_reload_services(name)
        # Enable services in container
        for service in config.setdefault('enabled_services',[]):
            self.ct_enable_service(name, service)
        # Disable services in container
        for service in config.setdefault('disabled_services', []):
            self.ct_disable_service(name, service)
        # Stop the container
        self.ct_stop(name)
        # Clear all network configuration
        ctbase = lxc.Container(name)
        ctbase.clear_config_item('lxc.net.0')
        ctbase.save_config()
        # Overwrite container configuration
        #self._load_config_container(name, os.path.join(RESOURCE_PATH, config['config']))
        """

    def ct_apt_install(self, name, pkgs):
        if not len(pkgs):
            self.logger.info('Skipping installation of apt packages: {}'.format(name))
            return
        ct = lxc.Container(name)
        self.logger.info('Install packages via apt: {} - {}'.format(name, pkgs))
        command = '/usr/bin/lxc-attach -n {} -- bash -c "DEBIAN_FRONTEND=noninteractive apt-get install -y {}"'.format(name, ' '.join(_ for _ in pkgs))
        self._sysexec(command, name)

    def ct_pip3_install(self, name, pkgs):
        if not len(pkgs):
            self.logger.info('Skipping installation of pip3 packages: {}'.format(name))
            return
        ct = lxc.Container(name)
        self.logger.info('Install packages via pip3: {} - {}'.format(name, pkgs))
        # Install python3-pip
        command = '/usr/bin/lxc-attach -n {} -- bash -c "DEBIAN_FRONTEND=noninteractive apt-get install -y python3-pip"'.format(name)
        self._sysexec(command, name)
        # Upgrade pip and install setuptools
        command = '/usr/bin/lxc-attach -n {} -- bash -c "pip3 install --upgrade pip setuptools"'.format(name)
        self._sysexec(command, name)
        # Install pip3 packages
        #command = '/usr/bin/lxc-attach -n {} -- bash -c "pip3 install --upgrade {}"'.format(name, ' '.join(_ for _ in pkgs))
        command = '/usr/bin/lxc-attach -n {} -- bash -c "pip3 install --ignore-installed --upgrade {}"'.format(name, ' '.join(_ for _ in pkgs))
        self._sysexec(command, name)

    def ct_reload_services(self, name, verbose = False):
        ct = lxc.Container(name)
        self.logger.debug('Reload services: {}'.format(name))
        ct.attach_wait(lxc.attach_run_command, ['systemctl', 'daemon-reload'])

    def ct_enable_service(self, name, service, verbose = False):
        ct = lxc.Container(name)
        self.logger.info('Enable & Start service: {} - {}'.format(name, service))
        ct.attach_wait(lxc.attach_run_command, ['systemctl', 'daemon-reload'])
        ct.attach_wait(lxc.attach_run_command, ['systemctl', 'enable', service])
        ct.attach_wait(lxc.attach_run_command, ['systemctl', 'start', service])

    def ct_disable_service(self, name, service, verbose = False):
        ct = lxc.Container(name)
        self.logger.info('Stop & Disable service: {} - {}'.format(name, service))
        ct.attach_wait(lxc.attach_run_command, ['systemctl', 'stop', service])
        ct.attach_wait(lxc.attach_run_command, ['systemctl', 'disable', service])

    def _load_config_container(self, name, filepath):
        self.logger.debug('Loading configuration: {}'.format(name))
        ct = lxc.Container(name)
        with open(filepath, 'r') as config:
            for line in config:
                #Sanitize values
                if not sanitize_line(line, token='='):
                    continue
                k,v = get_key_value(line)
                self.logger.debug('Setting attribute: {} - {} / {}'.format(ct.name, k, v))
                ct.append_config_item(k, v)
            ct.save_config()


    def _spawn_container(self, base, name, config_path):
        try:
            ct = lxc.Container(name)
            #self.logger.info('Cloning {} to {}\n\n'.format(base, name))

            if not ct.defined:
                start_time = time.time()
                self.ct_clone(base, name)
                elapsed_time = time.time() - start_time
                self._load_config_container(name, config_path)

                self.ct_start(name)
                #cloned_ct_file_path = os.path.join('ct_files/gwa', 'delta0/home/ubuntu')
                #print('cloned_ct_file_path', cloned_ct_file_path)
                self.sync_rootfs_container(name, os.path.join('ct_files/gwa', 'delta0/home/ubuntu'))
                self.fix_home_permissions(name)
                self.fix_etc_hosts_file(name)
                self.logger.info('Successfully cloned {} container in {} sec'.format(name, elapsed_time))

            else:
                self.logger.warning('Container already exists: {}'.format(name))

            #self.ct_start(name)
            """
            self.sync_rootfs_container(name, os.path.join(RESOURCE_PATH, config['rootfs']))
            self.fix_home_permissions(name)
            self.fix_etc_hosts_file(name)

            # Install apt packages
            self.ct_apt_install(name, config.setdefault('apt_packages', []))
            # Install pip3 packages
            self.ct_pip3_install(name, config.setdefault('pip3_packages', []))

            self.ct_reload_services(name)
            for service in config.setdefault('enabled_services', []):
                self.ct_enable_service(name, service)
            for service in config.setdefault('disabled_services', []):
                self.ct_disable_service(name, service)
            self.ct_restart(name)
            """

        except FileNotFoundError as e:
            self.logger.warning("Exception: {}", format(e))


    def sync_rootfs_container(self, name, path):
        self.logger.debug('Syncing rootfs: {}'.format(name))
        ct = lxc.Container(name)
        # Backup current working directory
        cwd = os.getcwd()
        # Change to rootfs path
        os.chdir(path)
        for root, dirs, files in os.walk('.'):
            for file in files:
                # Make absolute file in host
                _file = os.path.join(os.getcwd(), root, file)
                # Make absolute path in container
                ct_file = os.path.join(root, file)[1:]
                self.ct_sync_file(name, _file, ct_file)
        # Change to previous working directory
        os.chdir(cwd)


    def fix_home_permissions(self, name):
        self.logger.debug('Fixing $HOME permissions: {}'.format(name))
        # Set recursive permissions to $HOME directory
        self.logger.debug('[{}] >> Fixing folder permissions {}'.format(name, os.path.dirname('/home/{}'.format(CTUSER))))
        command = '/usr/bin/lxc-attach -n {} -- /bin/chown -R {}:{} /home/{}'.format(name, CTUSER, CTUSER, CTUSER)
        self._sysexec(command, name)


    def ct_sync_file(self, name, src, dst):
        # Create base directory
        ct = lxc.Container(name)
        # Get file's permissions
        fmode = os.stat(src).st_mode
        fmode_str = stat.filemode(fmode)
        fmode_chmod = oct(fmode)[-3:]
        # Create directory
        self.logger.debug('[{}] >> Creating directory {} ...'.format(name, os.path.dirname(dst)))
        command = '/usr/bin/lxc-attach -n {} -- /bin/mkdir -p -m {} {}'.format(name, '755', os.path.dirname(dst))
        self._sysexec(command, name)
        # Create file - Delete existing file to avoid problem with symbolic links
        self.logger.info('[{}] >> Copying {}'.format(name, dst))
        command = '/bin/cat {} | /usr/bin/lxc-attach -n {} -- /bin/rm -f {}'.format(src, name, dst)
        self._sysexec(command, name)
        command = '/bin/cat {} | /usr/bin/lxc-attach -n {} -- /bin/bash -c "/bin/cat > {}"'.format(src, name, dst)
        self._sysexec(command, name)
        # Set permissions to file
        self.logger.debug('[{}] >> Setting file permissions {}'.format(name, os.path.dirname(dst)))
        command = '/usr/bin/lxc-attach -n {} -- /bin/chmod {} {}'.format(name, fmode_chmod, dst)
        self._sysexec(command, name)


    def fix_etc_hosts_file(self, name):
        self.logger.debug('Fixing /etx/hosts file: {}'.format(name))
        # Replace $LXC_CT_BASENAME with $HOSTNAME in /etc/hosts file
        self.logger.debug('[{}] >> Fixing /etc/hosts'.format(name))
        command = '/usr/bin/lxc-attach -n {} -- /bin/sed -i "s/{}/{}/g" /etc/hosts'.format(name, LXC_CT_BASENAME, name)
        #sed -i 's/ugly/beautiful/g' /home/bruno/old-friends/sue.txt
        self._sysexec(command, name)

    def _sysexec(self, command, name=''):
        self.logger.debug('_sysexec: @{}# {}'.format(command, name))
        try:
            self.logger.info('time.sleep()')
            time.sleep(SYSEXEC_BACKOFF)
            self.logger.info("command: {}".format(command))
            lxc.subprocess.check_call(command, shell=True)
        except Exception as e:
            self.logger.error('_sysexec: {}'.format(e))

    def get_default(self, request):
        return web.Response(text="\nThe backend of CES orchestration UI\n")

    def create_ctbase(self, request):
        created_status = self._create_ctbase(LXC_CT_BASENAME)
        if created_status == CONTAINER_EXISTS:
            return web.Response(text="\nBase container <{}> already exists\n".format(LXC_CT_BASENAME))
        elif created_status == CONTAINER_CREATION_FAILED:
            return web.Response(text="\nFailed to create base container <{}>\n".format(LXC_CT_BASENAME))
        else:
            return web.Response(text="\nBase container '{}' created successfully\n".format(LXC_CT_BASENAME))

    def _getContainerList(self):
        return lxc.list_containers()

    def _getContainerStatus(self):
        ct_status = {}
        try:
            containerObjList = lxc.list_containers(as_object=True)
            for ct in containerObjList:
                ct_type = "unknown"
                ct_state = ct.state
                # ToDo: add a check if the container belongs to network.
                #ct_status[ct.name] = ct.state

                if self.container_mgr.hasContainer(ct.name):
                    ct_info = self.container_mgr.getContainer(ct.name)
                    ct_type = ct_info.get_container_type()
                    ct_type = self.format_container_type_for_frontend(ct_type)

                ct_status[ct.name] = (ct_type, ct_state)

        except:
            self.logger.error("Exception in getting container status")
        return ct_status

    def format_container_type_for_frontend(self, ct_type):
        parsed_str = ct_type.split("_")
        parsed_str = ' '.join(parsed_str)
        return parsed_str

    def _getContainerStatusById(self, ct_name):
        ct_status = None
        try:
            containerObjList = lxc.list_containers(as_object=True)
            # ToDo: add a check if the container belongs to network.
            for ct in containerObjList:
                if ct.name == ct_name:
                    return ct.state
        except:
            self.logger.error("Exception in getting container status")
        return ct_status

    def show_container_list(self, request):
        container_lst = self._getContainerList()
        if len(container_lst)==0:
            return web.Response(text="\nNo container found\n")

        resp_txt = "\nContainer list: \n"
        for itm in container_lst:
            resp_txt += itm + "\n"
        return web.Response(text=resp_txt)

    def get_container_list(self, request):
        """ Returns containers other than base container (i.e. ctbase)
        For web dashboard, we can also return more information (i.e. status of running containers and type of containers).
        """
        container_lst = list(self._getContainerList())
        if LXC_CT_BASENAME in container_lst:
            container_lst.remove(LXC_CT_BASENAME)
        return web.Response(text = json.dumps(container_lst))


    def get_container_status(self, request):
        ct_status = self._getContainerStatus()
        if LXC_CT_BASENAME in ct_status:
            del ct_status[LXC_CT_BASENAME]
        return web.Response(text=json.dumps(ct_status))

    def get_container_info(self, request):
        """ This shall return container info in an acceptable JSON format """
        start_time = time.time()
        container_id = request.match_info.get('id')
        if container_id not in self._getContainerList():
            return web.Response(text="Container '{}' doesn't exist".format(container_id))

        if not self.container_mgr.hasContainer(container_id):
            return web.Response(text="No information on container '{}' is found in backend script".format(container_id))

        ct = self.container_mgr.getContainer(container_id)
        ct_type = ct.get_container_type()

        ct_info = {}
        ct_info["name"] = container_id
        ct_info["type"] = ct_type
        ct_info["iface_br_info"] = {}
        ct_info["iface_ip_info"] = {}

        iface_br_map = ct.get_iface_bridge_map()
        for iface, br in iface_br_map.items():
            ct_info["iface_br_info"][iface] = br

        iface_ip_map = ct.get_iface_ip_mapping()
        for iface, ip_addr in iface_ip_map.items():
            ct_info["iface_ip_info"][iface] = ip_addr

        lapsed_time = time.time() - start_time
        print("Get container info time lapsed {}".format(lapsed_time))

        return web.Response(text=json.dumps(ct_info))



    def start_container(self, request):
        """ Starts container requested by HTTP front end """
        container_id = request.match_info.get('id')
        if container_id not in self._getContainerList():
            return web.Response(text="Container '{}' doesn't exist".format(container_id))

        self.ct_start(container_id)
        ct_status = self._getContainerStatusById(container_id)

        if ct_status == "RUNNING":
            return web.Response(text="Container '{}' started".format(container_id))
        elif ct_status == "STOPPED":
            return web.Response(text="Container '{}' failed to start".format(container_id))
        else:
            return web.Response(text="Container '{}' status is unknown".format(container_id))


    def stop_container(self, request):
        """ Stops a container requested by HTTP front end """
        start_time = time.time()
        container_id = request.match_info.get('id')
        if container_id not in self._getContainerList():
            return web.Response(text="Container '{}' doesn't exist".format(container_id))

        self.ct_stop(container_id)
        ct_status = self._getContainerStatusById(container_id)
        lapsed_time = time.time() - start_time
        print("Time to stop container: {}".format(lapsed_time))

        if ct_status == "STOPPED":
            return web.Response(text="Container '{}' is stopped successfully".format(container_id))
        elif ct_status == "RUNNING":
            return web.Response(text="Failed to stop the container '{}'".format(container_id))
        else:
            return web.Response(text="Container '{}' status is unknown".format(container_id))


    def destroy_ctbase(self, request):
        name = LXC_CT_BASENAME
        ct = lxc.Container(name)
        self.logger.debug("Container '{}' definition status: {}".format(name, ct.defined))

        if ct.defined:
            self.ct_stop(name)
            if ct.destroy():
                return web.Response(text="\nContainer '{}' successfully destroyed\n".format(LXC_CT_BASENAME))
            else:
                self.logger.debug("Failed to destroy container '{}', could there be existing clones?".format(name, ct.defined))
                return web.Response(text="\nFailed to destroy container '{}'\n".format(LXC_CT_BASENAME))
        else:
            return web.Response(text="\nContainer '{}' doesn't exist\n".format(LXC_CT_BASENAME))

    # Shall have function to record all container configs in some json, and tell script to get the hosts up in a certain network configuration.
    #

    def prepare_iface_configs(self, ct_name, ct_type, index, br_name, iface_name, ip_addr_list=[]):
        """ Returns a Python string of configuration to be recorded OR None for failure"""
        try:
            iface_cfg = ""
            iface_cfg += "# Interface no. {} configuration\n".format(index)
            iface_cfg += "lxc.net.{}.type = veth\n".format(index)
            iface_cfg += "lxc.net.{}.veth.pair = {}_{}\n".format(index, ct_name, iface_name)
            iface_cfg += "lxc.net.{}.link = {}\n".format(index, br_name)
            iface_cfg += "lxc.net.{}.flags = up\n".format(index)
            iface_cfg += "lxc.net.{}.name = {}\n".format(index, iface_name)

            for ip_addr in ip_addr_list:
                iface_cfg += "lxc.net.{}.ipv4.address = {}/24\n".format(index, ip_addr)
                # Additional possibility, to check if user provided a valid IPv4 address (format and context wise)
            return iface_cfg
        except Exception as ex:
            self.logger.error("Exception: {}".format(ex))
            return

    def get_common_container_config(self):
        """ Common configuration at start of each container """
        iface_common_cfg = "# Common configuration\n"
        iface_common_cfg += "lxc.include = /usr/share/lxc/config/ubuntu.common.conf"
        iface_common_cfg += "# Container specific configuration\n"
        iface_common_cfg += "lxc.arch = amd64\n"
        iface_common_cfg += "# Network configuration\n\n"
        return iface_common_cfg

    def _get_bridge_of_next_container(self, next_ct_name, iface_direction):
        if self.container_mgr.hasContainer(next_ct_name):
            next_ct = self.container_mgr.getContainer(next_ct_name)
            next_ct_iface_direction = None
            # For private facing interface, we should find bridge name on public facing interface of next_ct
            # print("Router's iface_direction:", iface_direction)
            if iface_direction == "private":    next_ct_iface_direction = "public"
            else:                               next_ct_iface_direction = "private"

            next_ct_iface_name = next_ct.get_interface_by_type(next_ct_iface_direction)
            br_name = next_ct.get_iface_bridge(next_ct_iface_name)
            return br_name
        else:
            return None

    def get_bridge_name(self, ct_name, ct_type, iface_name, iface_configs):
        """ Get bridge to be attached to a container's interface """
        try:
            iface_direction = None
            if "iface_direction" in iface_configs[iface_name]:
                iface_direction = iface_configs[iface_name]["iface_direction"]

            if iface_name == self.default_iface:
                self.default_br_name = "lxcmgt0"
                return self.default_br_name

            elif ct_type == "gateway":
                br_name = self.get_new_bridge(ct_name, ct_type, iface_name, iface_direction)
                return br_name

            else:                    # to get new interface, if type = "gateway"
                if (iface_direction is None) or (iface_direction not in ["private", "public"]):
                    self.logger.error("No valid direction of interface '{}' for container '{}' is specified".format(iface_name, ct_name))
                    return None

                if ct_type in ["router", "public_host"]:
                    next_ct_name = None
                    # Should I check if a router node is created, prior to creating a public-host? (because public host needs to connect to router).
                    if "next_container" in iface_configs[iface_name]:
                        next_ct_name = iface_configs[iface_name]["next_container"]
                        if self.container_mgr.hasContainer(next_ct_name):
                            br_name = self._get_bridge_of_next_container(next_ct_name, iface_direction)
                            return br_name
                        else:
                            self.logger.info("Next container named '{}' does not exist".format(next_ct_name))
                            return None
                    else:
                        br_name = self.get_new_bridge(ct_name, ct_type, iface_name, iface_direction)
                        if br_name is not None:
                            return br_name

                elif ct_type in ["proxy", "private_host"]:
                    gateway_name = None
                    if "gateway_name" in iface_configs[iface_name]:
                        gateway_name = iface_configs[iface_name]["gateway_name"]
                        ces_gateway_found = True

                        if self.container_mgr.hasContainer(gateway_name):
                            br_name = self._get_bridge_of_next_container(gateway_name, iface_direction)
                            return br_name
                        else:
                            self.logger.info("Gateway container named '{}' does not exist".format(gateway_name))
                            return None
                    else:
                        if ct_type == "private_host":
                            # If for host, no gateway container is specified on all interfaces then give error.
                            self.logger.info("No gateway container is specified for host-container {}".format(ct_name))
                            return
                        elif ct_type == "proxy":
                            # If for proxy, no gateway container is specified (on single interface) then create new bridge for interface
                            # If for proxy, no gateway container is specified on any interfaces then give error.
                            br_name = self.get_new_bridge(ct_name, ct_type, iface_name, iface_direction)
                            if br_name is not None:
                                return br_name

                            """
                            To be fixed
                            if (index == len(iface_configs)) and (ces_gateway_found is False):
                                self.logger.info("No gateway container specified for container '{}' of type '{}'".format(ct_name, ct_type))
                                return
                            """

                return None

        except Exception as ex:
            self.logger.error("Exception: '{}'".format(ex))
            return


    def get_new_bridge(self, ct_name, ct_type, iface_name, iface_direction):
        """ Returns new bridge name based on container-name and interface name """
        try:
            br_name = "br-{}-{}".format(ct_name, iface_name)              # Bridge name could be 'br-<iface>-<ct_name>'
            #self.logger.info("HAKA 1 ct_type {}, iface_direction {}".format(ct_type, iface_direction))
            if (ct_type == "gateway") and (iface_direction == "public"):
                br_name += "p"          # indicating proxy-ed interface on public side of gw container

            #self.logger.info("HAKA 2")
            if len(br_name) > 15:
                self.logger.info("Bridge name '{}' longer than 16 characters is not allowed".format(br_name))
                return

            self.logger.info("New bridge name '{}'".format(br_name))
            return br_name
        except Exception as ex:
            self.logger.info("Bridge could not be created for '{}', '{}'".format(ct_name, iface_name))
            return None

    def get_iface_direction(self, iface_name, iface_configs, ct_name):
        try:
            iface_direction = None
            if "iface_direction" in iface_configs[iface_name]:
                iface_direction = iface_configs[iface_name]["iface_direction"]

            if (iface_direction is None) or (iface_direction not in ["private", "public", "mgmt"]):
                self.logger.error(
                    "No valid direction of interface '{}' for container '{}' is specified".format(iface_name, ct_name))
                return None
            return iface_direction
        except:
            return

    def create_config(self, ct_name, ct_type, config_json):
        try:
            #print("config_json: ", config_json)
            iface_configs = config_json["interfaces"]
            numOfDefinedInterfaces = len(iface_configs)
            if numOfDefinedInterfaces == 0:
                return

            iface_cfg = ""
            default_gw_route_configured = False
            ces_gateway_found = False
            iface_common_cfg = self.get_common_container_config()
            c = ContainerInfo(ct_name, ct_type)          # Recorded to container manager, after all configurations are verified.

            idx = 0
            for iface_name in iface_configs:
                #Can check if 'iface_name' string is not too long - enforce limit of 4 characters
                self.logger.info("HAKA container_name {}, interface #{}, interface-name {}".format(ct_name, idx, iface_name))
                br_name = self.get_bridge_name(ct_name, ct_type, iface_name, iface_configs)
                if br_name is None:
                    return

                iface_direction = self.get_iface_direction(iface_name, iface_configs, ct_name)
                if iface_direction is None:
                    return None

                ip_addr_list = []           # Interfaces of proxy type container may not have any IP address
                if "ip_addr" in iface_configs[iface_name]:
                    ip_addr_list = iface_configs[iface_name]["ip_addr"]

                iface_specific_cfg = self.prepare_iface_configs(ct_name, ct_type, idx, br_name, iface_name, ip_addr_list)
                if iface_specific_cfg is None:
                    self.logger.info("Failed to create configuration for container '{}' of type '{}'".format(ct_name, ct_type))
                    return

                iface_cfg += iface_specific_cfg

                if "gateway" in iface_configs[iface_name]:
                    if default_gw_route_configured:
                        self.logger.error("A single container cannot have multiple defaults gateways")
                        return

                    default_gw_route_configured = True
                    gw_address = iface_configs[iface_name]["gateway"]
                    iface_cfg += "lxc.net.{}.ipv4.gateway = {}\n".format(idx, gw_address)

                #print("HAKA ip_addr_list:", ip_addr_list)
                c.register_interface_type(iface_name, iface_direction)
                c.register_iface_bridge(iface_name, br_name)
                c.register_iface_ipaddr_list_mapping(iface_name, ip_addr_list)
                self.register_bridge_name(br_name)

                # Create bridge only. if rest of interface configurations are okay.
                self.logger.info("Bridge to be created {}".format(br_name))
                self.create_bridge(br_name)
                # Add a separate new line at end of interface configuration.
                iface_cfg += "\n"
                idx += 1

            #print(iface_cfg)
            config_file = CT_CONFIG_DIR + "/" + ct_name + "_config"
            f = open(config_file, 'w')
            f.write(iface_common_cfg + iface_cfg)
            #print(config_file)
            self.logger.info("HAKA Configs created {}".format(br_name))
            self.container_mgr.addContainer(ct_name, c)
            return config_file

        except Exception as ex:
            traceback.print_exc()
            return None


    async def create_container(self, request):
        """
        Example command:
        curl -X POST -H "Content-Type: application/json" -d '{"interfaces": {"mgt0":["172.31.255.11"], "lan0":["192.168.0.1"], "wan0":["10.0.64.130"] }}' http://127.0.0.1:8080/create_container/gwa/gateway
        """
        container_type = request.match_info.get('type')
        container_id = request.match_info.get('id')
        self.logger.info("\n\n Request to create container {} of type {}".format(container_id, container_type))
        self.logger.debug("Container list: {}".format(self._getContainerList()))

        if container_id in self._getContainerList():
            return web.Response(text="\nContainer '{}' already exists\n".format(container_id))

        if (LXC_CT_BASENAME not in self._getContainerList()) and (self.base_ct_created is False):
            return web.Response(text="\nFailed to create container, as base container is not defined.\n")

        if container_type not in ["private_host", "public_host", "gateway", "proxy", "router"]:
            self.logger.info("Invalid request for creating container '{}' of type '{}'".format(container_id, container_type))
            return web.Response(text="\n Invalid request for creating container '{}' of type '{}'\n\n".format(container_id, container_type))

        start_time = time.time()
        try:
            config_payload_txt = await request.text()
            config_payload = json.loads(config_payload_txt)
            print("config_payload: ", config_payload)
            #config_payload = await request.json()
        except:
            traceback.print_exc()
            return web.Response(text="\nInvalid content of POST request\n")

        try:
            ct_config_path = self.create_config(container_id, container_type, config_payload)
            if ct_config_path is None:
                self.logger.error("Failed to create '{}' container configuration".format(container_id))
                return web.Response(text="\nFailed to create '{}' container configuration\n".format(container_id))

            base_ct_name = LXC_CT_BASENAME
            self._spawn_container(base_ct_name, container_id, ct_config_path)
            now = time.time()
            lapsed_time = now - start_time
            self.logger.info("container '{}' creation time = {}".format(container_id, lapsed_time))

            return web.Response(text="\nCreated container '{}' of type '{}'\n\n".format(container_id, container_type))
        except Exception as ex:
            traceback.print_exc()
            return web.Response(text="\nFailed to create container '{}'\n".format(container_id))


    def create_gw_script(self, request):
        start_time = time.time()
        gw_name = "gwa"
        domain_name  = "gwa.demo."
        domain_cname = "cname-gwa.demo."
        dns_port = 53
        dns_server_local_ip = "127.0.0.1"
        dns_server_lan_ip = "192.168.0.1"
        dns_server_wan_ip = "100.64.1.130"
        dns_resolver_ip = "100.64.0.1"
        ddns_server_ip = "127.0.0.2"

        ct = self.container_mgr.getContainer(gw_name)
        private_iface_name = ct.get_interface_by_type('private')
        private_iface_addr = ct.get_ip_for_interface(private_iface_name)
        dns_server_lan_ip = private_iface_addr
        public_iface_name = ct.get_interface_by_type('public')
        public_iface_addr = ct.get_ip_for_interface(private_iface_name)
        if type(private_iface_addr) == type(list()):
            dns_server_wan_ip = public_iface_addr[0]
        else:
            dns_server_wan_ip = private_iface_addr


        ces_start_script =  "#!/bin/bash\n\nif [[ $UID != 0 ]]; then\n\techo \"Please run this script with sudo:\"\n\techo \"sudo $0 $*\"\nexit 1\nfi\n\n"
        ces_start_script += "echo \"Starting Realm Gateway as gwa.demo\"\n"
        ces_start_script += "cd /home/ubuntu/CustomerEdgeSwitching/src \n"
        ces_start_script += "./rgw.py  --name {}            \\\n".format(domain_name)
        ces_start_script += "--dns-cname-soa {}             \\\n".format(domain_cname)
        ces_start_script += "--dns-soa 0.168.192.in-addr.arpa. 1.64.100.in-addr.arpa. \\\n".format()
        ces_start_script += "--dns-server-local {} {}       \\\n".format(dns_server_local_ip, dns_port)
        ces_start_script += "--dns-server-lan {} {}         \\\n".format(dns_server_lan_ip, dns_port)
        ces_start_script += "--dns-server-wan {} {}         \\\n".format(dns_server_wan_ip, dns_port)
        ces_start_script += "--dns-resolver {} {}           \\\n".format(dns_resolver_ip, dns_port)
        ces_start_script += "--ddns-server {} {}           \\\n".format(ddns_server_ip, dns_port)
        ces_start_script += "--dns-timeout 0.010 0.100 0.200  \\\n"
        ces_start_script += "--dns-timeout-naptr  0.100 0.200 0.300   \\\n"
        ces_start_script += "--pool-serviceip   100.64.1.130/32           \\\n"
        ces_start_script += "--pool-cpoolip     100.64.1.131/32 100.64.1.132/32 100.64.1.133/32  \\\n"
        ces_start_script += "--pool-cespoolip   172.16.1.100/26           \\\n"
        ces_start_script += "--ipt-cpool-queue  1           \\\n"
        ces_start_script += "--ipt-cpool-chain  CIRCULAR_POOL           \\\n"
        ces_start_script += "--ipt-host-chain   CUSTOMER_POLICY         \\\n"
        ces_start_script += "--ipt-markdnat                                                     \\\n"
        ces_start_script += "--ips-hosts        IPS_SUBSCRIBERS                                 \\\n"
        ces_start_script += "--ipt-policy-order PACKET_MARKING NAT mREJECT ADMIN_PREEMPTIVE \\\n"
        ces_start_script += "GROUP_POLICY CUSTOMER_POLICY ADMIN_POLICY ADMIN_POLICY_DHCP \\\n"
        ces_start_script += "ADMIN_POLICY_HTTP ADMIN_POLICY_DNS GUEST_SERVICES \\\n"
        ces_start_script += "--ipt-host-unknown CUSTOMER_POLICY_ACCEPT                          \\\n"
        ces_start_script += "--ipt-flush                                                        \\\n"
        ces_start_script += "--network-api-url  http://127.0.0.1:8081/                          \\\n"
        ces_start_script += "--repository-subscriber-folder ../config.d/gwa.demo.subscriber.d/  \\\n"
        ces_start_script += "--repository-policy-folder     ../config.d/gwa.demo.policy.d/      \\\n"
        ces_start_script += "--cetp-config  		../config.d/gwa.demo.cetp.policy/config_gwa.yaml       \\\n"
        ces_start_script += "--spm-services-boolean    False                                                      \\\n"
        ces_start_script += "--cetp-host-policy-location      http://10.0.3.200/API/cetp_policy_node?             \\\n"
        ces_start_script += "--cetp-network-policy-location   http://10.0.3.200/API/ces_policy_node?              \\\n"
        ces_start_script += "--cetp-policies-host-file      ../config.d/gwa.demo.cetp.policy/host_cetp_policies.json \\\n"
        ces_start_script += "--cetp-policies-network-file   ../config.d/gwa.demo.cetp.policy/network_cetp_policies.json \\\n"
        ces_start_script += "--repository-api-url  	   http://10.0.3.200:8001                              \\\n"
        ces_start_script += "--synproxy         		   127.0.0.1 12345"

        file_name = "run_{}.sh".format(gw_name)
        local_script_dir = "bootup_scripts"
        """
        cloned_ct_path = os.path.join( CONTAINER_BASE_PATH, gw_name )
        cloned_ct_path = os.path.join(cloned_ct_path, "delta0")
        cloned_ct_path = os.path.join(cloned_ct_path, "home/ubuntu")
        file_path = os.path.join(cloned_ct_path, file_name)
        """
        file_name = "ces_run_script.sh"
        fp = open(file_path, "w")
        fp.write(ces_start_script)
        lapsed_time = time.time() - start_time
        print("HAKA create_gw_script {}".format(lapsed_time))
        return web.Response(text="Script is created to run CES on gateway node.")


    def echo_back(self, request):
        return web.Response(text="\nEcho back\n")

    def _ct_destroy_exec(self, name, verbose = False):
        ct = lxc.Container(name)
        self.logger.debug("Container '{}' definition status: {}".format(name, ct.defined))
        if not ct.defined:
            self.logger.warning('Not defined container cannot be destoryed: {}'.format(name))
            return
        command = 'lxc-destroy -n {}'.format(name)
        self._sysexec(command, 'host')

    def destroy_container(self, request):
        start_time = time.time()
        container_id = request.match_info.get('id')
        if container_id in self._getContainerList():
            self.ct_destroy(container_id)
            lapsed_time = time.time() - start_time
            self.logger.info("destroyed container {}".format(lapsed_time))
            if container_id in self._getContainerList():
                return web.Response(text="\nFailed to destroy '{}' container\n".format(container_id))
            else:
                self.container_mgr.removeContainer(container_id)
                return web.Response(text="\nSuccessfully destroyed '{}' container\n".format(container_id))
        else:
            return web.Response(text="\nThere is no '{}' container to destroy\n".format(container_id))

    async def test_post(self, request):
        print("test_post func")
        #print("1. post():", request.match_info.post())
        post_payload = await request.text()    # can also use request.json()
        print("post_payload: ", post_payload)
        return web.Response(text="\n Post successful\n")

class BackendMgmt:
    def __init__(self):
        self.object = LxcEnv()
        self.network_state_file = "network_state.json"
        self.container_mgr = self.object.container_mgr

    def load_network_state(self):
        print("Loading network data")
        network_data = json.load(open(self.network_state_file))
        print("network_state: ", network_data)
        if len(network_data) == 0:
            return

        for name, ct_info in network_data.items():
            ct = ContainerInfo(name)
            load_result = ct.load_configs(ct_info)
            if load_result is False:
                print("\nFailed to load network container states\n")
                return
            self.container_mgr.addContainer(name, ct)

    def save_network_state(self):
        """ Will add network name based state saving later """
        print("Saving network state to JSON dump file")
        network_state = {}
        outputFileHandler = open(self.network_state_file, 'w')

        num_of_containers = self.container_mgr.numOfContainers()
        container_mgr = self.container_mgr.getContainerManager()
        if num_of_containers == 0:
            json.dump(network_state, outputFileHandler)
        else:
            for ct_name, ct_info in container_mgr.items():
                network_state[ct_name] = ct_info.dump_configs()

            print("network_state: ", network_state)
            json.dump(network_state, outputFileHandler)

    # URL mappers to callbacks
    async def build_server(self, loop, address, port):
        app = web.Application(loop=loop)
        #await object.connect()

        # http://127.0.0.1/API/test_post"
        app.router.add_post("/test_post", self.object.test_post)

        # http://127.0.0.1:8080/
        app.router.add_get("/", self.object.get_default)

        # http://127.0.0.1/echo
        app.router.add_get("/echo", self.object.echo_back)

        # http://127.0.0.1/create_gw_script"
        app.router.add_get("/create_gw_script", self.object.create_gw_script)

        # http://127.0.0.1:8080/show_container_list
        app.router.add_get("/show_container_list", self.object.show_container_list)

        """ List of stable URLs """
        # http://127.0.0.1:8080/get_container_list
        app.router.add_get("/get_container_list", self.object.get_container_list)

        # http://127.0.0.1:8080/get_container_status
        app.router.add_get("/get_container_status", self.object.get_container_status)

        # http://127.0.0.1:8080/create_base_ct
        app.router.add_get("/create_base_ct", self.object.create_ctbase)

        # http://127.0.0.1:8080/destroy_base_ct
        app.router.add_get("/destroy_base_ct", self.object.destroy_ctbase)

        # http://127.0.0.1:8080/start_container/{id}
        app.router.add_get("/start_container/{id}", self.object.start_container)

        # http://127.0.0.1:8080/stop_container/{id}
        app.router.add_get("/stop_container/{id}", self.object.stop_container)

        # http://127.0.0.1:8080/destroy_container/{id}"
        app.router.add_get("/destroy_container/{id}", self.object.destroy_container)

        # http://127.0.0.1:8080/get_container_info/{id}
        app.router.add_get("/get_container_info/{id}", self.object.get_container_info)

        # http://127.0.0.1:8080/create_container/{type}/{id}"
        app.router.add_post("/create_container/{type}/{id}", self.object.create_container)

        return await loop.create_server(app.make_handler(), address, port)

if __name__ == '__main__':
    backendMgmt = BackendMgmt()
    backendMgmt.load_network_state()
    loop = asyncio.get_event_loop()
    loop.run_until_complete(backendMgmt.build_server(loop, '127.0.0.1', 8080))
    print("Server ready!")

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print("Shutting Down!")
        backendMgmt.save_network_state()
        loop.close()
