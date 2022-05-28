#!/usr/bin/python3

from aiohttp import web
import json
import asyncio
import logging
import io
import os
import lxc
import sys
import time
import traceback
import stat

CTUSER              = 'ubuntu'
CTPASSWORD          = 'ubuntu'
CONTAINER_BASE_PATH = "/var/lib/lxc"

def create_ctbase_container(name):
    verbosity = 1
    start_time = time.time()
    ctbase = lxc.Container(name)
    if not ctbase.create('ubuntu', verbosity, {'user': CTUSER, 'password': CTPASSWORD}):
        self.logger.error("Failed to create the container '{}'".format(name))
        return CONTAINER_CREATION_FAILED

    now = time.time()
    time_lapsed = now - start_time
    print("Basic container creation")
    print(f"Time lapsed: {time_lapsed}")

def _sysexec(command, name=''):
    try:
        #time.sleep(SYSEXEC_BACKOFF)
        lxc.subprocess.check_call(command, shell=True)
    except Exception as e:
        self.logger.error('_sysexec: {}'.format(e))

def test_container_creation_via_clone(base, newCt):
    """
    ct_dst = lxc.Container(newCt)
    if ct_dst.defined:
        self.logger.warning('Destination clone already exists: {}'.format(dst))
        return
    """
    start_time = time.time()

    # Clone base container with snapshot
    command = 'lxc-copy -n {} -N {} -s -F'.format(base, newCt) # Ubuntu 16.04
    _sysexec(command, 'host')

    now = time.time()
    time_lapsed = now - start_time
    print("Create container from base")
    print(f"Time lapsed: {time_lapsed}")


base_name="ctbase1"
#create_ctbase_container(name)
test_container_creation_via_clone(base_name, "newCt")
