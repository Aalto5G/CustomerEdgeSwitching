#!/bin/bash

LOG_LEVEL=WARNING sudo -E ./async_echoserver_v4.py --tcp 100.64.2.139:81 100.64.2.140:81 100.64.2.141:81 100.64.2.142:81 100.64.2.139:82 100.64.2.140:82 100.64.2.141:82 100.64.2.142:82 100.64.2.139:83 100.64.2.140:83 100.64.2.141:83 100.64.2.142:83 100.64.2.139:84 100.64.2.140:84 100.64.2.141:84 100.64.2.142:84 --udp 100.64.2.139:81 100.64.2.140:81 100.64.2.141:81 100.64.2.142:81 100.64.2.139:82 100.64.2.140:82 100.64.2.141:82 100.64.2.142:82 100.64.2.139:83 100.64.2.140:83 100.64.2.141:83 100.64.2.142:83 100.64.2.139:84 100.64.2.140:84 100.64.2.141:84 100.64.2.142:84  > /dev/null
