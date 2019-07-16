"""
BSD 3-Clause License

Copyright (c) 2019, Hammad Kabir, Aalto University, Finland
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import socket, struct

def ip2int(ip4addr):
    """
    Convert an IPv4 address to integer.        
    @param addr: The IPv4 address in string format.
    @return: The integer value of the IPv4 address.  
    """
    return struct.unpack("!I", socket.inet_aton(ip4addr))[0]

def int2ip(ip4int):
    """
    Convert an integer to IPv4 address.        
    @param addr: The integer value of the IPv4 address.  
    @return: The IPv4 address in string format.
    """
    return socket.inet_ntoa(struct.pack("!I", ip4int))

def ip62int(ip6addr):
    """
    Convert an IPv6 address to integer.
    @param addr: The IPv6 address in string format.
    @return: The integer value of the IPv4 address.  
    """
    try:
        _str = socket.inet_pton(socket.AF_INET6, ip6addr)
    except socket.error:
        raise ValueError
    a, b = struct.unpack('!2Q', _str)
    return (a << 64) | b    

def int2ip6(ip6int):
    """
    Convert an integer to IPv6 address.        
    @param addr: The integer value of the IPv6 address.  
    @return: The IPv6 address in string format.
    """ 
    a = ip6int >> 64
    b = ip6int & ((1 << 64) - 1)
    return socket.inet_ntop(socket.AF_INET6, struct.pack('!2Q', a, b))
