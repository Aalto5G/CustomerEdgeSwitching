
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
