import asyncio

class CETPClient:
    def __init__(self, r_cesid):
        self.client_q   = asyncio.Queue()        # Enqueues the naptr responses triggered by private hosts (served by CES)
        self.c2c_q      = asyncio.Queue()        # Enqueues the response from remote peer (iCES), to H2H transactions
        self.r_cesid    = r_cesid
        self.trust_established = False

    def get_cetp_c2c(self, naptr_list):
        self.c2c = oCETPC2C(naptr_list, self)    #or c2cManager.getC2C(’cesid’)    # Register as well

    @asyncio.coroutine
    def enqueue(self, msg):
        yield from self.client_q.put(msg)        # Enqueues the naptr responses triggered by private hosts

    @asyncio.coroutine
    def consume_queue(self):
        while True:
            if self.trust_established == False:     # No processing of h2h, if the c2c-negotiation or trust establishment takes more than 'To' seconds.
                yield from asyncio.sleep(0.005)     # 2-to-5 millisecond interval for re-checking if trust established
                continue
            msg = yield from self.q.get()
            asyncio.ensure_future(self.h2h_transaction(msg) )
            self.client_q.task_done()

    @asyncio.coroutine
    def h2h_transaction(self, msg):
        naptr, host = msg
        h2h = H2HTransactionOutbound(naptr, host)
        cetp_msg = yield from h2h.start_cetp_processing()
        sstag, dstag = cetp_msg['sst'], cetp_msg['dst']
        self.cetp_state_mgr.register_h2h(sstag, dstag, h2h)    # Register state to continue processing later.
        self.send(cetp_msg)
        
    def send(self, msg):
        self.c2c.send(msg)
        
    @asyncio.coroutine
    def process_response(self, resp_msg):
        param_lst = None
        #param_lst = get_cetp_parameters(resp_msg)           # Some function in Utils class. 
        h2h = self.cetp_state_mgr.get_H2H_transaction(param_lst)
        res = yield from h2h.continue_cetp(resp_msg)        # return True, False, or response
        if res ==True:        pass # (Fine – process callbacks)        # Process callback internally in continue_cetp()
        if res ==False:       pass # self.send(error_resp)

    @asyncio.coroutine
    def c2c_msg_enqueue(self, msg):
        yield from self.c2c_q.put(msg)                      # Enqueues the CETP message from iCES, forwarded by CETPTransport layer

    @asyncio.coroutine
    def c2c_msg_consume(self):
        msg = yield from self.c2c_q.get()                   # Gets the CETP message sent by iCES
        if msg == "trust_established":
            self.trust_established == True
        else:
            asyncio.ensure_future(self.process_response(msg))
            
            

class H2HTransactionOutbound:
    def _init_(self, i_cesid, r_cesid, sstag, dstag, cetp_state_mgr, policy_client):
        self.state_mgr = state_mgr
        self.policy_client = policy_client

    def pre_process(self, msg):
        self.sanity_checking(msg)   # for min packet details & format    - on response packet

    def sanity_checking(self, msg):
        pass

    @asyncio.coroutine
    def start_cetp_processing(self):
        policies = yield from self.get_policies_from_PolicySystem(r_id, r_cesid)
        o_cetp_packet = cetp_processing(policies)
        return cetp_packet

    def continue_cetp_processing(self, msg):
        l_policy = get_cached_policy()
        if policies_match_both_ways:
            self.create_transaction_in_dp()
            self.dns_callback(dns_response)
        return msg                                                      # resp_msg, error_message, or None.

    def create_transaction_in_dp(self, cetp_msg):
        cetp_msg
        self.create_dataplane_entry(sst, dst, info)

    @asyncio.coroutine
    def get_policies_from_PolicySystem(self, r_hostid, r_cesid):        # Has to be a coroutine in asyncio - PolicyAgent
        yield from self.policy_client.send(r_hostid, r_cesid)



            
class oC2CTransaction:
    def _init_(self, i_cesid, r_cesid, sstag, dstag, cetp_state_mgr, policy_client):
        self.state_mgr = state_mgr
        self.policy_client  = policy_client
        self.i_cesid        = i_cesid
        self.r_cesid        = r_cesid
        self.cespolicy      = None

    def pre_process(msg):
        sanity_checking()       # for min packet details & format - on response packet

    @asyncio.coroutine
    def get_remote_ces_reputation():
        """ Reports any change in remote-ces reputation & triggers any corresponding action at c2c-Layer """
        pass
        
        
    @asyncio.coroutine
    def start_cetp_processing():
        policies = yield from self.get_policies_from_PolicySystem(r_id, r_cesid)
        o_cetp_packet = cetp_processing(policies)
        return cetp_packet

    def continue_cetp_processing(msg):
        l_policy = get_cached_policy()
        if policies_match_both_ways:
            self.trust_established = True
            return msg                              # or trust_establishment_status

    def post_trust_establishment(msg):
        rate_limit_cetp_flows(), block_host(), ratelimit_host(), SLA_violated()
        New_certificate_required(), ssl_renegotiation(), DNS_source_traceback()

    @asyncio.coroutine
    def get_policies_from_PolicySystem(self, r_hostid, r_cesid):    # Has to be a coroutine in asyncio - PolicyAgent
        yield from self.policy_client.send(r_hostid, r_cesid)
                    
            
            
  
class oCETPC2C:
    def __init__(self, naptr_list, cetp_client):
        self.q              = asyncio.Queue()        # Enqueues the CETP message from CETP Transport
        self.cetp_client    = cetp_client            # H2H layer manager for remote-cesid 
        self.get_cetp_transport(naptr_list)
        self.trust_established = False

    def get_cetp_transport(self, naptr_list):
        self.transport_layer = oCETPTransportMgr(naptr_list, self) 

    def send_cetp(self, msg):
        self.transport_layer.send_cetp(self, msg)

    @asyncio.coroutine
    def enqueue_cetp(self, msg):
        yield from self.q.put(msg)    

    @asyncio.coroutine
    def process_t2t_cetp(self):
        msg = yield from self.q.get()
        if self.trust_established == False:
            asyncio.ensure_future(self.process_c2c(msg))        # to exchange ces-policies and security policies.
        elif self.trust_established == True: #AND (sstag, dstag) belong to another c2c:
            asyncio.ensure_future(self.process_c2c(msg))        # to exchange ces-policies and security policies on another naptr.
        elif  self.is_c2c_transaction(msg) & self.trust_established==True:
            asyncio.ensure_future(self.process_c2c(msg))        # to get c2c-feedback or keepalive or whatever.
            self.q.task_done()
        else:
            self.forward_h2h(msg)            # - Message belongs to H2H layer.

    def is_c2c_transaction(msg):
        # Do some processing.
        pass                    # Either return True or return False.
    
    def forward_h2h(self, msg):
        self.cetp_client.c2c_msg_enqueue(msg)
            
    def process_c2c(self, msg):
        #fucntion for -- CES2CES-FSM, security, remote CES feedback, evidence collection, and other indicators.
        #if c2c security FSM negotiation succeeds:     self.forward_h2h(”trust_established”)
        pass
    
        #report_host():  OR enforce_ratelimits():        # Invoking these methods to report a misbehaving host to remote CES.
      
  
  
class oCETPTransportMgr:
    def __init__(self, naptr_list, c2cobj):
        self.c2c = c2cobj
        self.initiate_cetp_transport(naptr_list)
        self.initiated_transports = []
        self.connected_transports = []
    
    def initiate_cetp_transport(self, naptr_list):
        for naptr in naptr_list:
            if naptr_proto = 'tcp':      transport_instance = oCETPTransportTCP(self, 'tcp')
            if naptr_proto = 'tls':      transport_instance = oCETPTransportTLS(self, 'tls’)
            if naptr_proto = 'grpc':     transport_instance = oCETPTransportGRPC(self, 'grpc')

            asyncio.ensure_future( loop.create_connection(lambda: transport_instance, ip_addr, port) )
            self.initiated_transports.append(transport_instance)

    def register_connected_transports(self, transport):
        """ Registered connected CETP Transports """
        self.connected_transports.append(transport)
    
    def select_transport(self):
        # some processing to select current cetp_transport, based on
        #self.load_balancing() or self.best_Health(), or self.path_with_smalllest_rtt().
        #return cetp_transport
        pass
    
    def send_cetp(self, msg):
        current_transport = self.select_transport()
        current_transport.send_cetp(msg)

    def transport_report(self, msg):
        self.transport_layer_specific_processing()        # Last seen timestamp etc.
        self.c2c.enqueue_cetp( msg )

        #Also manages: 1) transport link failover; 2) keepalive signalling for health-checking of the transport link.


          
class oCETPTransport(asyncio.Protocol):
    def __init__(self, transport_layer, proto):
        self.t_layer = transport_layer

    def connection_made(self, transport):
        self.transport = transport
        self.t_layer.transport_report("Channel connected" )        # Reporting the connectivity to upper layer.
        
    def send_cetp(self, msg):
        framed_msg = self.message_framing(msg)
        self.transport.write(framed_msg.encode())

    def message_framing(self, msg):
        # Some framing
        return cetp_frame

    def data_received(self, data):
        data = data.decode()
        cetp_msg = self.unframe(data)
        self.t_layer.transport_report( cetp_msg )

    def unframe(self, data)
        # Some processing.
        return cetp_msg
    
    def connection_lost(self, exc):
        print('The server closed the connection')
        # process exc


"""
loop = asyncio.get_event_loop()
coro = loop.create_connection(lambda: EchoClientProtocol(message, loop), '127.0.0.1', 8888)
loop.run_until_complete(coro)
loop.run_forever()
"""

class H2H_Transaction_Inbound:
    def _init_(self, i_cesid, r_cesid, sstag, dstag, cetp_state_mgr, policy_client):
        self.state_mgr = state_mgr
        self.policy_client = policy_client

    def pre_process(self, msg):
        sanity_checking() for min packet details & format

    def start_cetp_processing(self, msg):
        policies = yield from self.get_policies_from_PolicySystem(r_id, r_cesid)
        if policies_match_both_ways:
            self.export_to_stateful(self)
            self.create_transaction_in_dp()
        return msg, error_message etc.

    def create_transaction_in_dp(self):
        self.create_dataplane_entry(sst, dst, info)

    def export_to_stateful(self):
        self.create_cetp_stateful(self)    # stateful (sst, dst) h2h entry

    @asyncio.coroutine
    def get_policies_from_PolicySystem(self, r_hostid, r_cesid):
        yield from self.policy_client.send(r_hostid, r_cesid)


        
class CETPServer:
    def __init__(self, c2clayer, r_cesid):
        self.c2c_q = asyncio.queue()
        self.c2c = c2clayer
        self.r_cesid = r_cesid

    def send(self, msg):
        self.c2c.send_cetp(msg)
 
    @asyncio.coroutine
    def c2c_msg_enqueue(self, msg):
        yield from self.c2c_q.put(msg)       # Enqueues the CETP message from oCES, forwarded by CETPTransport layer

    @asyncio.coroutine
    def c2c_msg_consume(self):
        while True:
            msg = yield from self.c2c_q.get()        # Retrieves the CETP message from oCES
            asyncio.ensure_future(self.process_msg(msg))
            self.c2c_q.task_done()

    @asyncio.coroutine
    def process_msg(self, cetp_msg):
        res = yield from self.h2h_transaction(msg)
        if True:    self.send(res)        # Transaction accepted
        elif False:    self.send(error_msg)    # Transaction dropped
        else:    self.send(res)        # Transaction continues (resolution).

    def h2h_transaction(self, msg):
        cetp_msg = yield from h2h.start_cetp_processing(msg)
        

        
class iCETPC2C:
    def __init__(self, cesid, c2c_cetp_transaction, t2t_mgr):
        self.q    = asyncio.Queue()        # Enqueues the CETP messages from CETP Transport
        self.t     = t2t_mgr        # This shall be transport layer manager
        self.c2c_cetp_transaction = c2c_cetp_transaction.

    def send_cetp(self, msg):
        self.t.send_cetp(msg)

    @asyncio.coroutine
    def enqueue_cetp(self, msg):
        yield from self.q.put(msg)

    @asyncio.coroutine
    def process_t2t_cetp(self):
        while True:
            msg = yield from  self.q.get()
            if  is_c2c_transaction(msg):        process_c2c(msg)
            else:            forward_h2h(msg)
            self.q.task_done()

    def forward_h2h(self, msg):
        self.cetp_h2h.c2c_msg_enqueue(msg)
            
    def process_c2c(self, msg):
        function for -- security, remote CES feedback, evidence collection, and other indicators.
        This is the CETP message received with (cetp.csst, cetp.cdst) session tags.

    def report_host(self):          
        #(or def enforce_ratelimits():)
        # These methods are invoked to report a misbehaving host to remote CES.

    def create_cetp_server(self, r_cesid):
        self.cetp_h2h= CETPServer(self, r_cesid)
        
        
class CETPc2cManager:
    # Doesn't belong to iCES layering model, rather only manages the connected clients under one CETP server_instance.
    def __init(self, c2c_mgr):
        self.c2c_store = {}

    def create_c2c_layer(self, cesid, c2c_cetp_transaction):
        c2cobj = CETPC2C(c2c_cetp_transaction)
        self.c2c_store[cesid] = c2cobj

    def has_c2c_layer(self, cesid):
        return cesid in self.c2c_store

    def get_c2c_layer(self, cesid):
        return self.c2c_store[cesid]

    def process_c2c_transaction(self, msg, transport):
        resp = c2c_transaction_processing_for_security()

        if resp == False: DROP packet, OR transport.send(cetp_error_response) AND transport.close()
        elif resp==True:
            if self.has_c2c_layer(cesid) == False: 
                t2t_mgr = CETPT2TManager( cesid, c2c_layer )
                transport.assign_t2t(t2t_mgr)
                c2c_layer = create_c2c_layer(cesid, c2c_cetp_transaction, t2t_mgr)    # Top layer to handling H2H
                            # Pass the completed c2c transaction as well
                transport.assign_c2c(c2c_layer)    # Assign c2c-layer for ’cesid’ to transport
                c2c_layer.create_cetp_server(cesid)
            elif self.has_c2c_layer(cesid) == True:
                c2c_obj = self.get_c2c_layer(cesid)     # Existing c2c layer for ’cesid’
                transport.assign_c2c(c2c_obj)           # Assigns existing c2c-layer for ’cesid’ to transport
                t2t_obj = self.get_t2t_layer(cesid)     # Existing t2t layer for ’cesid’
                transport.assign_t2t(t2t_obj)           # Assigns existing t2t-layer for ’cesid’ to transport
                self.append_active_c2c_transaction_id(cetp_obj.sst, cetp_obj.dst)       
                                                        # CETP response active (CSST, CDST) session tags to use for c2c communication.
        
        transport.send_cetp(resp)

class iCETPT2TManager:
    def __init(self, cesid, c2c_mgr):
        self.c2c_mgr     = c2c_mgr
        self.cesid    = cesid

    def select_transport(self):
        # some processing to select current cetp_transport, based on
        load_balancing() or best_Health(), or smalllest_rtt().
        return cetp_transport
    
    def send_cetp(self, msg):
        current_transport = self.select_transport()
        current_transport.send_cetp(msg)

    def transport_report(self, msg):
        self.transport_layer_specific_processing()        # Last seen timestamp etc.
        self.c2c.enqueue_cetp( msg )

    #Objective: 
    #1) absorb unexpected connection closure due to RST attack or due to NW.    (And how it is handled).
    #2) Make CETPC2C independent of CETPT2T                - currently it is dependent.


class iCETPTransport(asyncio.Protocol):
    def __init__(self, c2c_mgr):
        self.cesid   = None                     # Indicates if we trustworthly know the remote 'cesid' (having negotiated the c2c-policy with remote endpoint).
        self.c2c_mgr = c2c_mgr                  # c2c-Manager handles a newly connected client, until the c2c-negotiation (trust) is established.
                                                # Once trust is established, 
    
    def connection_made(self, transport):
        self.transport = transport
        peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(peername))
        
        if self.c2c_mgr.host_malicious_history(ip_addr) = True:
            self.transport.close()              # Better method of closing connection
    
    def assign_c2c(self, c2c_layer):               # Triggered by ’c2c-manager’
        self.c2c = c2c_layer                       # To load an existing c2c layer for ’cesid’
        self.cesid = True

    def assign_t2t_manager(self, t2t_mgr):         # Triggered by ’c2c-manager’
        self.t2t = t2t_mgr                         # To load an existing c2c layer for ’cesid’

    def send_cetp(self, msg):
        msg = self.message_framing(msg)
        self.send(msg)

    def message_framing(self, msg)
        #cetp_frame = some_processing(msg)
        return cetp_frame

    def data_received(self, data):
        msg = data.decode()
        print('Data received: {!r}'.format(msg))
        cetp_msg = unframe(msg)
        
        if self.cesid is not None:
            self.t2t.transport_report(msg)
        else:
            self.c2c_mgr.process_c2c_transaction(cetp_msg, self)      # Forwarding message to c2cmanager for ces-ces policy negotiation.

    def unframe(self, data)
        # After some processing on data
        return cetp_msg


"""    
# Each client connection will create a new protocol instance
coro = loop.create_server(EchoServerClientProtocol, '127.0.0.1', 8888)
server = loop.run_until_complete(coro)

try:
    loop.run_forever()
except KeyboardInterrupt:
    pass

# Close the server
server.close()
loop.run_until_complete(server.wait_closed())
"""


