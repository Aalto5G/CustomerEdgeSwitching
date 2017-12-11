import threading
import time
import random, string, sys, traceback, thread, threading
import dns.message, socket, select, time

"""
Code heavily leveraged by sample example given by Jesus Llorente.
A python2 App for launching DNS flooding from a list of sources, to a set of destinations, via a particular DNS server.
"""

class DNSDoS:
    def __init__(self):
        # For sending flood of message from a particular source, to a set of destinations, via a particular DNS server
        self.domains = ["srv1.hostb1.cesb.lte.", "srv2.hostb1.cesb.lte."] 
        self.base_port_dns = 32000        
        self.own_addr = "10.0.3.111"
        self.load = 30.0                                # Also shows number of parallel threads
        self.test_time = 10.0
        self.dns_addr = "10.0.3.101"
        self.dns_port = 53
        self.threads = []
        self.results = []
        
        
    def start_display(self):
        print("******** Launching DNS flood... **********")
        self.start_time = time.time()
      
    def initialize(self):
        i=0
        max_iterations = self.test_time * self.load
        idle = 1/self.load
        self.start_display()
        #domains = ["hosta5.cesproto.re2ee.org", "hosta3.cesproto.re2ee.org", "hosta1.cesproto.re2ee.org"]
        
        while(i<max_iterations):
            tme = time.time()
            domain = self.domains[i%len(self.domains)]
            #domain = "raimo.aalto.lte." #"hosta"+str(i)+".cesproto.re2ee.org"
            own_addr = self.own_addr
            #own_addr = self.interface_list[i % len(self.interface_list)]
            
            i+=1
            thread_obj = threading.Thread(target=self.resolve_domain, args =(i, domain, own_addr))
            thread_obj.start()
            self.threads.append(thread_obj)
            proc_delay = time.time()-tme
            interval = idle*0.99-proc_delay
            if interval >0:
                time.sleep(interval)


    def resolve_domain(self, sequence, domain, own_addr, dnsmodel =1 ):
        try:
            #print(" Starting Thread number %d     for domain '%s' " %(sequence, domain))
            address = None
            found = False
            i=0
            query = dns.message.make_query(domain, 1)
            sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sockfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sockfd.bind((own_addr, self.base_port_dns+sequence))
            start_time = time.time()
            
            if dnsmodel == 1:
                max_attempts = 4
                timeout=30
                
            max_attempts = 1                # Limits the retransmission to zero, for maintaining/controlling exact DNS flood rate.
    
            
            while(i<max_attempts and not found):
                #print("DNS Query:   Thread# %d    iteration# %d   for   '%s'," % (sequence, i+1, domain))
                sockfd.sendto(query.to_wire(), (self.dns_addr, self.dns_port))
                rd, wr, ex = select.select([sockfd], [], [], timeout) #model dependent
                for s in rd:
                    data, addr = s.recvfrom(1024)
                    response = dns.message.from_wire(str(data))
                    answer = str(response.answer.pop()).split()
                    #print(answer)
                    if len(answer) == 5:
                        address = answer[4]
                        resolution_delay = time.time()-start_time
                        self.results.append(resolution_delay)
                        sockfd.close()
                        found = True                # Remove this if error comes ...
                        return
                        #print("Resolved DNS address:", address)
                        #print("DNS Response Success:   thread# %d     iteration# %d    for '%s' = " % (sequence, i+1, domain), address)
                        #print " ? ? ? Got %s at port %d for %d" % (address, self.base_port_dns+sequence, sequence)
                        
                i+=1
    
            sockfd.close()
            return (None, 'failure')
        except:
            return None
        
    def finalize(self):
        for iter in self.threads:
            iter.join()
        
        duration = time.time() - self.start_time
        queries_answered = len(self.results)
        expected_answers = self.load * self.test_time
        print("Summary:\nLoad: {} && Test-duration: {} ".format(self.load, self.test_time))

        print("'{}'% successfully resolved queries".format(100 * queries_answered/expected_answers))
        avrg = sum(self.results)/len(self.results)
        print(" Average resolution delay: ", 1000*avrg, " msec")
        print(" Planned test duration: ", self.test_time)
        print(" Program execution duration: ", duration)


if __name__=="__main__":
    dos_attck = DNSDoS()
    dos_attck.initialize()
    dos_attck.finalize()
    
