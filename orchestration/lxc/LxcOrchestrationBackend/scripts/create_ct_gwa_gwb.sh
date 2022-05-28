#'gwa' Gateway container 
curl -X POST -H "Content-Type: application/json" -d '{"interfaces": {"mgt0":{"ip_addr":["172.31.255.11"], "iface_direction":"mgmt"}, "lan0":{"ip_addr":["192.168.0.1"], "iface_direction":"private"}, "wan0":{"ip_addr":["100.64.1.130", "100.64.1.131", "100.64.1.132", "100.64.1.133", "100.64.1.134", "100.64.1.135", "100.64.1.136", "100.64.1.137", "100.64.1.138", "100.64.1.139", "100.64.1.140", "100.64.1.141", "100.64.1.142"], "iface_direction":"public", "gateway":"100.64.1.1"} }}' http://127.0.0.1:8080/create_container/gateway/gwa

#'hosta1' private host
curl -X POST -H "Content-Type: application/json" -d '{"interfaces": {"mgt0":{"ip_addr":["172.31.255.31"], "iface_direction":"mgmt"}, "lan0":{"ip_addr":["192.168.0.101"], "gateway":"192.168.0.1", "gateway_name":"gwa", "iface_direction":"public"}} }' http://127.0.0.1:8080/create_container/private_host/hosta1

#'hosta2' private host
curl -X POST -H "Content-Type: application/json" -d '{"interfaces": {"mgt0":{"ip_addr":["172.31.255.32"], "iface_direction":"mgmt"}, "lan0":{"ip_addr":["192.168.0.101"], "gateway":"192.168.0.1", "gateway_name":"gwa", "iface_direction":"public"}} }' http://127.0.0.1:8080/create_container/private_host/hosta2

#'proxya' private host
curl -X POST -H "Content-Type: application/json" -d '{"interfaces": {"mgt0":{"ip_addr":["172.31.255.14"], "iface_direction":"mgmt"}, "wan0p":{"gateway_name":"gwa", "iface_direction":"private"}, "wan0":{"iface_direction":"public"} } }' http://127.0.0.1:8080/create_container/proxy/proxya


#'gwb' Gateway container 
curl -X POST -H "Content-Type: application/json" -d '{"interfaces": {"mgt0":{"ip_addr":["172.31.255.12"], "iface_direction":"mgmt"}, "lan0":{"ip_addr":["192.168.0.1"], "iface_direction":"private"}, "wan0":{"ip_addr":["100.64.2.130", "100.64.2.131", "100.64.2.132", "100.64.2.133", "100.64.2.134", "100.64.2.135", "100.64.2.136", "100.64.2.137", "100.64.2.138", "100.64.2.139", "100.64.2.140", "100.64.2.141", "100.64.2.142"], "iface_direction":"public", "gateway":"100.64.2.1"} }}' http://127.0.0.1:8080/create_container/gateway/gwb

#'hostb1' private host
curl -X POST -H "Content-Type: application/json" -d '{"interfaces": {"mgt0":{"ip_addr":["172.31.255.41"], "iface_direction":"mgmt"}, "lan0":{"ip_addr":["192.168.0.101"], "gateway":"192.168.0.1", "gateway_name":"gwa", "iface_direction":"public"}} }' http://127.0.0.1:8080/create_container/private_host/hostb1

#'hostb2' private host
curl -X POST -H "Content-Type: application/json" -d '{"interfaces": {"mgt0":{"ip_addr":["172.31.255.42"], "iface_direction":"mgmt"}, "lan0":{"ip_addr":["192.168.0.102"], "gateway":"192.168.0.1", "gateway_name":"gwa", "iface_direction":"public"}} }' http://127.0.0.1:8080/create_container/private_host/hostb2

#'proxyb' container
curl -X POST -H "Content-Type: application/json" -d '{"interfaces": {"mgt0":{"ip_addr":["172.31.255.15"], "iface_direction":"mgmt"}, "wan0p":{"gateway_name":"gwa", "iface_direction":"private"}, "wan0":{"iface_direction":"public"} } }' http://127.0.0.1:8080/create_container/proxy/proxyb

# router container
curl -X POST -H "Content-Type: application/json" -d '{"interfaces": {"mgt0":{"ip_addr":["172.31.255.10"], "iface_direction":"mgmt"}, "wan0":{"ip_addr":["100.64.0.1"], "iface_direction":"public"}, "wan1":{"next_container":"proxya", "iface_direction":"private", "ip_addr":["100.64.1.1"]}, "wan2":{"iface_direction":"private", "next_container":"proxyb", "ip_addr":["100.64.2.1"]} }}' http://127.0.0.1:8080/create_container/router/router
