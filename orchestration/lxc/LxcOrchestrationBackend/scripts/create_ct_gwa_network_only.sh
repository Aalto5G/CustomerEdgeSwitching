#'gwa' Gateway container 
curl -X POST -H "Content-Type: application/json" -d '{"interfaces": {"mgt0":{"ip_addr":["172.31.255.11"], "iface_direction":"mgmt"}, "lan0":{"ip_addr":["192.168.0.1"], "iface_direction":"private"}, "wan0":{"ip_addr":["100.64.1.130", "100.64.1.131", "100.64.1.132", "100.64.1.133", "100.64.1.134", "100.64.1.135", "100.64.1.136", "100.64.1.137", "100.64.1.138", "100.64.1.139", "100.64.1.140", "100.64.1.141", "100.64.1.142"], "iface_direction":"public", "gateway":"100.64.1.1"} }}' http://127.0.0.1:8080/create_container/gateway/gwa

#'hosta1' private host
curl -X POST -H "Content-Type: application/json" -d '{"interfaces": {"mgt0":{"ip_addr":["172.31.255.31"], "iface_direction":"mgmt"}, "lan0":{"ip_addr":["192.168.0.101"], "gateway":"192.168.0.1", "gateway_name":"gwa", "iface_direction":"public"}} }' http://127.0.0.1:8080/create_container/private_host/hosta1

#'hosta2' private host
curl -X POST -H "Content-Type: application/json" -d '{"interfaces": {"mgt0":{"ip_addr":["172.31.255.32"], "iface_direction":"mgmt"}, "lan0":{"ip_addr":["192.168.0.101"], "gateway":"192.168.0.1", "gateway_name":"gwa", "iface_direction":"public"}} }' http://127.0.0.1:8080/create_container/private_host/hosta2

#'proxya' private host
curl -X POST -H "Content-Type: application/json" -d '{"interfaces": {"mgt0":{"ip_addr":["172.31.255.14"], "iface_direction":"mgmt"}, "wan0p":{"gateway_name":"gwa", "iface_direction":"private"}, "wan0":{"iface_direction":"public"} } }' http://127.0.0.1:8080/create_container/proxy/proxya

# router container
curl -X POST -H "Content-Type: application/json" -d '{"interfaces": {"mgt0":{"ip_addr":["172.31.255.10"], "iface_direction":"mgmt"}, "wan0":{"ip_addr":["100.64.0.1"], "iface_direction":"public"}, "wan1":{"next_container":"proxya", "iface_direction":"private", "ip_addr":["100.64.1.1"]}, "wan2":{"iface_direction":"private", "next_container":"proxyb", "ip_addr":["100.64.2.1"]} }}' http://127.0.0.1:8080/create_container/router/router
