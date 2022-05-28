#'gwa' Gateway container 
curl -X POST -H "Content-Type: application/json" -d '{"interfaces": {"mgt0":{"ip_addr":["172.31.255.11"], "iface_direction":"mgmt"}, "lan0":{"ip_addr":["192.168.0.1"], "iface_direction":"private"}, "wan0":{"ip_addr":["100.64.1.130", "100.64.1.131", "100.64.1.132"], "iface_direction":"public", "gateway":"100.64.1.1"} }}' http://127.0.0.1:8080/create_container/gateway/gwa

#'hosta1' private host
curl -X POST -H "Content-Type: application/json" -d '{"interfaces": {"mgt0":{"ip_addr":["172.31.255.31"], "iface_direction":"mgmt"}, "lan0":{"ip_addr":["192.168.0.101"], "gateway":"192.168.0.1", "gateway_name":"gwa", "iface_direction":"public"}} }' http://127.0.0.1:8080/create_container/private_host/hosta1

#'hosta2' private host
curl -X POST -H "Content-Type: application/json" -d '{"interfaces": {"mgt0":{"ip_addr":["172.31.255.32"], "iface_direction":"mgmt"}, "lan0":{"ip_addr":["192.168.0.101"], "gateway":"192.168.0.1", "gateway_name":"gwa", "iface_direction":"public"}} }' http://127.0.0.1:8080/create_container/private_host/hosta2

#'proxya' private host
curl -X POST -H "Content-Type: application/json" -d '{"interfaces": {"mgt0":{"ip_addr":["172.31.255.14"], "iface_direction":"mgmt"}, "lan0":{"gateway_name":"gwa", "iface_direction":"private"}, "wan0":{"iface_direction":"public"} } }' http://127.0.0.1:8080/create_container/proxy/proxya

