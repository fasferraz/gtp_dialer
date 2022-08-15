# GTPv1/GTPv2  Dialer
This application is a GTP dialer to create sessions towards a SGW, PGW or GGSN.
It can act as SGSN (gn/gp or S4), MME (S11), SGW (S5/S8), ePDG (S2b) or TWAG (S2a).
The application implements not only the control plane, but also the user plane, so it's really useful to perform user plane tests for any APN, under specific conditions (IMSI, MSISDN, APN, IMEI, ULI, RAT, Charging Characteristics, Fixed IP APNs, DHCP, PDP Type, Authentication, etc...)

After the PDP/PDN session is established, a tunnel is created with the IP(s) received from the GGSN/PGW.
A default route is created pointing to the tunnel interface, so that applications can use the PDN/PDP established.

There is an option to use Namespaces.
PDP/PDN types ipv4, ipv6 and ipv4v6 are supported.

The application has the following options:

```
root@ubuntu:/home/fabricio/Documents# python3 gtp_dialer.py -h
Usage: gtp_dialer.py [options]

Options:
  -h, --help            show this help message and exit
  -t TUNNEL_TYPE, --tunnel_type=TUNNEL_TYPE
                        tunnel Type: GTP (Default), GTPv2
  -d TUNNEL_DST_IP, --tunnel_dst_ip=TUNNEL_DST_IP
                        tunnel IP GTP endpoint
  -i DEV_ID, --dev_id=DEV_ID
                        tun/tap device index
  -a APN_NAME, --apn_name=APN_NAME
                        APN name
  -I IMSI, --imsi=IMSI  IMSI
  -M MSISDN, --msisdn=MSISDN
                        MSISDN
  -p PDPTYPE, --pdptype=PDPTYPE
                        PDP type (ipv4, ipv6 or ipv4v6)
  -s GTP_ADDRESS, --gtp_source_address=GTP_ADDRESS
                        GTP source address (for GTP-C and GTP-U)
  -S IP_SOURCE_ADDRESS, --ip_source_address=IP_SOURCE_ADDRESS
                        IP source address. If not specified, the bind is done
                        for all IPs
  -g GATEWAY_IP_ADDRESS, --gateway_ip_address=GATEWAY_IP_ADDRESS
                        gateway IP address
  -n NODETYPE, --nodetype=NODETYPE
                        Node type (SGSN, MME, SGW, EPDG or TWAN)
  -E IMEI, --imei=IMEI  IMEI
  -f FIXED_IPV4, --fixed_ipv4=FIXED_IPV4
                        Static IPv4 for session
  -F FIXED_IPV6, --fixed_ipv6=FIXED_IPV6
                        Static IPv6 for session
  -U USERNAME, --username=USERNAME
                        username (for gtp proxy access)
  -P PASSWORD, --password=PASSWORD
                        password (for gtp proxy access)
  -G GGSN, --ggsn=GGSN  ggsn/pgw ip address (for gtp proxy access or when set
                        to SGSN/MME node in GTPv2)
  -H PASSWORD_TO_HASH, --hash=PASSWORD_TO_HASH
                        password hash calculation (for gtp proxy access)
  -v, --version         version
  -u USERNAME_PCO, --username_pco=USERNAME_PCO
                        username (for APN)
  -w PASSWORD_PCO, --password_pco=PASSWORD_PCO
                        password (for APN)
  -A AUTHENTICATION_TYPE, --authentication_type=AUTHENTICATION_TYPE
                        authentication type: PAP (default), CHAP
  -T TIMEOUT, --timeout=TIMEOUT
                        timeout for session establishment
  -D, --dhcp            Deferred IP allocation using DHCP (ipv4)
  -C CC, --cc=CC        Charging Characteristics
  -O OPERATOR, --operator=OPERATOR
                        Operator MCCMNC for ULI
  -R RAT, --rat=RAT     Radio Access Type
  -Q, --quit            Quit immediately after activating session
  -N NETNS, --netns=NETNS
                        Name of network namespace for tun device
root@ubuntu:/home/fabricio/Documents# 
```

Example of using the application as SGW:

```
root@ubuntu:/home/fabricio/Documents# python3 gtp_dialer.py -d 172.16.168.5 -s 172.16.168.130 -a gtptester -n SGW -t GTPv2 -g 172.16.168.5

   _____ _______ _____    _____  _       _           
  / ____|__   __|  __ \  |  __ \(_)     | |          
 | |  __   | |  | |__) | | |  | |_  __ _| | ___ _ __ 
 | | |_ |  | |  |  ___/  | |  | | |/ _` | |/ _ \ '__|
 | |__| |  | |  | |      | |__| | | (_| | |  __/ |   
  \_____|  |_|  |_|      |_____/|_|\__,_|_|\___|_|   by fasferraz@gmail (2012-2022)

 1. Adding route to GGSN IP Address pointing to the current default gateway
 2. Creating GTP-C Socket
 3. Sending Create Session Request to SGW/PGW
 4. Answer received and GTPv2 decoded.
    => PGW GTP-U IP Adresss: 172.16.168.5
    => PGW GTP-C IP Adresss: 172.16.168.5
    => End-User IPv4 Adresss: 192.168.255.2
    => TEID Data Remote: 2147491841
    => TEID Control Remote: 2147491841
    => DNS Addresses Ipv4: ['8.8.8.8', '8.8.4.4']
    => DNS Addresses IPv6: None
 5. Creating GTP-U Socket
 6. Creating Tunnel Interface
 7. DNS: Backing up current /etc/resolv.conf. Creating a new one:
    => Adding DNS IPv4 8.8.8.8
    => Adding DNS IPv4 8.8.4.4
 8. Configuring End User Address in the Tunnel interface
cmd: ip addr add 192.168.255.2/32 dev tun10
 9.1 Adding default routes (0.0.0.0/1 and 128.0.0.0/1) pointing to the tunnel interface (to prevail over any current default route (0.0.0.0/0) already existing in the system)
cmd: route add -net 0.0.0.0/1 gw 192.168.255.2
cmd: route add -net 128.0.0.0/1 gw 192.168.255.2
10. Starting threads: GTP-U encapsulation and GTP-U decapsulation.

Press q to quit

```

Example of using the application as MME (-G options is needed to set the PGW/GGSN IP Address):

```
root@ubuntu:/home/fabricio/Documents# python3 gtp_dialer.py -d 172.16.168.3 -s 172.16.168.130 -a gtptester -n MME -t GTPv2 -g 172.16.168.3 -G 172.16.168.5

   _____ _______ _____    _____  _       _           
  / ____|__   __|  __ \  |  __ \(_)     | |          
 | |  __   | |  | |__) | | |  | |_  __ _| | ___ _ __ 
 | | |_ |  | |  |  ___/  | |  | | |/ _` | |/ _ \ '__|
 | |__| |  | |  | |      | |__| | | (_| | |  __/ |   
  \_____|  |_|  |_|      |_____/|_|\__,_|_|\___|_|   by fasferraz@gmail (2012-2022)

 1. Adding route to GGSN IP Address pointing to the current default gateway
 2. Creating GTP-C Socket
 3. Sending Create Session Request to SGW/PGW
 4. Answer received and GTPv2 decoded.
    => SGW GTP-U IP Adresss: 172.16.168.3
    => SGW GTP-C IP Adresss: 172.16.168.3
    => End-User IPv4 Adresss: 192.168.255.3
    => TEID Data Remote: 2147500033
    => TEID Control Remote: 2147500033
    => DNS Addresses Ipv4: ['8.8.8.8', '8.8.4.4']
    => DNS Addresses IPv6: None
 4.1. Sending Modify Bearer Request to SGW
 5. Creating GTP-U Socket
 6. Creating Tunnel Interface
 7. DNS: Backing up current /etc/resolv.conf. Creating a new one:
    => Adding DNS IPv4 8.8.8.8
    => Adding DNS IPv4 8.8.4.4
 8. Configuring End User Address in the Tunnel interface
cmd: ip addr add 192.168.255.3/32 dev tun10
 9.1 Adding default routes (0.0.0.0/1 and 128.0.0.0/1) pointing to the tunnel interface (to prevail over any current default route (0.0.0.0/0) already existing in the system)
cmd: route add -net 0.0.0.0/1 gw 192.168.255.3
cmd: route add -net 128.0.0.0/1 gw 192.168.255.3
10. Starting threads: GTP-U encapsulation and GTP-U decapsulation.

Press q to quit
```

# Notes:
- if you are running the application in a VM, the -s option (the GTP address present at GTP level) must match the output IP address that will reach the SGW/PGW/GGSN.
- Use option -S to choose which IP source address to use when there are multiple interfaces in the OS.
- Use option -g to set the gateway statically when there are multiple interfaces, and the SGW/PGW/GGSN is not reachable via the current default route, but through a different interface. This IP address will be used as the gateway for GTP-c and GTP-u traffic.
