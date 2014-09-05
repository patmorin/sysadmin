#!/bin/sh

#  IPTABLES  FIREWALL  script for the Linux 2.4 kernel.
#  This script is a derivitive of the script presented in
#  the IP Masquerade HOWTO page at:
#  www.tldp.org/HOWTO/IP-Masquerade-HOWTO/stronger-firewall-examples.html
#  It was simplified to coincide with the configuration of
#  the sample system presented in the Guides section of
#  www.aboutdebian.com
#
#  This script is presented as an example for testing ONLY
#  and should not be used on a production firewall server.
#
#    PLEASE SET THE USER VARIABLES
#    IN SECTIONS A AND B OR C

echo "\n\nSETTING UP IPTABLES FIREWALL..."


# === SECTION A
# -----------   FOR EVERYONE 

# SET THE INTERFACE DESIGNATION AND ADDRESS AND NETWORK ADDRESS
# FOR THE NIC CONNECTED TO YOUR _INTERNAL_ NETWORK
#   The default value below is for "eth0".  This value 
#   could also be "eth1" if you have TWO NICs in your system.
#   You can use the ifconfig command to list the interfaces
#   on your system.  The internal interface will likely have
#   have an address that is in one of the private IP address
#   ranges.
#       Note that this is an interface DESIGNATION - not
#       the IP address of the interface.

# Enter the designation for the Internal Interface's
INTIF="eth0"

# Enter the NETWORK address the Internal Interface is on
INTNET="192.168.123.0/24"

# Enter the IP address of the Internal Interface
INTIP="192.168.123.254"


# SET THE INTERFACE DESIGNATION FOR YOUR "EXTERNAL" (INTERNET) CONNECTION
#   The default value below is "ppp0" which is appropriate 
#   for a MODEM connection.
#   If you have two NICs in your system change this value
#   to "eth0" or "eth1" (whichever is opposite of the value
#   set for INTIF above).  This would be the NIC connected
#   to your cable or DSL modem (WITHOUT a cable/DSL router).
#       Note that this is an interface DESIGNATION - not
#       the IP address of the interface.
#   Enter the external interface's designation for the
#   EXTIF variable:

# name of external interface
EXTIF="eth1"

# ip address of external interface
EXTIP="134.117.27.24"
EXTIP2="134.117.27.56"

# --------  No more variable setting beyond this point  --------


echo "Loading required stateful/NAT kernel modules..."

/sbin/depmod -a
/sbin/modprobe ip_tables
/sbin/modprobe ip_conntrack
/sbin/modprobe ip_conntrack_ftp
/sbin/modprobe ip_conntrack_irc
/sbin/modprobe iptable_nat
/sbin/modprobe ip_nat_ftp
/sbin/modprobe ip_nat_irc

echo "    Enabling IP forwarding..."
echo "1" > /proc/sys/net/ipv4/ip_forward
# echo "1" > /proc/sys/net/ipv4/ip_dynaddr


echo "    Setting higher conntrack limits..."
echo 4194304 > /proc/sys/net/ipv4/netfilter/ip_conntrack_max
echo 1048576 > /sys/module/nf_conntrack/parameters/hashsize

echo "    Enabling tcp_be_liberal hack..."
echo 1 > /proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_be_liberal

echo "    External interface: $EXTIF"
echo "       External interface IP address is: $EXTIP"
echo "    Loading firewall server rules..."

UNIVERSE="0.0.0.0/0"

# Clear any existing rules and setting default policy to DROP
iptables -P INPUT DROP
iptables -F INPUT 
iptables -P OUTPUT DROP
iptables -F OUTPUT 
iptables -P FORWARD DROP
iptables -F FORWARD 
iptables -t nat -F PREROUTING
iptables -t nat -F POSTROUTING
iptables -t nat -F OUTPUT

# Delete all User-specified chains
iptables -X
iptables -t nat -X

# Reset all IPTABLES counters
iptables -Z
iptables -t nat -Z

echo "     - Loading INPUT rulesets"

#######################################################################
# INPUT: Incoming traffic from various interfaces.  All rulesets are 
#        already flushed and set to a default policy of DROP. 
#

#######################################################################
# INPUT: Incoming traffic from various interfaces.  All rulesets are 
#        already flushed and set to a default policy of DROP. 
#

# loopback interfaces are valid.
iptables -A INPUT -i lo -s $UNIVERSE -d $UNIVERSE -j ACCEPT

# local interface, local machines, going anywhere is valid
iptables -A INPUT -i $INTIF -s $INTNET -d $UNIVERSE -j ACCEPT

# remote interface, claiming to be local machines, IP spoofing, get lost
iptables -A INPUT -i $EXTIF -s $INTNET -d $UNIVERSE -j DROP

# remote interface, any source, going to external ip address is valid
iptables -A INPUT -i $EXTIF -s $UNIVERSE -d $EXTIP -j ACCEPT

# Allow any related traffic coming back to the MASQ server in
iptables -A INPUT -i $EXTIF -s $UNIVERSE -d $EXTIP -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i $EXTIF -s $UNIVERSE -d $EXTIP2 -m state --state ESTABLISHED,RELATED -j ACCEPT

# Catch all rule, all other incoming is denied and logged. 
iptables -A INPUT -s $UNIVERSE -d $UNIVERSE -j DROP

echo "     - Loading OUTPUT rulesets"

#######################################################################
# OUTPUT: Outgoing traffic from various interfaces.  All rulesets are 
#         already flushed and set to a default policy of DROP. 
#

# loopback interface is valid.
iptables -A OUTPUT -o lo -s $UNIVERSE -d $UNIVERSE -j ACCEPT

# any source going to local net on local interface is valid
iptables -A OUTPUT -o $INTIF -s $EXTIP -d $INTNET -j ACCEPT
iptables -A OUTPUT -o $INTIF -s $INTIP -d $INTNET -j ACCEPT

# outgoing to local net on remote interface, broken routing, deny
iptables -A OUTPUT -o $EXTIF -s $UNIVERSE -d $INTNET -j DROP

# anything else outgoing on remote interface is valid
iptables -A OUTPUT -o $EXTIF -s $EXTIP -d $UNIVERSE -j ACCEPT
iptables -A OUTPUT -o $EXTIF -s $EXTIP2 -d $UNIVERSE -j ACCEPT

# Catch all rule, all other outgoing is denied and logged.
#iptables -A OUTPUT -s $UNIVERSE -d $UNIVERSE -j DROP  (already the default for the chain)

echo "     - Loading FORWARD rulesets"

#######################################################################
# FORWARD: Enable Forwarding and thus IPMASQ

# Forcefully drop invalid packets, these were leaking into the internet without getting SNATed
# (known bug http://www.smythies.com/~doug/network/iptables_notes/index.html  http://bugzilla.netfilter.org/show_bug.cgi?id=693)
iptables -A FORWARD -i $INTIF -p tcp -m state --state INVALID -j DROP

# Accept any already-established connections
iptables -A FORWARD -i $EXTIF -o $INTIF -m state --state ESTABLISHED,RELATED -j ACCEPT

# Block port 25 outgoing except from euclid
iptables -A FORWARD -s 192.168.123.10/32 -p udp --dport 25 -j ACCEPT 
iptables -A FORWARD -s 192.168.123.10/32 -p tcp --dport 25 -j ACCEPT 
iptables -A FORWARD -s 192.168.123.0/24 -p udp --dport 25 -j REJECT
iptables -A FORWARD -s 192.168.123.0/24 -p tcp --dport 25 -j REJECT

# Forward anything from the internal interface to the external interface
iptables -A FORWARD -i $INTIF -s $INTNET -o $EXTIF \! -d $INTNET -j ACCEPT

# Forward anything from the internal interface to the internal interface
iptables -A FORWARD -i $INTIF -s $INTNET -o $INTIF -d $INTNET -j ACCEPT

#############################################################
# Forward applications from anywhere to our internal servers
#############################################################
# SMTP forwarding
iptables -t nat -A PREROUTING -d 134.117.27.24/32 -p tcp --dport 25 -j DNAT --to-destination 192.168.123.10
iptables -t nat -A PREROUTING -d 134.117.27.24/32 -p udp --dport 25 -j DNAT --to-destination 192.168.123.10
iptables -A FORWARD -d 192.168.123.10/32 -p udp --dport 25 -m state --state NEW -j ACCEPT 
iptables -A FORWARD -d 192.168.123.10/32 -p tcp --dport 25 -m state --state NEW -j ACCEPT 

# NTP forwarding
iptables -t nat -A PREROUTING -d 134.117.27.24/32 -p tcp --dport 123 -j DNAT --to-destination 192.168.123.10
iptables -t nat -A PREROUTING -d 134.117.27.24/32 -p udp --dport 123 -j DNAT --to-destination 192.168.123.10
iptables -A FORWARD -d 192.168.123.10/32 -p udp --dport 123 -m state --state NEW -j ACCEPT 
iptables -A FORWARD -d 192.168.123.10/32 -p tcp --dport 123 -m state --state NEW -j ACCEPT 

# ssh forwarding (to 192.168.123.30 [coxeter])
iptables -t nat -A PREROUTING -d 134.117.27.24/32 -p tcp --dport 22 -j DNAT --to-destination 192.168.123.38
iptables -t nat -A PREROUTING -d 134.117.27.24/32 -p udp --dport 22 -j DNAT --to-destination 192.168.123.38
iptables -A FORWARD -d 192.168.123.38/32 -p tcp --dport 22 -m state --state NEW -j ACCEPT 
iptables -A FORWARD -d 192.168.123.38/32 -p udp --dport 22 -m state --state NEW -j ACCEPT 

## ssh forwarding (to 192.168.123.78 [miniscule])
#iptables -t nat -A PREROUTING -d 134.117.27.24/32 -p tcp -m tcp --dport 8888 -j DNAT --to-destination 192.168.123.78:22
#iptables -t nat -A PREROUTING -d 134.117.27.24/32 -p udp -m udp --dport 8888 -j DNAT --to-destination 192.168.123.78:22
#iptables -A FORWARD -d 192.168.123.78/32 -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT 
#iptables -A FORWARD -d 192.168.123.78/32 -p udp -m state --state NEW -m udp --dport 22 -j ACCEPT 
#
## ssh forwarding (to localhost [gateway])
#iptables -t nat -A PREROUTING -d 134.117.27.24/32 -p tcp -m tcp --dport 9999 -j DNAT --to-destination 192.168.123.254:22
#iptables -t nat -A PREROUTING -d 134.117.27.24/32 -p udp -m udp --dport 9999 -j DNAT --to-destination 192.168.123.254:22
#iptables -A FORWARD -d 192.168.123.254/32 -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT 
#iptables -A FORWARD -d 192.168.123.254/32 -p udp -m state --state NEW -m udp --dport 22 -j ACCEPT 
#

# imaps (SSL) forwarding
iptables -t nat -A PREROUTING -d 134.117.27.24/32 -p tcp --dport 993 -j DNAT --to-destination 192.168.123.10
iptables -t nat -A PREROUTING -d 134.117.27.24/32 -p udp --dport 993 -j DNAT --to-destination 192.168.123.10
iptables -A FORWARD -d 192.168.123.10/32 -p udp --dport 993 -m state --state NEW -j ACCEPT 
iptables -A FORWARD -d 192.168.123.10/32 -p tcp --dport 993 -m state --state NEW -j ACCEPT 

# git-daemon forwarding
iptables -t nat -A PREROUTING -d 134.117.27.24/32 -p tcp --dport 9418 -j DNAT --to-destination 192.168.123.10
iptables -A FORWARD -d 192.168.123.10/32 -p tcp --dport 9418 -m state --state NEW -j ACCEPT 

# HTTP forwarding
iptables -t nat -A PREROUTING -d 134.117.27.24/32 -p tcp --dport 80 -j DNAT --to-destination 192.168.123.10
iptables -t nat -A PREROUTING -d 134.117.27.24/32 -p udp --dport 80 -j DNAT --to-destination 192.168.123.10
iptables -A FORWARD -d 192.168.123.10/32 -p udp --dport 80 -m state --state NEW -j ACCEPT 
iptables -A FORWARD -d 192.168.123.10/32 -p tcp --dport 80 -m state --state NEW -j ACCEPT 

# HTTP:82 forwarding (to ssh box 192.168.123.76 [laplace])
iptables -t nat -A PREROUTING -d 134.117.27.24/32 -p tcp --dport 82 -j DNAT --to-destination 192.168.123.76
iptables -t nat -A PREROUTING -d 134.117.27.24/32 -p udp --dport 82 -j DNAT --to-destination 192.168.123.76
iptables -A FORWARD -d 192.168.123.76/32 -p udp --dport 82 -m state --state NEW -j ACCEPT 
iptables -A FORWARD -d 192.168.123.76/32 -p tcp --dport 82 -m state --state NEW -j ACCEPT 

# HTTP:9091 forwarding (to 192.168.123.12 [mirzakhani])
iptables -t nat -A PREROUTING -d 134.117.27.24/32 -p tcp --dport 9091 -j DNAT --to-destination 192.168.123.40:80
iptables -t nat -A PREROUTING -d 134.117.27.24/32 -p udp --dport 9091 -j DNAT --to-destination 192.168.123.40:80
iptables -A FORWARD -d 192.168.123.40/32 -p udp --dport 80 -m state --state NEW -j ACCEPT 
iptables -A FORWARD -d 192.168.123.40/32 -p tcp --dport 80 -m state --state NEW -j ACCEPT 


# HTTPS forwarding
iptables -t nat -A PREROUTING -d 134.117.27.24/32 -p tcp --dport 443 -j DNAT --to-destination 192.168.123.10
iptables -t nat -A PREROUTING -d 134.117.27.24/32 -p udp --dport 443 -j DNAT --to-destination 192.168.123.10
iptables -A FORWARD -d 192.168.123.10/32 -p udp --dport 443 -m state --state NEW -j ACCEPT 
iptables -A FORWARD -d 192.168.123.10/32 -p tcp --dport 443 -m state --state NEW -j ACCEPT 

# Squid (http proxy) forwarding
#iptables -t nat -A PREROUTING -d 134.117.27.24/32 -p tcp --dport 3128 -j DNAT --to-destination 192.168.123.10
#iptables -t nat -A PREROUTING -d 134.117.27.24/32 -p udp --dport 3128 -j DNAT --to-destination 192.168.123.10
#iptables -A FORWARD -d 192.168.123.10/32 -p udp --dport 3128 -m state --state NEW -j ACCEPT 
#iptables -A FORWARD -d 192.168.123.10/32 -p tcp --dport 3128 -m state --state NEW -j ACCEPT 

# Enable SNAT (MASQUERADE) functionality to outside of $INTNET
iptables -t nat -A POSTROUTING -s 192.168.123.255/24 ! -d $INTNET -j SNAT --to $EXTIP

#iptables -t nat -A POSTROUTING -s 192.168.123.20/32 ! -d $INTNET -j SNAT --to 134.117.27.57
#iptables -t nat -A POSTROUTING -s 192.168.123.21/32 ! -d $INTNET -j SNAT --to 134.117.27.57
#iptables -t nat -A POSTROUTING -s 192.168.123.22/32 ! -d $INTNET -j SNAT --to 134.117.27.57
#iptables -t nat -A POSTROUTING -s 192.168.123.24/32 ! -d $INTNET -j SNAT --to 134.117.27.57
#iptables -t nat -A POSTROUTING -s 192.168.123.29/32 ! -d $INTNET -j SNAT --to 134.117.27.57
#iptables -t nat -A POSTROUTING -s 192.168.123.30/32 ! -d $INTNET -j SNAT --to 134.117.27.57
#iptables -t nat -A POSTROUTING -s 192.168.123.78/32 ! -d $INTNET -j SNAT --to 134.117.27.57
#
#iptables -t nat -A POSTROUTING -s 192.168.123.32/32 ! -d $INTNET -j SNAT --to 134.117.27.66
#iptables -t nat -A POSTROUTING -s 192.168.123.38/32 ! -d $INTNET -j SNAT --to 134.117.27.66
#iptables -t nat -A POSTROUTING -s 192.168.123.41/32 ! -d $INTNET -j SNAT --to 134.117.27.66
#iptables -t nat -A POSTROUTING -s 192.168.123.62/32 ! -d $INTNET -j SNAT --to 134.117.27.66
#iptables -t nat -A POSTROUTING -s 192.168.123.64/32 ! -d $INTNET -j SNAT --to 134.117.27.66
#
#
#iptables -t nat -A POSTROUTING -s 192.168.123.65/32 ! -d $INTNET -j SNAT --to 134.117.27.66
#iptables -t nat -A POSTROUTING -s 192.168.123.66/32 ! -d $INTNET -j SNAT --to 134.117.27.66
#iptables -t nat -A POSTROUTING -s 192.168.123.67/32 ! -d $INTNET -j SNAT --to 134.117.27.66
#iptables -t nat -A POSTROUTING -s 192.168.123.69/32 ! -d $INTNET -j SNAT --to 134.117.27.66
#iptables -t nat -A POSTROUTING -s 192.168.123.71/32 ! -d $INTNET -j SNAT --to 134.117.27.66
#iptables -t nat -A POSTROUTING -s 192.168.123.73/32 ! -d $INTNET -j SNAT --to 134.117.27.66
#iptables -t nat -A POSTROUTING -s 192.168.123.75/32 ! -d $INTNET -j SNAT --to 134.117.27.66
#
#iptables -t nat -A POSTROUTING -s 192.168.123.76/32 ! -d $INTNET -j SNAT --to 134.117.27.67
#
#iptables -t nat -A POSTROUTING -s $INTNET ! -d $INTNET -j SNAT --to 134.117.27.56

# Enable SNAT (MASQUERADE) functionality on $INTNET
iptables -t nat -A POSTROUTING -s $INTNET -d $INTNET -j SNAT --to $INTIP

echo "    Firewall server rule loading complete\n\n"

