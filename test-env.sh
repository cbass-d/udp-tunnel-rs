# Create bridge
ip link add br0 type bridge
ip addr add 192.168.100.1/24 dev br0
ip link set br0 up

# Namespaces
ip netns add clientA
ip netns add clientB

# Create veth pairs
ip link add vethA type veth peer name vethA-br
ip link set vethA netns clientA
ip link set vethA-br master br0
ip link set vethA-br up

ip link add vethB type veth peer name vethB-br
ip link set vethB netns clientB
ip link set vethB-br master br0
ip link set vethB-br up

# Config addresses
ip netns exec clientA ip addr add 192.168.100.2/24 dev vethA
ip netns exec clientA ip link set vethA up
ip netns exec clientA ip route add default via 192.168.100.1
ip netns exec clientA ip link set lo up

ip netns exec clientB ip addr add 192.168.100.3/24 dev vethB
ip netns exec clientB ip link set vethB up
ip netns exec clientB ip route add default via 192.168.100.1
ip netns exec clientB ip link set lo up
