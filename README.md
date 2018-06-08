DPDK example in C++
===================

This is a simple reference example for packet RX/TX with flow director. It uses
one client machine and one server machine, which may each run multiple threads.
Packets are steered to a server thread based on the UDP port of received packets.

ixgbe and i40e based NICs are supported.
