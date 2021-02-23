# P4EC_hotedge20

### Code for P4EC
P4EC: Enabling Terabit Edge Computing in Enterprise 4G LTE
https://www.usenix.org/conference/hotedge20/presentation/hollingsworth

p4ec.p4 (warning file contains some calls specific to the Stordis switch)

receive_sctp.py runs on the p4 controller and monitors for any packets that are copy_to_cpu (line 542 of p4ec.p4). The packets are parsed for TEID and IP.

remote_add_entry.py also runs on the p4 controller. It adds and removes table entries for packets that should be routed to and from the edge.
