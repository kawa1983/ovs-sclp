Using VXLAN over SCLP tunneling
===============================

SCLP (Segment-oriented Connection-less Protocol) is a novel L4 protocol 
for accelerating performance of existing tunneling protocols, such as 
VXLAN and NVGRE. The SCLP protocol is designed to take advantage of 
a GSO (Generic Segmentation Offload) and a GRO (Generic Receive Offload) 
features of the Linux kernel.


=
### Install

### 1. Install an SCLP RPM package

How to install the package is described the following link

    https://github.com/sdnnit/sclp


=
### 2. Building Open vSwitch packages

```sh
$ mv ovs-sclp openvswitch-2.4.0

$ tar cvzf openvswitch-2.4.0.tar.gz openvswitch-2.4.0

$ mv openvswitch-2.4.0.tar.gz ~/rpmbuild/SOURCES

$ cd openvswitch-2.4.0

$ cp rhel/openvswitch-kmod.files ~/rpmbuild/SOURCES

$ rpmbuild -bb rhel/openvswitch.spec

$ rpmbuild -bb rhel/openvswitch-kmod-rhel6.spec  # The sclp RPM package must be installed in advance

$ cd ~/rpmbuild/RPMS/x86_64

$ sudo rpm -ivh kmod-openvswitch-2.4.0-1.el6.x86_64.rpm 

$ sudo rpm -ivh openvswitch-2.4.0-1.x86_64.rpm

$ sudo service openvswitch start 
```

If the installation process succeeds, an openvswitch module is loaded into the kernel.


=
### 3. Setup VXLAN over SCLP tunneling


```sh
$ sudo ovs-vsctl add-br br0

$ sudo ovs-vsctl add-port br0 vxlan0 -- set Interface vxlan0 type=vxlan-sclp options:remote_ip=x.x.x.x   
  # vport_vxlan-sclp and sclp modules will be loaded

$ sudo ovs-vsctl add-port br0 vnet0

$ sudo ovs-dpctl show  # sclp_sys_4789 (vxlan-sclp) 
```
