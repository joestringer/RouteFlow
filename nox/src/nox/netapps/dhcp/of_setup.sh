#! /bin/sh
tunctl -u root
tunctl -u root
/sbin/ifconfig tap0 172.27.75.70 netmask 255.255.254.0 up
/etc/init.d/dhcp3-server start
vde_switch -daemon -hub -sock /tmp/tapsock -tap tap0,tap1
vde_plug2tap --daemon --sock=/tmp/tapsock tap0
vde_plug2tap --daemon --sock=/tmp/tapsock tap1
insmod /home/basenox/openflow/datapath/linux-2.6/openflow_mod.ko
/home/basenox/openflow/utilities/dpctl adddp nl:0
/home/basenox/openflow/utilities/dpctl addif nl:0 tap1
/home/basenox/openflow/utilities/dpctl show nl:0
/sbin/ifconfig of0 hw ether 00:aa:aa:aa:aa:aa
/home/basenox/openflow/secchan/secchan nl:0 tcp:localhost:6650
