#! /bin/sh
killall secchan vde_switch vde_plug2tap
/home/basenox/openflow/utilities/dpctl delif nl:0 tap0
/home/basenox/openflow/utilities/dpctl deldp nl:0
rmmod openflow_mod
/etc/init.d/dhcp3-server stop
tunctl -d tap0
tunctl -d tap1
