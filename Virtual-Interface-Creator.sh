for i in {11..99};
do
	sudo ip link add eth$i type dummy
	sudo ifconfig eth10 hw ether 00:0c:29:13:a8:$i
	sudo ip addr add 192.168.1.1$i/24 brd + dev eth$i label eth$i:0
	#sudo ip link delete ethrange$i type dummy
done
sudo ip addr del 192.168.100.140/24 brd + dev eth40 label eth40:0
sudo ip link delete eth40 type dummy
