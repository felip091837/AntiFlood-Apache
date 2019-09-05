#!/bin/bash

if [ $# -eq 0 ]; then
echo -e  "+================================================================+
|            AntiFlood Apache by felipesi - 2017              |
|----------------------------------------------------------------|
|                                                                |
|    USE: nohup $0 MAX_REQ TIME_ACCESS > /dev/null 2>&1&  |
|   STOP: $0 stop                                         |
|   DROP: $0 drop IP                                      |
| UNDROP: $0 undrop IP                                    |
|  ALLOW: $0 allow IP PORT                                |
|								 |
|----------------------------------------------------------------|
| LOGS APACHE AVAILABLE ON: /var/www/html/req.php                |
| DROPPED IP's AVAILABLE ON: /var/www/html/drop.txt              |
+================================================================+"

elif [ "$1" == "stop" ]; then
	iptables -F
	arq=(/var/log/apache2/.tmp.log /root/.IPS_drop.txt /root/.cron.sh /root/.IPS_drop_current.txt /root/.REQ /root/.IP /var/www/html/req.txt /var/www/html/req.php /var/www/html/drop.txt /var/www/html/.tmp.txt)
	for ((x=0; x < ${#arq[*]}; x++)); do
		if [ -e ${arq[$x]} ]; then
			rm ${arq[$x]}
		fi
	done
	killall -9 ddos.sh .cron.sh sleep
	exit 1

elif [ "$1" == "undrop" ]; then
	iptables -F
	sed -i '/'$2'/d' /root/rules.txt
	sh /root/rules.txt
	cat /root/rules.txt | grep 'DROP' | cut -d " " -f 5,11,12,13 | grep "\." > /var/www/html/drop.txt
	exit 1

elif [ "$1" == "drop" ]; then
	iptables -F
	sed -i '1s/^/iptables -A INPUT -s '$2' -j DROP -m comment --comment "BAN BY ARGUMENT" \n/' /root/rules.txt
	sh /root/rules.txt
	cat /root/rules.txt | grep 'DROP' | cut -d " " -f 5,11,12,13 | grep "\." > /var/www/html/drop.txt
	exit 1

elif [ "$1" == "allow" ]; then
	iptables -F
	sed -i "1s/^/iptables -A INPUT -m multiport -p tcp --dport $3 -s $2 -j ACCEPT\n/" /root/rules.txt
	sh /root/rules.txt
	exit 1

elif [ "$1" == "allow80" ]; then
	iptables -F
        sed -i "1s/^/iptables -A INPUT -m multiport -p tcp --dport 80 -s $2 -j ACCEPT\n/" /root/rules.txt
        sh /root/rules.txt

        sleep 10

	iptables -F
	sed -i '/'$2'/d' /root/rules.txt
	sh /root/rules.txt
        exit 1

else

	echo "#!/bin/bash" > /root/.cron.sh
	echo "while [ 1 ]; do" >> /root/.cron.sh
	echo " > /var/log/apache2/access.log" >> /root/.cron.sh
	echo "sleep "$2"" >> /root/.cron.sh
	echo "done" >> /root/.cron.sh

	chmod +x /root/.cron.sh
	nohup /root/.cron.sh > /dev/null 2>&1&

	echo '<script type="text/javascript">' > /var/www/html/req.php
	echo 'window.onload = function(){' >> /var/www/html/req.php
	echo '        setTimeout(function(){' >> /var/www/html/req.php
	echo '                window.location = "";' >> /var/www/html/req.php
	echo '        }, 1000);' >> /var/www/html/req.php
	echo '}' >> /var/www/html/req.php
	echo '</script>' >> /var/www/html/req.php
	echo '<iframe src="'req.txt'" height="1000" width="100%" style="border: 0px;"></iframe>' >> /var/www/html/req.php

	if [ -e /root/rules.txt ]; then
		sh /root/rules.txt
		cat /root/rules.txt | grep 'DROP' | cut -d " " -f 5,11,12,13 | grep "\." > /var/www/html/drop.txt
	fi

	cp /var/log/apache2/access.log /var/log/apache2/.tmp.log

	while [ 1 ]; do
		eoq=$(diff /var/log/apache2/access.log /var/log/apache2/.tmp.log)
		if [ "$eoq" != "" ]; then
			cat /var/log/apache2/access.log | cut -d " " -f 1 | sort | uniq -c | sort -rn | grep -v : | awk '{print "REQUESTS="$1" / IP="$2}' > /var/www/html/.tmp.txt; tam=$(wc -l "/var/www/html/.tmp.txt" | cut -d " " -f 1); while read row; do echo "$tam $row"; let tam-- ; done < "/var/www/html/.tmp.txt" | sed 's/ / - /'> /var/www/html/req.txt
			cat /var/log/apache2/access.log | cut -d " " -f 1 | sort | uniq -c | sort -rn | grep -v : | sed 's/^ *//' | cut -d " " -f 1 > /root/.REQ
			cat /var/log/apache2/access.log | cut -d " " -f 1 | sort | uniq -c | sort -rn | grep -v : | sed 's/^ *//' | cut -d " " -f 2 > /root/.IP

			TOTAL=$(awk 'END {print NR}' /root/.REQ)
			for ((i=1;i<=$TOTAL;i++)); do
				eval REQ_$i=$(sed -n "$i"p /root/.REQ)
				eval IP_$i=$(sed -n "$i"p /root/.IP)
				for x in REQ_"$i"; do
					for y in IP_"$i"; do
						if [ "${!x}" -ge "$1" ]; then
							echo "REQ >= "$1" --> " "${!y}"
							echo "${!y}" >> /var/www/html/.ips.txt
						fi
					done
				done
			done

			arq=(/root/.REQ /root/.IP)
			for ((x=0; x < ${#arq[*]}; x++)); do
				if [ -e ${arq[$x]} ]; then
					rm ${arq[$x]}
				fi
			done

		fi

		if [ -e /var/www/html/.ips.txt ]; then
			cat /var/www/html/.ips.txt | sort -u | sed 's/^/iptables -A INPUT -s /' | sed 's/$/& -j DROP -m comment --comment "BAN BY REQ" /' > /root/.IPS_drop_current.txt
			rm /var/www/html/.ips.txt

			if [ -e /root/.IPS_drop.txt ]; then
				diff=$(diff /root/.IPS_drop_current.txt /root/.IPS_drop)
				if [ "$diff" != "" ]; then
					cat /root/.IPS_drop_current.txt /root/rules.txt > /root/.temp.txt && mv /root/.temp.txt /root/.iptables_rules.sh
					awk '!i[$0]++' < /root/.iptables_rules.sh > /root/rules.txt
					iptables -F
					sh /root/rules.txt &> /dev/null
					rm /root/.iptables_rules.sh
					mv /root/.IPS_drop_current.txt /root/.IPS_drop
				fi
			elif [ -e /root/rules.txt  ]; then
				cat /root/.IPS_drop_current.txt /root/rules.txt > /root/.temp.txt && mv /root/.temp.txt /root/.iptables_rules.sh
				awk '!i[$0]++' < /root/.iptables_rules.sh > /root/rules.txt
				iptables -F
				sh /root/rules.txt &> /dev/null
				rm /root/.iptables_rules.sh
			else
				cp /root/.IPS_drop_current.txt /root/rules.txt
				sh /root/rules.sh &> /dev/null
				echo 1 > /root/.IPS_drop.txt
			fi

			cat /root/rules.txt | grep 'DROP' | cut -d " " -f 5,11,12,13 | grep "\." > /var/www/html/drop.txt
		fi
		cp /var/log/apache2/access.log /var/log/apache2/.tmp.log
		sleep 1
	done

fi
