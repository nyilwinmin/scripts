if [ ! -d /home/ec2-user/load_monitor/ ]
then mkdir -p /home/ec2-user/load_monitor/
fi

#'EOF' to escape command substitution characters

cat << 'EOF' > /home/ec2-user/load_monitor/load_monitor.sh
idle_cpu=`top -b -n 1 | grep -w "%Cpu(s)" | awk '{sub(/\..*/, "", $8); print $8}'`


if [ $idle_cpu -le 30 ] 
then
top -bc -d 10 -n 6 >> /home/ec2-user/load_monitor/topc_`date +%Y%m%d%H%M%S`.out &
top -bH -d 10 -n 6 >> /home/ec2-user/load_monitor/topH_`date +%Y%m%d%H%M%S`.out &
ps -eLf >> /home/ec2-user/load_monitor/ps_`date +%Y%m%d%H%M%S`.out
rm /home/ec2-user/load_monitor/*`date +%Y%m%d -d 'last week'`*
fi
EOF

chmod 755 /home/ec2-user/load_monitor/load_monitor.sh

if ! crontab -l | grep load_monitor.sh
then (crontab -l; echo "*/5 * * * * /home/ec2-user/load_monitor/load_monitor.sh")| crontab -
fi