#!/bin/bash

export PATH=$PATH:/usr/local/bin

#list all alarms and filter
aws cloudwatch describe-alarms --profile ssnet_devops | jq -r '.MetricAlarms[] | .AlarmName' > ./Alarmlist
grep -i -E 'cpu|disk|mem|io|load|swap' Alarmlist > Alarmlist1

#loop through filtered alarms
while IFS= read -r line; do

#remove blank,'/','!',"." from filename
modified_line=$(echo "$line" | sed 's/[[:blank:]\/!.]/_/g')
#echo $modified_line

#get timestamps for all triggered alarms for the past month
aws cloudwatch describe-alarm-history --alarm-name "$line" --output json --profile ssnet_devops | jq -r '.AlarmHistoryItems[] | [ .Timestamp, .HistorySummary ] | @csv' | grep "Alarm updated from OK to ALARM" | grep `date +%Y-%m -d "last month"` | awk -F ',' '{print $1}' > temp.csv

#get newState value for the corresponding alarms
aws cloudwatch describe-alarm-history --alarm-name "$line"  --output json --profile ssnet_devops | jq -r '.AlarmHistoryItems[] | [ .Timestamp, .HistorySummary, .HistoryData ] | @csv' | grep "Alarm updated from OK to ALARM" | grep "^\"`date +%Y-%m -d "last month"`" | grep -oP 'newState.*recentDatapoints"":\[\K[0-9.]+' > temp1.csv

#zip and remove temp files
paste temp.csv temp1.csv -d , > ${modified_line}.csv
zip -m CWAlarms_`date +%b%Y -d "last month"`.zip ${modified_line}.csv

done < ./Alarmlist1

rm Alarmlist

aws s3 mv CWAlarms_`date +%b%Y -d "last month"`.zip s3://ec2-ssnet-prd-patching/MSR/ --profile ssnet_devops