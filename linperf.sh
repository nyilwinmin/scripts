#!/bin/sh
###############################################################################
#
# This script is used to collect data for 
# 'MustGather: Performance, Hang or High CPU Issues on Linux'
#
# ./linperf.sh [PID(s)_of_the_problematic_JVM(s)_separated_by_spaces]
#
# Optional flags
# -j javacore interval
# -q quiet end message
# -s script span
# -t top dash interval
# -v vmstat interval
# -z allow stats
#
# Example with some flags and PIDs to produce a javacore/thread dump every 5 seconds for up to 30 seconds:
# ./linperf.sh -j 5 -s 30 PID_of_the_problamtic_JVM
#
# Example without PID
# ./linperf.sh -z
# 
SCRIPT_VERSION=2022.06.22
###############################################################################
#                        #
# Variables              # 
#                        #
##########################
SCRIPT_SPAN=240          # How long the whole script should take. Default=240
JAVACORE_INTERVAL=30    # How often javacores should be taken. Default=30
TOP_INTERVAL=60          # How often top data should be taken. Default=60
TOP_DASH_H_INTERVAL=5    # How often top dash H data should be taken. Default=5
VMSTAT_INTERVAL=5        # How often vmstat data should be taken. Default=5
###############################################################################
# * All values are in seconds.
# * All the 'INTERVAL' values should divide into the 'SCRIPT_SPAN' by a whole 
#   integer to obtain expected results.
# * Setting any 'INTERVAL' too low (especially JAVACORE) can result in data
#   that may not be useful towards resolving the issue.  This becomes a problem 
#   when the process of collecting data obscures the real issue.
###############################################################################

KEEPQUIET=0
ALLOWSTATS=0
OPTIND=1
START_TIMESTAMP=$(date +%s)

while getopts "j:qs:t:u:v:z" opt; do
  case "$opt" in
    j)
      JAVACORE_INTERVAL="${OPTARG}"
      ;;
    q)
      KEEPQUIET=1
      ;;
    s)
      SCRIPT_SPAN="${OPTARG}"
      ;;
    t)
      TOP_INTERVAL="${OPTARG}"
      ;;
    u)
      TOP_DASH_H_INTERVAL="${OPTARG}"
      ;;
    v)
      VMSTAT_INTERVAL="${OPTARG}"
      ;;
    z)
      ALLOWSTATS=1
      ;;
  esac
done

shift $((OPTIND-1))

if [ "${1:-}" = "--" ]; then
  shift
fi

if [ $# -eq 0 ] && [ $ALLOWSTATS -eq 0 ]
then
  echo "$0 : Unable to find required PID argument.  Please rerun the script as follows:"
  echo "$0 : ./linperf.sh [PID(s)_of_the_problematic_JVM(s)_separated_by_spaces]"
  exit 1
fi
##########################
# Create output files    #
#                        #
##########################
# Create the screen.out and put the current date in it.
echo > screen.out
date >> screen.out

# Starting up
echo $(date) "MustGather>> linperf.sh script starting..." | tee -a screen.out
echo $(date) "MustGather>> Script version:  $SCRIPT_VERSION." | tee -a screen.out

# Display the PIDs which have been input to the script
for i in $*
do
	echo $(date) "MustGather>> PROBLEMATIC_PID is:  $i" | tee -a screen.out
done

# Display the being used in this script
echo $(date) "MustGather>> SCRIPT_SPAN = $SCRIPT_SPAN" | tee -a screen.out
echo $(date) "MustGather>> JAVACORE_INTERVAL = $JAVACORE_INTERVAL" | tee -a screen.out
echo $(date) "MustGather>> TOP_INTERVAL = $TOP_INTERVAL" | tee -a screen.out
echo $(date) "MustGather>> TOP_DASH_H_INTERVAL = $TOP_DASH_H_INTERVAL" | tee -a screen.out
echo $(date) "MustGather>> VMSTAT_INTERVAL = $VMSTAT_INTERVAL" | tee -a screen.out

# Collect the user currently executing the script
date > whoami.out
whoami >> whoami.out 2>&1
echo $(date) "MustGather>> Collection of user authority data complete." | tee -a screen.out

# Create some of the output files with a blank line at top
echo $(date) "MustGather>> Creating output files..." | tee -a screen.out
echo > vmstat.out
echo > ps.out
echo > top.out
echo $(date) "MustGather>> Output files created:" | tee -a screen.out
echo $(date) "MustGather>>      vmstat.out" | tee -a screen.out
echo $(date) "MustGather>>      ps.out" | tee -a screen.out
echo $(date) "MustGather>>      top.out" | tee -a screen.out
for i in $*
do
	echo > topdashH.$i.out
	echo $(date) "MustGather>>      topdashH.$i.out" | tee -a screen.out
done

###############################################################################
#                       #
# Start collection of:  #
#  * netstat x2         #
#  * top                #
#  * top dash H         #
#  * vmstat             #
#                       #
#########################
# Start the collection of netstat data.
# Collect the first netstat: date at the top, data, and then a blank line
date >> netstat.out
netstat -pan >> netstat.out 2>&1
#PIDs,all,numeric
echo >> netstat.out
echo $(date) "MustGather>> First netstat snapshot complete." | tee -a screen.out

# Start the collection of top data.
# It runs in the background so that other tasks can be completed while this runs.
date >> top.out
echo >> top.out
top -bc -d $TOP_INTERVAL -n `expr $SCRIPT_SPAN / $TOP_INTERVAL + 1` >> top.out 2>&1 &

# b - batch
# c - show command (doesn't seem to toggle contrary to man page)
# d - duration (e.g if 10, will run once every 10s indefinitely)
# n - number of times to run


echo $(date) "MustGather>> Collection of top data started." | tee -a screen.out

# Start the collection of top dash H data.
# It runs in the background so that other tasks can be completed while this runs.
for i in $*
do
	date >> topdashH.$i.out
	echo >> topdashH.$i.out
	echo "Collected against PID $i." >> topdashH.$i.out
	echo >> topdashH.$i.out
	top -bH -d $TOP_DASH_H_INTERVAL -n `expr $SCRIPT_SPAN / $TOP_DASH_H_INTERVAL + 1` -p $i >> topdashH.$i.out 2>&1 &
	echo $(date) "MustGather>> Collection of top dash H data started for PID $i." | tee -a screen.out
done

# Start the collection of vmstat data.
# It runs in the background so that other tasks can be completed while this runs.
date >> vmstat.out
vmstat $VMSTAT_INTERVAL `expr $SCRIPT_SPAN / $VMSTAT_INTERVAL + 1` >> vmstat.out 2>&1 &
echo $(date) "MustGather>> Collection of vmstat data started." | tee -a screen.out

################################################################################
#                       #
# Start collection of:  #
#  * javacores          #
#  * ps                 #
#                       #
#########################
# Initialize some loop variables
n=1
m=`expr $SCRIPT_SPAN / $JAVACORE_INTERVAL`

# Loop
while [ $n -le $m ]
do
	
	# Collect a ps snapshot: date at the top, data, and then a blank line
	date >> ps.out
	ps -eLf >> ps.out 2>&1
	echo >> ps.out
	echo $(date) "MustGather>> Collected a ps snapshot." | tee -a screen.out
	
	# Collect a javacore against the problematic pid (passed in by the user)
	# Javacores are output to the working directory of the JVM; in most cases this is the <profile_root>
	for i in $*
	do
		kill -3 $i >> screen.out 2>&1
		echo $(date) "MustGather>> Produced a javacore for PID $i." | tee -a screen.out
	done
	
	# Pause for JAVACORE_INTERVAL seconds.
	echo $(date) "MustGather>> Continuing to collect data for $JAVACORE_INTERVAL seconds..." | tee -a screen.out
	sleep $JAVACORE_INTERVAL
	
	# Increment counter
	n=`expr $n + 1`

done

# Collect a final javacore and ps snapshot.
date >> ps.out
ps -eLf >> ps.out 2>&1
echo >> ps.out
echo $(date) "MustGather>> Collected the final ps snapshot." | tee -a screen.out

for i in $*
do
	kill -3 $i >> screen.out 2>&1
	echo $(date) "MustGather>> Produced the final javacore for PID $i." | tee -a screen.out
done

# Collect a final netstat
date >> netstat.out
netstat -pan >> netstat.out 2>&1
echo $(date) "MustGather>> Final netstat snapshot complete." | tee -a screen.out

################################################################################
#                       #
# Other data collection #
#                       #
#########################
dmesg > dmesg.out 2>&1
df -hk > df-hk.out 2>&1

echo $(date) "MustGather>> Collected other data." | tee -a screen.out
################################################################################
#                       #
# Compress & Cleanup    #
#                       #
#########################
# Brief pause to make sure all data is collected.
echo $(date) "MustGather>> Preparing for packaging and cleanup..." | tee -a screen.out
sleep 5

# Tar default javacores
TARRED_JAVACORE_STRING=""
PIDS_NOT_FOUND_DEFAULT_JAVACORE=""
ELAPSED_TIME=`awk "BEGIN {print ($(date +%s) - $START_TIMESTAMP ) / 60 + 0.05}"`
for i in $*
do
	FINDOUTPUT=$(cd /proc/$i/cwd/ && find -name "javacore*$i*.txt" -mmin -$ELAPSED_TIME -type f -printf '%f\n' 2>/dev/null)
	#FINDOUTPUT=$(cd /proc/$i/cwd/ && find * -name "javacore*$i*.txt" -mmin -$ELAPSED_TIME -print0 2>/dev/null)
	#echo $FINDOUTPUT
	if [ -n "${FINDOUTPUT}" ]
	then
		(cd /proc/$i/cwd/ && tar c $FINDOUTPUT ) > javacore.$i.tar
		TEMP_JAVACORE_STRING="$TARRED_JAVACORE_STRING javacore.$i.tar "
		TARRED_JAVACORE_STRING="$TEMP_JAVACORE_STRING"
	else
		TEMP_PID_STRING="$PIDS_NOT_FOUND_DEFAULT_JAVACORE $i"
		PIDS_NOT_FOUND_DEFAULT_JAVACORE="$TEMP_PID_STRING "
	fi
done


# Tar the output files together
FILE_TIMESTAMP_STRING=$(date -d @$START_TIMESTAMP '+%Y.%m.%d.%H.%M.%S')
echo $(date) "MustGather>> Compressing output files into linperf_RESULTS.$FILE_TIMESTAMP_STRING.tar.gz" | tee -a screen.out

# Build a string to contain all the file names
FILES_STRING="netstat.out vmstat.out ps.out top.out screen.out dmesg.out whoami.out df-hk.out $TARRED_JAVACORE_STRING"
for i in $*
do
	TEMP_STRING=" topdashH.$i.out"
	FILES_STRING="$FILES_STRING $TEMP_STRING"
done
tar -cvf linperf_RESULTS.$FILE_TIMESTAMP_STRING.tar $FILES_STRING

# GZip the tar file to create linperf_RESULTS.FILE_TIMESTAMP_STRING.tar.gz
gzip linperf_RESULTS.$FILE_TIMESTAMP_STRING.tar

# Clean up the output files now that they have been tar/gz'd.
echo $(date) "MustGather>> Cleaning up..."
rm $FILES_STRING

echo $(date) "MustGather>> Clean up complete."
echo $(date) "MustGather>> linperf.sh script complete."


if [ $KEEPQUIET -eq 0 ]; then
	echo
	echo "$(tput setaf 0)$(tput setab 3)\t\t\t\t\t\t\t\t\t\t$(tput sgr 0)"
	echo "$(tput setaf 0)$(tput setab 3)  $(tput sgr 0)"
	echo "$(tput setaf 0)$(tput setab 3)  $(tput sgr 0)  To share with IBM support, upload all the following files:"
	echo "$(tput setaf 0)$(tput setab 3)  $(tput sgr 0)"
	echo "$(tput setaf 0)$(tput setab 3)  $(tput sgr 0)  * linperf_RESULTS.$FILE_TIMESTAMP_STRING.tar.gz"
	echo "$(tput setaf 0)$(tput setab 3)  $(tput sgr 0)  * /var/log/messages (Linux OS files)"
	echo "$(tput setaf 0)$(tput setab 3)  $(tput sgr 0)"
	echo "$(tput setaf 0)$(tput setab 3)  $(tput sgr 0)  For WebSphere Application Server:"
	echo "$(tput setaf 0)$(tput setab 3)  $(tput sgr 0)  * Logs (systemout.log, native_stderr.log, etc)"

	if [ "${PIDS_NOT_FOUND_DEFAULT_JAVACORE}" != "" ]; then
		echo "$(tput setaf 0)$(tput setab 3)  $(tput sgr 0)  * javacores from PID(s) $PIDS_NOT_FOUND_DEFAULT_JAVACORE"
	fi

	echo "$(tput setaf 0)$(tput setab 3)  $(tput sgr 0)  * server.xml for the server(s) that you are providing data for"
	echo "$(tput setaf 0)$(tput setab 3)  $(tput sgr 0)"
	echo "$(tput setaf 0)$(tput setab 3)  $(tput sgr 0)  For Liberty:"
	echo "$(tput setaf 0)$(tput setab 3)  $(tput sgr 0)  * Logs (messages.log, console.log, etc)"

	if [ "${PIDS_NOT_FOUND_DEFAULT_JAVACORE}" != "" ]; then
		echo "$(tput setaf 0)$(tput setab 3)  $(tput sgr 0)  * javacores from PID(s) $PIDS_NOT_FOUND_DEFAULT_JAVACORE (if running on an IBM JDK)"
	fi

	echo "$(tput setaf 0)$(tput setab 3)  $(tput sgr 0)  * server.env, server.xml, and jvm.options"
	echo "$(tput setaf 0)$(tput setab 3)  $(tput sgr 0)"
	echo "$(tput setaf 0)$(tput setab 3)\t\t\t\t\t\t\t\t\t\t$(tput sgr 0)"
fi
################################################################################