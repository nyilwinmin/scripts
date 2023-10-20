#!/bin/bash -x
#change hostnames, environment names (prd)
#RUN COMMAND: "sudo -u ec2-user -i /bin/bash -x -c \"aws s3 cp s3://ec2-ssnet-prd-patching/maintenance_page_setup.sh . --profile ssnet_devops && chmod +x maintenance_page_setup.sh && ./maintenance_page_setup.sh false\""

export PATH=/usr/local/bin:$PATH
current_host=`hostname`

truefalse_var=$1

if [ $truefalse_var = 'true' ]
then
	updown_var=Up
elif [ $truefalse_var = 'false' ]
then
	updown_var=Down
else
	echo "provide either 'true' or 'false' as parameter"
	exit 1
fi

deploy_inter(){
cd ${ssnetoneweb_path}/deploy_logs
image_tag=`grep -Porh 'ssnetoneweb-prd-([a-z0-9]+)ez' *deploy.log | tail -1`
sudo -u ec2-user -i /bin/bash -c "${ssnetoneweb_path}/deploy.sh prd ssnet_devops $image_tag internet > ${ssnetoneweb_path}/deploy_logs/inter_maintenance.log"

echo 'Following is the latest image from ECR' >> ${ssnetoneweb_path}/deploy_logs/inter_maintenance.log
aws ecr describe-images --repository-name ssnetoneweb-repo --query 'imageDetails[?not_null(imageTags) && ends_with(imageTags[0], `ez`)] | sort_by(@, &imagePushedAt) | [-1].[imageTags[0], imagePushedAt]' --output text --profile ssnet_devops >> ${ssnetoneweb_path}/deploy_logs/inter_maintenance.log
}

deploy_intra(){
cd ${ssnetoneweb_path}/deploy_logs
image_tag=`grep -Porh 'ssnetoneweb-prd-([a-z0-9]+)iz' *deploy.log | tail -1`
sudo -u ec2-user -i /bin/bash -c "${ssnetoneweb_path}/deploy.sh prd ssnet_devops $image_tag intranet > ${ssnetoneweb_path}/deploy_logs/intra_maintenance.log"

echo 'Following is the latest image from ECR' >> ${ssnetoneweb_path}/deploy_logs/intra_maintenance.log
aws ecr describe-images --repository-name ssnetoneweb-repo --query 'imageDetails[?not_null(imageTags) && ends_with(imageTags[0], `iz`)] | sort_by(@, &imagePushedAt) | [-1].[imageTags[0], imagePushedAt]' --output text --profile ssnet_devops >> ${ssnetoneweb_path}/deploy_logs/intra_maintenance.log
}

deploy_apigw(){
apigw_path=/home/ec2-user/deployments/ssnet-infra/nginxrevproxy
cd ${apigw_path}
sudo -u ec2-user -i /bin/bash -c "${apigw_path}/deploy.sh prd ssnet_devops internet ${truefalse_var}"
sudo -u ec2-user -i /bin/bash -c "${apigw_path}/deploy.sh prd ssnet_devops intranet ${truefalse_var}"
}

#DEVOPS
if [ $current_host == ip-100-121-17-114 ]
	then 
	echo 'devops'
		
	#ssnetoneweb 
	ssnetoneweb_path=/home/ec2-user/deployments/devops/ssnetoneweb
	
	#pull 
	sudo -u ec2-user -i /bin/bash -c "cd /home/ec2-user/deployments/devops/ && ./pull_repo.sh prd ssnet_devops"
	
	if [ $truefalse_var = 'true' ]
	then
		##inter
		values_file=${ssnetoneweb_path}/ssnetoneweb/prd_ez_values.yaml
		sed -i 's|maintenance: "false"|maintenance: "true"|' $values_file
		sed -i -E 's|maintenance_date: "[0-9]+ [A-Za-z]+ [0-9]{4}"|maintenance_date: "'"$(date +'%d %B %Y')"'"|' ${values_file}
		
		##intra
		values_file=${ssnetoneweb_path}/ssnetoneweb/prd_iz_values.yaml
		sed -i 's|maintenance: "false"|maintenance: "true"|' $values_file
		sed -i -E 's|maintenance_date: "[0-9]+ [A-Za-z]+ [0-9]{4}"|maintenance_date: "'"$(date +'%d %B %Y')"'"|' ${values_file}
		
	elif [ $truefalse_var = 'false' ]
	then
		##inter
		values_file=${ssnetoneweb_path}/ssnetoneweb/prd_ez_values.yaml
		sed -i 's|maintenance: "true"|maintenance: "false"|' $values_file		
		##intra
		values_file=${ssnetoneweb_path}/ssnetoneweb/prd_iz_values.yaml
		sed -i 's|maintenance: "true"|maintenance: "false"|' $values_file
	else
		echo "provide either 'true' or 'false' as parameter"
		exit 1
	fi
	#push
	sudo -u ec2-user -i /bin/bash -c "cd /home/ec2-user/deployments/devops/ && ./push_repo.sh prd ssnet_devops"
	
	deploy_inter
	deploy_intra
	deploy_apigw

#web1
elif [ $current_host == ip-10-211-103-14 ]
	then
	echo 'web1'
	sudo sed -i -E 's|[0-9]+ [A-Za-z]+ [0-9]{4}|'"$(date +'%d %B %Y')"'|g' /home/saadmin/maintenancePage.html
	sudo /app/scripts/SetMaintenancePage.sh $updown_var

#web2
elif [ $current_host == ip-10-211-103-96 ]
	then
	echo 'web2'
	sudo sed -i -E 's|[0-9]+ [A-Za-z]+ [0-9]{4}|'"$(date +'%d %B %Y')"'|g' /home/saadmin/maintenancePage.html
	sudo /app/scripts/SetMaintenancePage.sh $updown_var

#intra01
elif [ $current_host == ip-10-211-118-58 ]
then
	if [ $truefalse_var = 'true' ]
	then
		echo 'intra01'
		#stop quartz
		sudo /app/script/stopQuartz.sh
		#disable cron jobs
		sudo -u saadmin crontab -l > /tmp/crontab_bkp
		echo | sudo -u saadmin crontab -
	elif [ $truefalse_var = 'false' ]
	then
		#restore cron jobs
		cat /tmp/crontab_bkp | sudo -u saadmin crontab -
	fi

#intra02
elif [ $current_host == ip-10-211-118-71 ]
then
	if [ $truefalse_var = 'true' ]
	then
		echo 'intra02'
		#stop quartz
		sudo /app/script/stopQuartz.sh
		#disable cron jobs
		sudo -u saadmin crontab -l > /tmp/crontab_bkp
		echo | sudo -u saadmin crontab -
	elif [ $truefalse_var = 'false' ]
	then
		#restore cron jobs
		cat /tmp/crontab_bkp | sudo -u saadmin crontab -
	fi

#inter01
elif [ $current_host == ip-10-211-118-45 ]
then
	if [ $truefalse_var = 'true' ]
	then
		echo 'inter01'
		#stop quartz
		sudo /app/script/stopQuartz.sh
		#disable cron jobs
		sudo -u saadmin crontab -l > /tmp/crontab_bkp
		echo | sudo -u saadmin crontab -
	elif [ $truefalse_var = 'false' ]
	then
		#restore cron jobs
		cat /tmp/crontab_bkp | sudo -u saadmin crontab -
	fi

#inter02
elif [ $current_host == ip-10-211-118-112 ]
then
	if [ $truefalse_var = 'true' ]
	then
		echo 'inter02'
		#stop quartz
		sudo /app/script/stopQuartz.sh
		#disable cron jobs
		sudo -u saadmin crontab -l > /tmp/crontab_bkp
		echo | sudo -u saadmin crontab -
	elif [ $truefalse_var = 'false' ]
	then
		#restore cron jobs
		cat /tmp/crontab_bkp | sudo -u saadmin crontab -
	fi
fi
