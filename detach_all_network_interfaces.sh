aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId, NetworkInterfaces[0].NetworkInterfaceId]' --output text | awk '{print $1, $2}'

#!/bin/bash

# Function to detach network interfaces from the specified instance
function detach_network_interfaces {
    instance_id=$1
    echo "Detaching network interfaces for instance: $instance_id"
    
    # Get the network interface IDs for the specified instance
    network_interface_ids=$(aws ec2 describe-instances --instance-ids "$instance_id" --query 'Reservations[*].Instances[*].NetworkInterfaces[*].NetworkInterfaceId' --output text)
    
    # Detach each network interface
    for network_interface_id in $network_interface_ids; do
        aws ec2 detach-network-interface --attachment-id "$network_interface_id"
    done
}

# Loop through each instance and detach its network interfaces
while read -r instance_id network_interface_id; do
    if [ -n "$network_interface_id" ]; then
        detach_network_interfaces "$instance_id"
    fi
done
