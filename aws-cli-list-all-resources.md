#VPCs
aws ec2 describe-vpcs --query "Vpcs[*].[VpcId, CidrBlock]" --output text
aws ec2 describe-subnets --query "Subnets[*].[VpcId, SubnetId, CidrBlock]" --output text

#Route Tables
aws ec2 describe-route-tables --query "RouteTables[*].[VpcId, RouteTableId, Tags[?Key=='Name'].Value, Routes[*].[DestinationCidrBlock, TransitGatewayId, GatewayId]]" --output text

#VPC Endpoint
aws ec2 describe-vpc-endpoints --query "VpcEndpoints[*].[VpcId,VpcEndpointId,ServiceName]" --output text
aws ec2 describe-vpc-endpoints --query "VpcEndpoints[*].SubnetIds" --output text
aws ec2 describe-vpc-endpoints --query "VpcEndpoints[*].Groups[].GroupId]" --output text
aws ec2 describe-vpc-endpoints --query "VpcEndpoints[*].Tags[?Key=='Name'].Value]" --output text

#SecurityGroups
aws ec2 describe-security-groups --query "SecurityGroups[*].[GroupId, GroupName, VpcId, IpPermissions.['Ingress'], IpPermissions[*].[FromPort, IpProtocol, IpRanges[*].[CidrIp, Description]], IpPermissionsEgress.['Egress'], IpPermissionsEgress[*].[FromPort, IpProtocol, IpRanges[*].[CidrIp, Description]]]" --output text

sed -i 's/^/- - - - /' security_groups.txt
sed -i 's/- - - - sg/sg/' security_groups.txt
sed -i 's/- - - - Ingress/- - - Ingress/' security_groups.txt
sed -i 's/- - - - Egress/- - - Egress/' security_groups.txt
sed -i -E '/([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}/ s/^/- - /' security_groups.txt

#NACL
aws ec2 describe-network-acls --query "NetworkAcls[*].[NetworkAclId, VpcId, Associations[*].SubnetId, Entries[*].[Egress, RuleNumber, Protocol, PortRange.From, PortRange.To, CidrBlock, RuleAction]]" --output text

#EC2
aws ec2 describe-instances --query "Reservations[*].Instances[*].[VpcId, SubnetId, InstanceId, InstanceType]" --output text
aws ec2 describe-instances --query "Reservations[*].Instances[*].[Tags[?Key=='Name'].Value]" --output text
aws ec2 describe-instances --query "Reservations[*].Instances[*].[Placement.AvailabilityZone]" --output text
aws ec2 describe-instances --query "Reservations[*].Instances[*].SecurityGroups" --output text

#EKS
for cluster_name in `aws eks list-clusters --query "clusters[*]" --output text`
do
paste -d ' ' \
<(echo $cluster_name) \
<(aws eks describe-cluster --name $cluster_name --query "cluster.resourcesVpcConfig.vpcId" --output text) \
<(aws eks describe-cluster --name $cluster_name --query "cluster.resourcesVpcConfig.subnetIds" --output text) \
<(aws eks describe-cluster --name $cluster_name --query "cluster.resourcesVpcConfig.clusterSecurityGroupId" --output text) \
<(aws eks describe-cluster --name $cluster_name --query "cluster.resourcesVpcConfig.securityGroupIds" --output text)
done

#ELB
aws elbv2 describe-load-balancers --query "LoadBalancers[*].[LoadBalancerName, VpcId, Type]" --output text
aws elbv2 describe-load-balancers --query "LoadBalancers[*].AvailabilityZones[*].ZoneName" --output text

for lb_arn in `aws elbv2 describe-load-balancers --query "LoadBalancers[*].LoadBalancerArn" --output text`
do
paste -d ' ' \
<(echo $lb_arn | awk -F'/' '{print $3}') \
<(aws elbv2 describe-target-groups --load-balancer-arn $lb_arn --query "TargetGroups[*].[TargetGroupName, Port]" --output text)
done

for lb_arn in `aws elbv2 describe-load-balancers --query "LoadBalancers[*].LoadBalancerArn" --output text`
do
aws elbv2 describe-target-groups --load-balancer-arn $lb_arn --query "TargetGroups[*].[TargetGroupName, Port]" --output text
done

for lb_arn in `aws elbv2 describe-load-balancers --query "LoadBalancers[*].LoadBalancerArn" --output text`
do
paste -d ' ' \
<(aws elbv2 describe-listeners --load-balancer-arn $lb_arn --query "Listeners[*].DefaultActions[*].ForwardConfig.TargetGroups" --output text | awk -F'/' '{print $2}') \
<(aws elbv2 describe-listeners --load-balancer-arn $lb_arn --query "Listeners[*].Port" --output text)
done

#RDS
aws rds describe-db-instances --query "DBInstances[*].[DBInstanceIdentifier, DBInstanceClass, Engine, AvailabilityZone, MultiAZ]" --output text
aws rds describe-db-instances --query "DBInstances[*].DBSubnetGroup.VpcId" --output text
aws rds describe-db-instances --query "DBInstances[*].VpcSecurityGroups[*].VpcSecurityGroupId" --output text
aws rds describe-db-instances --query "DBInstances[*].DBSubnetGroup.Subnets[*].SubnetIdentifier" --output text
