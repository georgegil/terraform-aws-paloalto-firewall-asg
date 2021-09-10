# PowerShell script file to be executed as a AWS Lambda function.
#
# When executing in Lambda the following variables will be predefined.
#   $LambdaInput - A PSObject that contains the Lambda function input data.
#   $LambdaContext - An Amazon.Lambda.Core.ILambdaContext object that contains information about the currently running Lambda environment.
#
# To include PowerShell modules with your Lambda function, like the AWS.Tools.S3 module, add a "#Requires" statement
# indicating the module and version. If using an AWS.Tools.* module the AWS.Tools.Common module is also required.

#Requires -Modules @{ModuleName='AWS.Tools.Common';ModuleVersion='4.1.14.0'}, @{ModuleName='AWS.Tools.EC2';ModuleVersion='4.1.14.0'}, @{ModuleName='AWS.Tools.SecretsManager';ModuleVersion='4.1.14.0'}, @{ModuleName='AWS.Tools.AutoScaling';ModuleVersion='4.1.14.0'}

# send the input event to CloudWatch Logs
Write-Host (ConvertTo-Json -InputObject $LambdaInput -Compress -Depth 5)


# An SNS Subscription can receive multiple SNS records in a single execution.
foreach ($record in $LambdaInput.Records) {
    $message = $record.Sns.Message | convertfrom-json
    write-host 'log_message:' $message
    $AutoScalingGroupName = $message.AutoScalingGroupName
    Write-Host 'log_AutoScalingGroupName:' $AutoScalingGroupName
    $ec2_id = $message.EC2InstanceId
    write-host 'log_ec2_id:' $ec2_id
    $LifecycleTransition = $message.LifecycleTransition
    write-host 'log_LifecycleTransition:' $LifecycleTransition
    $LifecycleHookName = $message.LifecycleHookName
    Write-Host 'log_LifecycleHookName:' $LifecycleHookName
    $LifecycleActionToken = $message.LifecycleActionToken
    Write-Host 'log_LifecycleActionToken:' $LifecycleActionToken
    $region = $env:AWS_REGION
    write-host 'log_Region:' $region

    if ($message.NotificationMetadata) {
        $NotificationMetadata = $message.NotificationMetadata | convertfrom-json
        write-host 'log_NotificationMetadata:' $NotificationMetadata
    }


    if ($LifecycleTransition -eq "autoscaling:EC2_INSTANCE_LAUNCHING") {
        $ec2 = Get-EC2Instance -region $region -InstanceId $ec2_id
        $az = $ec2.Instances[0].Placement.AvailabilityZone
        $mgmt_sg = Get-EC2SecurityGroup -Region $region -Filter @{name = "tag:Name"; values = 'Management-SG' }
        $mgmt_subnet = get-EC2Subnet -Region $region -Filter @{name = "tag:Name"; values = '*Management*' } | Where-Object { ($_.AvailabilityZone -eq $az) }
        $mgmt_interface = new-EC2NetworkInterface -Region $region -SubnetId $mgmt_subnet.SubnetId -Description "Management Inteface" -Group $mgmt_sg.GroupId
        $mgmt_attachment_id = Add-EC2NetworkInterface -DeviceIndex 1 -InstanceId $ec2_id -NetworkInterfaceId $mgmt_interface.NetworkInterfaceId
        Edit-EC2NetworkInterfaceAttribute -NetworkInterfaceId $mgmt_interface.NetworkInterfaceId -SourceDestCheck $false
        Edit-EC2NetworkInterfaceAttribute -NetworkInterfaceId $mgmt_interface.NetworkInterfaceId -Attachment_DeleteOnTermination $true -Attachment_AttachmentId $mgmt_attachment_id

        Complete-ASLifecycleAction -AutoScalingGroupName $AutoScalingGroupName -LifecycleActionResult 'CONTINUE' -LifecycleActionToken $LifecycleActionToken -LifecycleHookName $LifecycleHookName
    }

    if ($LifecycleTransition -eq "autoscaling:EC2_INSTANCE_TERMINATING") {
        $ec2 = Get-EC2Instance -region $region -InstanceId $ec2_id
        $instance_ip = $ec2.Instances[0].NetworkInterfaces[1].PrivateIpAddress
        Write-Host "log_ec_ip_address: $instance_ip"
        $panorama_https = $NotificationMetadata.panorama_server
        Write-Host "log_panorama_https: $panorama_https"
        $device_group = $NotificationMetadata.dgname
        Write-Host "log_device_group: $device_group"
        $template_stack = $NotificationMetadata.tplname
        Write-Host "log_template_stack: $template_stack"

        $apikey = Get-SECSecretValue -SecretId pan_api_key -region $region | Select-Object -ExpandProperty SecretString

        $devices = invoke-webrequest -SkipCertificateCheck -Uri "https://$panorama_https/api/?type=op&cmd=<show><devices><all></all></devices></show>&key=$apikey" | Select-Object -ExpandProperty content | Select-Xml -XPath '/response/result/devices'


        foreach ($device in $devices.node.entry) {
            $device_ip = $device."ip-address"
           
            ## Uncomment below for troubleshooting. Not commenting creates a lot of noise in log file, comment again once troubleshooting is completed.
            #Write-Host "log_device_IP_address: $device_ip "

            switch ($device_ip) {
            
                $instance_ip {
            
                    $serialnumber = $device.serial 
                    Write-Host "log_device_serialnumber" $serialnumber

                    $deactivate_license = Invoke-WebRequest -SkipCertificateCheck -Uri "https://$panorama_https/api/?type=op&cmd=<request><batch><license><deactivate><VM-Capacity><mode>auto</mode><devices>$serialnumber</devices></VM-Capacity></deactivate></license></batch></request>&key=$apikey"
                    Write-Host "log_deactivate_license: $deactivate_license"

                    $remove_from_dg = Invoke-WebRequest -SkipCertificateCheck -Uri "https://$panorama_https/api/?type=config&action=delete&xpath=/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='$device_group']/devices/entry[@name='$serialnumber']&key=$apikey" | Select-Object -ExpandProperty content | Select-Xml -XPath '/response'
                    Write-Host "removed $serialnumber from $device_group detail:" $remove_from_dg.Node.msg
            
                    $remove_from_tpl = Invoke-WebRequest -SkipCertificateCheck -Uri "https://$panorama_https/api/?type=config&action=delete&xpath=/config/devices/entry[@name='localhost.localdomain']/template-stack/entry[@name='$template_stack']/devices/entry[@name='$serialnumber']&key=$apikey" | Select-Object -ExpandProperty content | Select-Xml -XPath '/response'
                    Write-Host "removed $serialnumber from $remove_from_tpl detail:" $remove_from_tpl.Node.msg
            
                    $remove_from_pan = Invoke-WebRequest -SkipCertificateCheck -Uri "https://$panorama_https/api/?type=config&action=delete&xpath=/config/mgt-config/devices/entry[@name='$serialnumber']&key=$apikey" | Select-Object -ExpandProperty content | Select-Xml -XPath '/response'
                    Write-Host "removed $serialnumber from $panorama_https detail:" $remove_from_pan.Node.msg
            
                    Invoke-WebRequest -SkipCertificateCheck -Uri "https://$panorama_https/api/?type=commit&cmd=<commit></commit>&key=$apikey" | Select-Object -ExpandProperty content | Select-Xml -XPath '/response'
                
                }
            }
        }

        Complete-ASLifecycleAction -AutoScalingGroupName $AutoScalingGroupName -LifecycleActionResult 'CONTINUE' -LifecycleActionToken $LifecycleActionToken -LifecycleHookName $LifecycleHookName

    }
}

