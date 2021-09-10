import-module AWS.Tools.Common -MinimumVersion 4.1.14.0
import-Module AWSLambdaPSCore

New-AWSPowerShellLambdaPackage -ScriptPath "$PSScriptRoot\manage_asg.ps1" `
-OutputPackage "$PSScriptRoot\manage_asg.zip" -Verbose