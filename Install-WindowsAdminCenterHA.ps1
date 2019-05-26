<#########################################################################################################
 # File: Install-WindowsAdminCenterHA.ps1
 #
 # .DESCRIPTION
 #
 #  Install Windows Admin Center as HA service.
 #
 #  Copyright (c) Microsoft Corp 2017.
 #
 #########################################################################################################>

<#
.SYNOPSIS

Install Windows Admin Center as HA service.

.DESCRIPTION

The Install-WindowsAdminCenterHA.ps1 script installs sme on all nodes in failover cluster and create a generic service role for it.

.PARAMETER MsiPath
Specifies the path of the Windows Admin Center msi installer.

.PARAMETER CertPath
Specifies the path for ssl certificate.

.PARAMETER CertPassword
Specifies the password for ssl certificate.

.PARAMETER GenerateSslCert
Generates a self signed ssl certificate.

.PARAMETER ClusterStorage
Specifies the path to the cluster shared volume.

.PARAMETER ClientAccessPoint
Specifies the name for client access point.

.PARAMETER PortNumber
Specifies the ssl port number.

.PARAMETER StaticAddress
Specifies one or more static addresses for the cluster generic service.

.EXAMPLE
.\Install-WindowsAdminCenterHA.ps1 -MsiPath '.\ServerManagementGateway.msi' -GenerateSslCert -ClusterStorage C:\ClusterStorage\Volume1 -ClientAccessPoint smeha-1

.EXAMPLE
$certPassword = Read-Host -AsSecureString
.\Install-WindowsAdminCenterHA.ps1 -MsiPath '.\ServerManagementGateway.msi' -CertPath test.pfx -CertPassword $CertPassword -ClusterStorage C:\ClusterStorage\Volume1 -ClientAccessPoint smeha-1

#>

#Requires -RunAsAdministrator

[CmdletBinding(DefaultParameterSetName='Upgrade', SupportsShouldProcess=$true, ConfirmImpact="Medium")]
param (
    [Parameter(ParameterSetName='InstallSpecifyCert', Mandatory = $true)]
    [Parameter(ParameterSetName='InstallGenerateCert', Mandatory = $true)]
    [Parameter(ParameterSetName='Upgrade', Mandatory = $true)]
    [Parameter(ParameterSetName='UpgradeSpecifyCert', Mandatory = $true)]
    [Parameter(ParameterSetName='UpgradeGenerateCert', Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({
        if (Test-Path $_) {
            $true
        } else {
            throw "MsiPath '$_' is invalid or does not exist."
        }
    })]
    [String]
    $MsiPath = '.\ServerManagementGateway.msi',

    [Parameter(ParameterSetName='InstallSpecifyCert', Mandatory = $true)]
    [Parameter(ParameterSetName='UpgradeSpecifyCert', Mandatory = $true)]
    [Parameter(ParameterSetName='UpdateSpecifyCert', Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({
        if (Test-Path $_) {
            $true
        } else {
            throw "CertPath '$_' is invalid or does not exist."
        }
    })]
    [String]
    $CertPath,

    [Parameter(ParameterSetName='InstallSpecifyCert', Mandatory = $true)]
    [Parameter(ParameterSetName='UpgradeSpecifyCert', Mandatory = $true)]
    [Parameter(ParameterSetName='UpdateSpecifyCert', Mandatory = $true)]
    [SecureString]
    $CertPassword,

    [Parameter(ParameterSetName='InstallGenerateCert', Mandatory = $true)]
    [Parameter(ParameterSetName='UpgradeGenerateCert', Mandatory = $true)]
    [Parameter(ParameterSetName='UpdateGenerateCert', Mandatory = $true)]
    [ValidateSet($true)]
    [switch]
    $GenerateSslCert,

    [Parameter(ParameterSetName='InstallSpecifyCert', Mandatory = $true)]
    [Parameter(ParameterSetName='InstallGenerateCert', Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({
        if (Test-Path $_) {
            $true
        } else {
            throw "ClusterStorage path '$_' is invalid or does not exist."
        }
    })]
    [String]
    $ClusterStorage,

    [Parameter(ParameterSetName='InstallSpecifyCert', Mandatory = $true)]
    [Parameter(ParameterSetName='InstallGenerateCert', Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({
        if (Test-Connection $_ -Count 1 -Quiet) {
            throw "Client access point '$_' is already in use (can be pinged)."
        }
        #elseif (Resolve-DnsName $_ -ErrorAction SilentlyContinue) {
        #    throw  "Client access point '$_' is already registered in DNS."
        #}
        else {
            $true
        }
    })]
    [String]
    $ClientAccessPoint,

    [Parameter(ParameterSetName='InstallSpecifyCert', Mandatory = $false)]
    [Parameter(ParameterSetName='InstallGenerateCert', Mandatory = $false)]
    [int]
    $PortNumber = 443,

    [Parameter(ParameterSetName='InstallSpecifyCert', Mandatory = $false)]
    [Parameter(ParameterSetName='InstallGenerateCert', Mandatory = $false)]
    [String[]]
    $StaticAddress,

    [Parameter(ParameterSetName='Uninstall', Mandatory = $true)]
    [switch]
    $Uninstall
)

function Trace-Execution {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Message,

        [switch]
        $NoTimeStamp
    )

    if (-not $NoTimeStamp) {
        $Message = "$([DateTime]::Now.ToString("yyyy-MM-dd HH:mm:ss")) $Message"
    }

    Write-Verbose $Message
}

function Test-ShouldProcess {
    [CmdletBinding()]
    param (
        [string]
        $Message
    )
    
    $whatIf = (Get-PSCallStack).Arguments -join '' -match 'WhatIf=True'

    if ($whatIf) {
        Trace-Execution "WhatIf: $Message"
        return $false
    } else {
        Trace-Execution "$Message"
        return $true
    }
}

# Runs command as a scheduled task. The call returns as soon as command has started.
function Invoke-AsyncCommand {
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $ComputerName,

        [Parameter(Mandatory=$true)]
        [string]
        $TaskName,

        [Parameter(Mandatory=$true)]
        [string]
        $TaskPath,

        [Parameter(Mandatory=$true)]
        [string]
        $Execute,

        [Parameter(Mandatory=$false)]
        [string]
        $Argument
    )

    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        Import-Module ScheduledTasks
        $VerbosePreference = $using:VerbosePreference
        Write-Verbose "Unregister scheduled task '$using:TaskName', if it already exists." -Verbose:$using:clientVerbosePreference
        Get-ScheduledTask | ? TaskName -eq $using:TaskName | Unregister-ScheduledTask -Confirm:$false
        if ($using:Argument) {
            $action = New-ScheduledTaskAction -Execute $using:Execute -Argument:$using:Argument
        } else {
            $action = New-ScheduledTaskAction -Execute $using:Execute
        }
        Write-Verbose "Register scheduled task '$using:TaskName'." -Verbose:$using:clientVerbosePreference
        $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType S4U
        $task = Register-ScheduledTask -TaskName $using:TaskName -TaskPath $using:TaskPath -Action $action -Principal $principal -Force -Verbose:$false
        $startTime = [DateTime]::Now
        $secondsToStart = 10
        Write-Verbose "Start scheduled task '$using:TaskName'." -Verbose:$using:clientVerbosePreference
        $lastRunTime = $taskInfo.LastRunTime
        $taskHasStarted = $false
        $null = Start-ScheduledTask -InputObject $task
        while ([DateTime]::Now -lt $startTime.AddSeconds($secondsToStart)) {
            $taskInfo = Get-ScheduledTask | ?  TaskName -eq $using:TaskName | Get-ScheduledTaskInfo
            if ($taskInfo.LastRunTime -ne $lastRunTime) {
                Write-Verbose "Scheduled task '$using:TaskName' has started execution." -Verbose:$using:clientVerbosePreference
                $taskHasStarted = $true
                break
            }
        }
        if (-not $taskHasStarted) {
            Write-Error "Task '$using:TaskName' failed to start in $secondsToStart seconds."
        }
    }
}

function Install-WindowsAdminCenter {
    [CmdletBinding()]
    param (
        $certThumbprint, $PortNumber, $tempFolder, $certName, $CertPassword, [switch]$UseLocalMsi
    )

    $nodes = Get-ClusterNode

    foreach ($node in $nodes) {
        $computerName = $node.Name
        $installingMessage = "$script:msiMode Windows Admin Center on '$computerName'."
        Write-Host $installingMessage -ForegroundColor Green
        
        if (Test-ShouldProcess $installingMessage) {
            if ($certName) {
                Trace-Execution "Install certificate"
                Invoke-Command -ComputerName $computerName {
                    $null = Import-PfxCertificate -FilePath "$using:tempFolder\$using:certName" -Password $using:certPassword -CertStoreLocation Cert:\LocalMachine\My
                }
            }

            Trace-Execution "Start Windows Administration Center MSI install."
            $taskName = 'InstallWindowsAdminCenterHA'
            $wacProductInfo = Get-WmiObject Win32_Product -ComputerName $computerName | ? Name -eq $WAC_PRODUCT_NAME
            if ($UseLocalMsi) {
                $MsiPath = $wacProductInfo.LocalPackage
            } else {
                $MsiPath = "$tempFolder\ServerManagementGateway.msi"
            }
            $logPath = "$tempFolder\sme-$computerName.log"
            $msiArgumentString = "/qn /l*v `"$logPath`" SME_PORT=$PortNumber SSL_CERTIFICATE_OPTION=installed SME_THUMBPRINT=$certThumbprint SET_TRUSTED_HOSTS=`"*`""
            if ($wacProductInfo) {
                $msiArgumentString += " REINSTALLMODE=amus REINSTALL=ALL"
            }

            Trace-Execution "Start MSI install - $MsiPath $msiArgumentString"
            $asyncCommandParameters = @{
                ComputerName = $computerName
                TaskName = $taskName
                TaskPath = '\Microsoft\WindowsAdminCenter'
                Execute = $MsiPath
                Argument = $msiArgumentString
            }
            Invoke-AsyncCommand @asyncCommandParameters
        }
    }
    foreach ($node in $nodes) {
        $computerName = $node.Name
        $minutesToInstall = 10
        $waitingMessage = "Wait for $minutesToInstall minutes for MSI to install on $computerName."
        Write-Host $waitingMessage -ForegroundColor Green
        if (Test-ShouldProcess $waitingMessage) {
            $endTime = [DateTime]::Now.AddMinutes($minutesToInstall)
            $taskComplete = $null
            while ([DateTime]::Now -lt $endTime) {
                try {
                    $taskInfo = Invoke-Command -ComputerName $computerName {
                        Get-ScheduledTask | ? TaskName -eq $using:taskName | Get-ScheduledTaskInfo
                    }
                    Trace-Execution "Task last run result at $([DateTime]::Now.ToString('HH:mm:ss')) is $($taskInfo.LastTaskResult)"
                    if ($taskInfo.LastTaskResult -eq 0) {
                        $taskComplete = $true
                    }

                } catch {
                    # Ignoring exceptions as the remote call is expected break some time during WAC installation due to winrm reconfiguration.
                }
                if ($taskComplete) {
                    break
                }
                if ($taskInfo.LastTaskResult -eq 1603) {
                    Write-Error "MSI installation failed with the code 'Fatal Error During Installation' (1603)."
                }
                if ($taskInfo.LastTaskResult -eq 1618) {
                    Write-Error "MSI installation failed with the code ERROR_INSTALL_ALREADY_RUNNING (1618)."
                }
                if ($taskInfo.LastTaskResult -eq 1641) {
                    Write-Warning "You must restart your system for the configuration changes made to Windows Admin Center to take effect."
                    $taskComplete = $true
                    break
                }
                Start-Sleep -Seconds 10
            }

            if (-not $taskComplete) {
                Write-Error "Failed to install Windows Administration Center MSI on $computerName in $minutesToInstall minutes."
            }
        }
    
        if (Test-ShouldProcess "Change ServerManagementGateway service start mode to manual and stop the service.") {
            Invoke-Command -ComputerName $computerName {
                Set-Service ServerManagementGateway -StartupType Manual
            }
        }

        if (Test-ShouldProcess "Stop ServerManagementGateway service.") {
            Invoke-Command -ComputerName $computerName {
                Stop-Service ServerManagementGateway
            }
        }

        if (Test-ShouldProcess "Verify firewall rule was created.") {
            Invoke-Command -ComputerName $computerName {
                if (-not (Get-NetFirewallRule | ? DisplayName -eq SmeInboundOpenException)) {
                    Write-Verbose "Recreate firewall rule to allow inbound trafic." -Verbose:$using:clientVerbosePreference
                    $null = New-NetFirewallRule -DisplayName SmeInboundOpenException -Direction Inbound -LocalPort 443 -Protocol TCP -Action Allow -Description 'Windows Admin Center inbound port exception'
                }
            }
        }
    }
}

function Uninstall-WindowsAdminCenter {
    Write-Host "Uninstalling $WAC_PRODUCT_NAME." -ForegroundColor Green
   
    Trace-Execution "Get cluster resource for '$WAC_PRODUCT_NAME'."
    $wacClusterResource = Get-ClusterResource | ? Name -match $WAC_PRODUCT_NAME
    if ($wacClusterResource) {
        $ownerGroupName = $wacClusterResource.OwnerGroup.Name
        Trace-Execution "Remove cluster group $ownerGroupName."
        Remove-ClusterGroup $ownerGroupName -RemoveResources -Force
    }
    $nodeNames = Get-ClusterNode | % Name

    foreach ($nodeName in $nodeNames) {
        $uninstallMessage = "Uninstalling $WAC_PRODUCT_NAME on $nodeName."
        Write-Host $uninstallMessage -ForegroundColor Green
        if (Test-ShouldProcess $uninstallMessage) {
            Invoke-Command -ComputerName $nodeName -ScriptBlock {
                $queryResult = Get-WmiObject -Query "SELECT ProductCode FROM Win32_Property WHERE Property='UpgradeCode' AND Value='{af3e4932-2d63-46f8-a37f-b6acfd5378cd}'"
                if ($queryResult) {
                    $productCode = $queryResult.ProductCode
                    $app = Get-WmiObject Win32_Product -Filter "IdentifyingNumber='$productCode'"
                    if ($app) {
                        Write-Verbose "Running uninstall of $($app.Name)." -Verbose:$using:clientVerbosePreference
                        $app.UnInstall() | Out-Null
                    }
                }
                if (Test-Path $using:WAC_SETTINGS_REG_KEY) {
                    Write-Verbose "Remove registry settings at $using:WAC_SETTINGS_REG_KEY." -Verbose:$using:clientVerbosePreference
                    Remove-Item $using:WAC_SETTINGS_REG_KEY -Recurse
                }
            }
        }
    }
}

function Get-TempPassword {
    $length = 20
    $characterSet = [char]'0'..[char]'9' + [char]'A'..[char]'Z'
    $tempPassword = (1..$length | % {$characterSet | Get-Random} | % {[string][char]$_}) -join ''
    return $tempPassword
}

$ErrorActionPreference = "Stop"
$clientVerbosePreference = $VerbosePreference -ne 'SilentlyContinue'

$WAC_PRODUCT_NAME = 'Windows Admin Center'
$WAC_SETTINGS_REG_KEY = 'HKLM:\Software\Microsoft\ServerManagementGateway' 
$HA_SETTINGS_REG_KEY = "$WAC_SETTINGS_REG_KEY\ha"

if ($PSCmdlet.ParameterSetName -match 'Uninstall') {
    Uninstall-WindowsAdminCenter
    return
}

Trace-Execution "Selecting installation mode based on the specified parameters."
Write-Host "Installation mode is $($PSCmdlet.ParameterSetName)." -ForegroundColor Green

# $msiMode variable is used to provide descriptive messages on the way the MSI package gets applied - installing, upgrading, or just updating certificates.
if ($PSCmdlet.ParameterSetName -match 'Install') {
    $script:msiMode = 'Installing'
} elseif ($PSCmdlet.ParameterSetName -match 'Upgrade') {
    $script:msiMode = 'Upgrading'
} else {
    $script:msiMode = 'Updating'
}

if ($ClientAccessPoint) {
    # Assigning this parameter to a local variable to avoid parameter validation, when/if this value is modified.
    $accessPoint = $ClientAccessPoint
}

Trace-Execution "Get cluster resource for '$WAC_PRODUCT_NAME'."
$wacClusterResource = Get-ClusterResource | ? Name -match $WAC_PRODUCT_NAME

if ($wacClusterResource -or ($PSCmdlet.ParameterSetName -match 'Upgrade') -or ($PSCmdlet.ParameterSetName -match 'Update')) {
    if (-not $wacClusterResource) {
        Write-Error "Upgrade failed, reason - '$WAC_PRODUCT_NAME' cluster resource does not exist."
    }
    $ownerGroup = $wacClusterResource.OwnerGroup
    $ownerNodeName = $ownerGroup.OwnerNode.Name
    Trace-Execution "Retrieve gateway settings of the previous installation."
    $haSettings = Invoke-Command -ComputerName $ownerNodeName {
        Get-ItemProperty $using:HA_SETTINGS_REG_KEY
    }
    if (-not $haSettings) {
        Write-Error "Failed to retrieve gateway settings of the previous installation from $ownerNodeName, registry key '$HA_SETTINGS_REG_KEY'."
    }
    $storagePath = $haSettings.StoragePath
    Trace-Execution "StoragePath = $storagePath"
    $certThumbprint = $haSettings.Thumbprint
    Trace-Execution "Thumbprint = $certThumbprint"
    Trace-Execution "Port = $($haSettings.Port)"
    Trace-Execution "ClientAccessPoint = $($haSettings.ClientAccessPoint)"
    if ($haSettings.StaticAddress) {
        Trace-Execution "StaticAddress = $StaticAddress"
    } else {
        Trace-Execution "StaticAddress is not defined."
    }

    # Settings passed from parameters override values stored in registry.
    if (-not $ClusterStorage) {
        $ClusterStorage = (Get-Item $storagePath).Parent.FullName
    }
    Trace-Execution "ClusterStorage value to be used - $ClusterStorage"
    if (-not $accessPoint) {
        $accessPoint = $haSettings.ClientAccessPoint
    }
    Trace-Execution "ClientAccessPoint value to be used - $accessPoint"
    if (-not $PortNumber) {
        $PortNumber = $haSettings.Port
    }
    Trace-Execution "Port value to be used - $PortNumber"
    if (-not $StaticAddress) {
        $StaticAddress = $haSettings.StaticAddress.Split(',')
    }
    Trace-Execution "StaticAddress value to be used - $StaticAddress"

    if (Test-ShouldProcess "Remove cluster group for the previous installation - $accessPoint.") {
        Remove-ClusterGroup $haSettings.ClientAccessPoint -RemoveResources -Force
    }
}

$matchingClusterVolume = Get-ClusterSharedVolume | ForEach-Object -WhatIf:$false SharedVolumeInfo | ForEach-Object -WhatIf:$false FriendlyVolumeName | ? {$ClusterStorage -like "$_*"}

if (-not $matchingClusterVolume) {
    Write-Error "Specified cluster storage '$ClusterStorage' does not belong to a cluster shared volume."
}

$tempFolder = "$ClusterStorage\temp"
Trace-Execution "Create temporary folder for the installation - '$tempFolder'."
$null = New-Item $tempFolder -Type Directory -Force

if ($PSCmdlet.ParameterSetName -match 'Cert') {
    if ($GenerateSslCert) {
        Trace-Execution "Creating self-signed certificate."
        $domain = (Get-WmiObject win32_computersystem).Domain
        $dnsName = "$accessPoint.$domain"
        $cert = New-SelfSignedCertificate -DnsName $dnsName -CertStoreLocation "cert:\LocalMachine\My" -NotAfter (Get-Date).AddMonths(3) -WhatIf:$false
        $tmpPassword = Get-TempPassword
        $CertPassword = ConvertTo-SecureString -String $tmpPassword -Force -AsPlainText
        $certificatePath = "$PSScriptRoot\sme.pfx"
        $null = $cert | Export-PfxCertificate -FilePath $certificatePath -Password $CertPassword -WhatIf:$false
    } else{
        $certificatePath = Resolve-Path $CertPath
        Trace-Execution "Import certificate from '$certificatePath'."
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $cert.Import($certificatePath, $CertPassword, 'DefaultKeySet')
    }

    $certName = Split-Path $certificatePath -Leaf
    $certThumbprint = $cert.Thumbprint
    Trace-Execution "Certificate thumbprint to be used - '$certThumbprint'."

    Trace-Execution "Copy certificate file to the temporary shared folder."
    Copy-Item -Path $certificatePath -Destination $tempFolder -Force
}

$nodes = Get-ClusterNode

if ($PSCmdlet.ParameterSetName -notmatch 'Update') {
    Trace-Execution "Copy installation file to the temporary shared folder."
    Copy-Item -Path $MsiPath -Destination "$tempFolder\ServerManagementGateway.msi" -Force
}

if ($PSCmdlet.ParameterSetName -match 'Cert') {
    if ($PSCmdlet.ParameterSetName -match 'Update') {
        Install-WindowsAdminCenter $certThumbprint $PortNumber $tempFolder $certName $CertPassword -UseLocalMsi
    } else {
        Install-WindowsAdminCenter $certThumbprint $PortNumber $tempFolder $certName $CertPassword
    }
} else {
    Install-WindowsAdminCenter $certThumbprint $PortNumber $tempFolder
}

Write-Host "Configuring Windows Admin Center gateway." -ForegroundColor Green

if (Test-ShouldProcess "Adding Cluster Generic Service Role '$accessPoint'") {
    if ($StaticAddress) {
        $role = Add-ClusterGenericServiceRole -ServiceName ServerManagementGateway -Name $accessPoint -CheckpointKey "SOFTWARE\Microsoft\ServerManagementGateway\Ha" -StaticAddress $StaticAddress
    } else {
        $role = Add-ClusterGenericServiceRole -ServiceName ServerManagementGateway -Name $accessPoint -CheckpointKey "SOFTWARE\Microsoft\ServerManagementGateway\Ha"
    }
}

$ownerNodeName = $role.OwnerNode.Name
if (Test-ShouldProcess "Configure $WAC_PRODUCT_NAME on the owner node $ownerNodeName.") {
    $smePath = "$ClusterStorage\Server Management Experience"
    $command = { 
        param (
            $smePath, $certThumbprint, $PortNumber, $accessPoint, $StaticAddress
        )

        Write-Verbose "Copying files to cluster storage: $smePath" -Verbose:$using:clientVerbosePreference
        $uxFolder = "$smePath\Ux"
        if (Test-Path $uxFolder) {
            Remove-Item $uxFolder -Force -Recurse
        }
        New-Item -Path $uxFolder -ItemType Directory | Out-Null

        Copy-Item -Path "$env:programdata\Server Management Experience\Ux" -Destination $smePath -Recurse -Container -Force

        Write-Verbose "Saving settings to registry: $using:HA_SETTINGS_REG_KEY" -Verbose:$using:clientVerbosePreference
        $registryPath = $using:HA_SETTINGS_REG_KEY
        $null = New-Item -Path $registryPath -Force
        New-ItemProperty -Path $registryPath -Name IsHaEnabled -Value "true" -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $registryPath -Name StoragePath -Value $smePath -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $registryPath -Name Thumbprint -Value $certThumbprint -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $registryPath -Name Port -Value $PortNumber -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $registryPath -Name ClientAccessPoint -Value $accessPoint -PropertyType String -Force | Out-Null
        $StaticAddressValue = $StaticAddress -join ','
        New-ItemProperty -Path $registryPath -Name StaticAddress -Value $StaticAddress -PropertyType String -Force | Out-Null
    
        Write-Verbose "Grant permissions to Network Service for the UX folder." -Verbose:$using:clientVerbosePreference
        $Acl = Get-Acl $uxFolder
	    $sID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-20")
        $Ar = New-Object  system.security.accesscontrol.filesystemaccessrule($sID, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $Acl.SetAccessRule($Ar)
        Set-Acl $uxFolder $Acl

        Write-Verbose "Restart ServerManagementGateway service." -Verbose:$using:clientVerbosePreference
        Restart-Service ServerManagementGateway
    }

    Invoke-Command -ComputerName $ownerNodeName -ScriptBlock $command -ArgumentList $smePath, $certThumbprint, $PortNumber, $accessPoint, $StaticAddress
}

Trace-Execution "Installation is complete."
