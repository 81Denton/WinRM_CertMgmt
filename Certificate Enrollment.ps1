#Requires -Version 4

<# error codes
0 - success
1 - invalid cert (expired / name mismatch)
3 - no cert available to enable https
4 - misc error
#>

# Original author: Stephen Owen (https://github.com/1RedOne // https://github.com/1RedOne/WinRM_CertMgmt)

# Prerequisites:
# PowerShell Version 4
# WinRM: Firewall exception (5986 TCP) and WinRM service set to auto start

# Changelog
# 2020-03-30 added exit code 0 and log message if listener gets updated to use a longer cert.
#   if listener exists, it gets deleted and added instead of modified (prevents errors if existing listener contains a bad hostname).
#   fixed new listener creation to create a new listener with the correct cert instead of using winrm quickconfig. misc grammar and formatting changes.

# TODO
# Test if 'setspn' is required
# Add separate error code for expired cert
# Write logs to windows event log instead of local file
# Add error feedback for 'Requires -Version 4' that can be fed into another script that updates PS versions
# Replace 'Invoke-Expression' with powershell equivalents


#region setup logging
function Write-Log {
    param(
        [int]$ErrorLevel=1, # 1 - info, 2 - warning, 3 - error, 4 - misc
        [Parameter(position=1,ValueFromPipeline=$true)][string]$Msg,
        [Parameter(position=2)][string]$Component, # source of the entry
        [Parameter(position=3)][string]$LogFile = "$env:windir\temp\LPUlog.log",
        [switch]$break,
        [switch]$tee
    )

    if( !$Component ){ $Component = $PSCommandPath -replace '^.*\\|\.[^\.]*$' } # script name
    if( !$LogFile ){ $LogFile = $PSCommandPath -replace '\.ps1$','.log' } # <ScriptRoot>\<ScriptName>.log
    if($break){$Msg='#############################################################'}
    if($tee){Write-Output $msg}
    $TZBias = (Get-WmiObject Win32_TimeZone).bias
    $Time = "$(Get-Date -Format 'HH:mm:ss.fff')$TZBias"
    $Date = Get-Date -Format 'MM-dd-yyyy'
    $Context = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    $LogEntry = "<![LOG[$Msg]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"$Context`" type=`"$ErrorLevel`" thread=`"$pid`" file=`"`">"

    Add-Content -Path $LogFile -Value $LogEntry

}
#endregion

#get fqdn
$fqdn = [System.Net.Dns]::GetHostByName(($env:ComputerName)).HostName.ToLower()
#check if listener already exists
$listener = Get-ChildItem WSMan:\localhost\Listener | Where-Object Keys -like *https*

if ($listener){
    #Listener already exists, verify it's using an appropriate certificate (matching subject, server EKU, not self signed), and the cert with the longest possible validity period

    #Resolve the HTTPs listener name
    $ListenerName = Get-ChildItem WSMan:\localhost\Listener | Where-Object Keys -like *https* | Select-Object -expand Name

    #Get the WINRM HTTPS listener certificate thumbprint
    $CertThumbprt =  (Get-ChildItem "WSMan:\localhost\Listener\$ListenerName" | Where-Object Name -like "CertificateThumbprint" | Select-Object -ExpandProperty Value) -replace " ",""

    #Compare that to our longest cert...

    #grabs the longest lasting cert availble for SSL
    $LongestValidCertThmbprt = Get-ChildItem cert:\localmachine\My | Where-Object EnhancedKeyUsageList -like "*(1.3.6.1.5.5.7.3.1)*"  | Where-Object Subject -like *$env:COMPUTERNAME* |
        Where-Object Issuer -NotLike *$($ENV:COMPUTERNAME)* | Sort-Object NotAfter -Descending | Select-Object -ExpandProperty ThumbPrint | Select-Object -First 1

    write-log "Found existing listener using a valid certificate. Checking if certificate store contains a cert with a longer validity period. Result: $($LongestValidCertThmbprt -eq $CertThumbprt)" -tee

    #Are we using the longest cert we could? If so, we've got nothing to do, time to quit
    If ($LongestValidCertThmbprt -eq $CertThumbprt){
        #we're done
        Write-Log "This machine is using the longest possible cert for SSL. Exiting with errorlevel 0." -tee
        exit 0
    }

    #Is $CertThumbPrt or $LongestValidCertThmbprt actually nonexistant?
    if (($LongestValidCertThmbprt -eq $null) ) {
        #! Error condition: listener is enabled, but not using a valid cert
        Write-Log "!error condition: This machine doesn't have a valid cert anymore (maybe it changed names or domains?). Exiting with errorlevel 1." -tee
        exit 1

        #later : try to renew a cert (Get-Certficate)

    }

    #Do we have a longer cert available and we're not using it?  Let's fix that
    If ($LongestValidCertThmbprt -ne $CertThumbprt){

        #remove current listener and create a new one using the longest valid cert
        Remove-WSManInstance -ResourceURI winrm/config/listener -SelectorSet @{Address="*";Transport="HTTPS"}
        New-WSManInstance -ResourceURI winrm/config/listener -SelectorSet @{Address="*";Transport="HTTPS"} -ValueSet @{Hostname=$fqdn;CertificateThumbprint=$LongestValidCertThmbprt}
        Write-Log "WinRM HTTPS listener has been updated to use a certificate with a longer validity period. Exiting with errorlevel 0." -tee
        exit 0
    }

}
else{
    #if no listener...

    #attempts to find a certificate suitable for Client Authentication for this system, and picks the one with the longest date
    $LongestValidCert = Get-ChildItem cert:\localmachine\My | Where-Object EnhancedKeyUsageList -like "*(1.3.6.1.5.5.7.3.1)*" |
        Where-Object Subject -like *$env:COMPUTERNAME* | Where-Object Issuer -NotLike *$($ENV:COMPUTERNAME)* | Sort-Object NotAfter -Descending |
        Select-Object -First 1

    #region errorconditions
        #if LongestValidCert is empty, then we can't setup a listener, lets #exit
        If ($LongestValidCert -eq $null){
            Write-Log -Msg "!error condition: no valid cert to enable a listener (no cert or name mismatch). Exiting with errorlevel 3." -tee
            exit 3
        }

        #cert has expired
        if ($LongestValidCert.NotAfter -le (Get-Date)){
            #! error condition: Certificate has expired
            Write-Log -Msg "!error condition: The only valid cert available has expired. Exiting with errorlevel 1." -tee

            #Renew cert steps go here
            exit 1
        }
    #endregion

    #We have a valid cert, enabling WinRM over HTTPS
    New-WSManInstance -ResourceURI winrm/config/listener -SelectorSet @{Address="*";Transport="HTTPS"} -ValueSet @{Hostname=$fqdn;CertificateThumbprint=$LongestValidCert.Thumbprint} -ErrorVariable winRMerror | Out-Null
    if ($WinrmError){
       #! error condition: winrm quickconfig failed for some reason
       Write-Log "!error condition: error occurred during WinRM HTTPS listener creation. Exiting with errorlevel 4." -tee
       Write-Log "!error text $WinrmError"
       exit 4
    }
    # remove the following else block if you uncomment the setspn block
    else {
        Write-Log "WinRM HTTPS listener has been created successfully, using an existing certificate. Exiting with errorlevel 0." -tee
        exit 0
    }

    # Code below is commented out since I couldn't find any reasons why creating an HTTPS SPN on top of the existing WSMAN SPN is neccessary

    #We need to create a service record to tell the domain we're listening on https, let's do that below
    # $fqdn = [System.Net.Dns]::GetHostByName(($env:ComputerName)).HostName.ToLower()
    # $SPNoutput = Invoke-Expression "setspn -S HTTPS/$fqdn $($env:COMPUTERNAME)" -ErrorVariable spnerror

    # #test for https record in output of prev cmd
    # if ($out = $SPNoutput | select-string HTTPS) {
    #     Write-Log "success!  SPN seems to have been created, output [$($out.ToString().Trim())]" -tee
    #     Write-Log "output from SPN command $SPNoutput"
    #     exit 0
    # }else{
    #     Write-Log "!error condition: failed to create SPN! output [$SPNoutput] error [$SPNerror]" -tee
    #     Write-Log "!error condition: exiting with errorlevel 4" -tee
    #     exit 4
    # }

}