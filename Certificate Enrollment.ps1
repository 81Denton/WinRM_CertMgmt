<#
    .SYNOPSIS
        Is used to install or refresh an HTTPS WSMan Listener on a computer with a valid certificate.
    .DESCRIPTION
        This script is designed to be called from a Startup/Logon PowerShell GPO.
        If multiple valid certificates are present in the local cert store, it will pick the one with the longest validity period.
        This script does not handle basic WinRM setup such as adding a firewall exception (5986 TCP) or setting the WinRM service to auto start.
        Prerequisites:
            PowerShell version 4
    .OUTPUTS
        Log file stored in '$env:windir\temp\LPUlog.log'.
    .NOTES
        Original script by: Stephen Owen (https://github.com/1RedOne // https://github.com/1RedOne/WinRM_CertMgmt)
        Modifications by: https://github.com/81Denton
        TODO
            Test if 'setspn' is required
            Add separate error code for expired cert
            Write logs to windows event log (ELK compatible) instead of local file
            Add error feedback for 'Requires -Version 4' that can be fed into another script that updates PS versions
            Replace 'Invoke-Expression' with powershell equivalents
        Changelog
        2020-03-30: added exit code 0 and log message if listener gets updated to use a longer cert.
            if listener exists, it gets deleted and added instead of modified (prevents errors if existing listener contains a bad hostname).
            fixed new listener creation to create a new listener with the correct cert instead of using winrm quickconfig. misc grammar and formatting changes.
        2020-03-31: made log time formatting less verbose. addded cert thumbprints to logs
#>

#Requires -Version 4
#Requires -RunAsAdministrator

function Write-Log {

    <# error codes
0 - success
1 - invalid cert (expired / name mismatch)
3 - no cert available to enable https
4 - misc error
#>

    param(
        [int]$ErrorLevel=1, #1 - info, 2 - warning, 3 - error, 4 - misc
        [Parameter(position=1,ValueFromPipeline=$true)][string]$Msg,
        [Parameter(position=2)][string]$Component, #source of the entry
        [Parameter(position=3)][string]$LogFile = "$env:windir\temp\LPUlog.log",
        [switch]$break,
        [switch]$tee
    )

    if(!$Component){$Component = $PSCommandPath -replace '^.*\\|\.[^\.]*$'} #script name
    if(!$LogFile){$LogFile = $PSCommandPath -replace '\.ps1$','.log'} #<ScriptRoot>\<ScriptName>.log
    if($break){$Msg='#############################################################'}
    if($tee){Write-Output $msg}
    $Time = Get-Date -Format 'HH:mm:ss.ff'
    $Date = Get-Date -Format 'yyyy-MM-dd'
    $Context = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    $LogEntry = "<![LOG[$Msg]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"$Context`" type=`"$ErrorLevel`" thread=`"$pid`" file=`"`">"

    Add-Content -Path $LogFile -Value $LogEntry
}

#Get the host FQDN
$fqdn = [System.Net.Dns]::GetHostByName(($env:ComputerName)).HostName.ToLower()
#Check if WinRM HTTPS listener already exists
$listener = Get-ChildItem WSMan:\localhost\Listener | Where-Object Keys -like *https*

if ($listener){
    #Listener already exists, verify that it's using:
    #1) a valid certificate: matching subject, server authetication EKU, not self signed, not expired
    #2) the cert with the longest possible validity period

    #Resolve the HTTPS listener name
    $ListenerName = Get-ChildItem WSMan:\localhost\Listener | Where-Object Keys -like *https* | Select-Object -expand Name

    #Get the WINRM HTTPS listener certificate thumbprint
    $CertThumbprt =  (Get-ChildItem "WSMan:\localhost\Listener\$ListenerName" | Where-Object Name -like "CertificateThumbprint" | Select-Object -ExpandProperty Value) -replace " ",""

    #compare the currently used cert to the longest lasting cert availble for SSL
    $LongestValidCertThmbprt = Get-ChildItem cert:\localmachine\My | Where-Object EnhancedKeyUsageList -like "*(1.3.6.1.5.5.7.3.1)*"  | Where-Object Subject -like *$env:COMPUTERNAME* |
        Where-Object Issuer -NotLike *$($ENV:COMPUTERNAME)* | Sort-Object NotAfter -Descending | Select-Object -ExpandProperty ThumbPrint | Select-Object -First 1

    write-log "Found existing listener using a valid certificate '$CertThumbprt'. Checking if certificate store contains a cert with a longer validity period. Result: $($LongestValidCertThmbprt -eq $CertThumbprt)" -tee

    #Are we using the longest cert we could? If so, we've got nothing to do, time to quit
    If ($LongestValidCertThmbprt -eq $CertThumbprt){
        Write-Log "This machine is already using the certificate with the longest validity period. Exiting with errorlevel 0." -tee
        exit 0
    }

    #Is there no certificate that satisfies the conditions for $LongestValidCertThmbprt?
    #! Error condition:
    #1) listener is enabled
    #2) listener is using an invalid cert (expired, name mismatch, self signed)
    #3) there is no valid cert available in cert store
    if (($LongestValidCertThmbprt -eq $null) ) {
        Write-Log "!error condition: This machine's WinRM HTTPS listener is configured with an invalid certificate (expiration, name mismatch etc.); no other valid certificates are available. Exiting with errorlevel 1." -tee
        exit 1
    }

    #Do we have a longer cert available and we're not using it?  Let's fix that
    If ($LongestValidCertThmbprt -ne $CertThumbprt){
        #Remove current listener and create a new one using the longest valid cert
        Remove-WSManInstance -ResourceURI winrm/config/listener -SelectorSet @{Address="*";Transport="HTTPS"}
        New-WSManInstance -ResourceURI winrm/config/listener -SelectorSet @{Address="*";Transport="HTTPS"} -ValueSet @{Hostname=$fqdn;CertificateThumbprint=$LongestValidCertThmbprt}
        Write-Log "WinRM HTTPS listener has been updated to use a certificate with a longer validity period. Old: '$CertThumbprt' New: '$LongestValidCertThmbprt'. Exiting with errorlevel 0." -tee
        exit 0
    }

}

else{
    #No WinRM HTTPS listener exists

    #Attempts to find a suitable certificate and picks the one with the longest validity period
    #Identical to the conditions required for $LongestValidCertThmbprt
    $LongestValidCert = Get-ChildItem cert:\localmachine\My | Where-Object EnhancedKeyUsageList -like "*(1.3.6.1.5.5.7.3.1)*" |
        Where-Object Subject -like *$env:COMPUTERNAME* | Where-Object Issuer -NotLike *$($ENV:COMPUTERNAME)* | Sort-Object NotAfter -Descending |
        Select-Object -First 1

        #If LongestValidCert is empty, then we can't set up a listener, let's exit
        If ($LongestValidCert -eq $null){
            Write-Log -Msg "!error condition: No valid certificate available to enable a listener. Exiting with errorlevel 3." -tee
            exit 3
        }

        #Cert has expired
        if ($LongestValidCert.NotAfter -le (Get-Date)){
            Write-Log -Msg "!error condition: The only valid certificate available has expired. Exiting with errorlevel 1." -tee
            exit 1
        }

    #Valid cert is available, enabling WinRM over HTTPS
    New-WSManInstance -ResourceURI winrm/config/listener -SelectorSet @{Address="*";Transport="HTTPS"} -ValueSet @{Hostname=$fqdn;CertificateThumbprint=$LongestValidCert.Thumbprint} -ErrorVariable winRMerror | Out-Null
    if ($WinrmError){
       #! error condition: WinRM HTTPS listener creation failed
       Write-Log "!error condition: Error occurred during listener creation. Exiting with errorlevel 4." -tee
       Write-Log "!error text: $WinrmError"
       exit 4
    }
    #Remove the following else{} block if you uncomment the setspn block
    else {
        $LongestValidCertThmbprt = $LongestValidCert.Thumbprint
        Write-Log "WinRM HTTPS listener has been created successfully, using an existing certificate with thumbprint '$LongestValidCertThmbprt'. Exiting with errorlevel 0." -tee
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