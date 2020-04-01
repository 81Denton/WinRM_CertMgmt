<#
    .SYNOPSIS
        Is used to install or refresh an HTTPS WSMan Listener on a computer with a valid certificate.
    .DESCRIPTION
        This script is designed to be called from a Startup/Logon PowerShell GPO.
        If multiple valid certificates are present in the local cert store, it will pick the one with the longest validity period.
        This script does not handle basic WinRM setup such as adding a firewall exception (5986 TCP) or setting the WinRM service to auto start.
        Prerequisites:
            PowerShell version 4 (WMF 4 is compatible with Windows Server 2008 R2 and above)
    .OUTPUTS
        Logs are written to the Windows Application log with a custom soruce named 'WinRM-HTTPS-Setup'.
    .NOTES
        Original script by: Stephen Owen (https://github.com/1RedOne // https://github.com/1RedOne/WinRM_CertMgmt)
        Modifications by: https://github.com/81Denton

        Changelog:
        v1.1        2020-03-30
            added exit code 0 and log message if listener gets updated to use a longer cert.
            if listener exists, it gets deleted and added instead of modified (prevents errors if existing listener contains a bad hostname).
            fixed new listener creation to create a new listener with the correct cert instead of using winrm quickconfig.
            misc grammar and formatting changes.
        v1.2        2020-03-31
            made log time formatting less verbose. addded cert thumbprints to logs
            added #Requires -RunAsAdministrator
        v1.3        2020-04-01
            replaced Write-Log with New-EventLog to use win event logs for logging
#>

#Requires -Version 4
#Requires -RunAsAdministrator

#global defines
$CustomSourceName = "WinRM-HTTPS-Setup"
$EventID = 31337
$fqdn = [System.Net.Dns]::GetHostByName(($env:ComputerName)).HostName.ToLower()

#Register new event log source 'WinRM-HTTPS-Setup' to the Windows Application log
try{
    if(([System.Diagnostics.EventLog]::SourceExists($CustomSourceName))){
        Write-Verbose "Event log source '$CustomSourceName' already exists."
    }else{
        #New-EventLog –LogName Application –Source "$CustomSourceName"
        [System.Diagnostics.EventLog]::CreateEventSource($CustomSourceName, 'Application')
        Write-Verbose "Created log source '$CustomSourceName' in the 'Application' log."
    }
}catch{
    Write-Error "FATAL ERROR: Could not create or check for the log source '$CustomSourceName'. Ending script execution" -ErrorAction Stop
}

#Check if WinRM HTTPS listener already exists
$listener = Get-ChildItem WSMan:\localhost\Listener | Where-Object Keys -like *https*
if ($listener){
    #Listener already exists, verify that it's using:
    #1) a valid certificate: matching subject, server authentication present in EKU, not self signed, not expired
    #2) the cert with the longest possible validity period

    #Resolve the HTTPS listener name
    $ListenerName = Get-ChildItem WSMan:\localhost\Listener | Where-Object Keys -like *https* | Select-Object -expand Name

    #Get the WINRM HTTPS listener certificate thumbprint
    $CertThumbprt =  (Get-ChildItem "WSMan:\localhost\Listener\$ListenerName" | Where-Object Name -like "CertificateThumbprint" | Select-Object -ExpandProperty Value) -replace " ",""

    #Compare the currently used cert to the longest lasting cert availble for SSL
    $LongestValidCertThmbprt = Get-ChildItem cert:\localmachine\My | Where-Object EnhancedKeyUsageList -like "*(1.3.6.1.5.5.7.3.1)*"  | Where-Object Subject -like *$env:COMPUTERNAME* |
        Where-Object Issuer -NotLike *$($ENV:COMPUTERNAME)* | Sort-Object NotAfter -Descending | Select-Object -ExpandProperty ThumbPrint | Select-Object -First 1

    Write-EventLog -LogName Application -Source $CustomSourceName -EntryType Information -EventId $EventID -Message "Found existing listener using a valid certificate '$CertThumbprt'. Checking if certificate store contains a cert with a longer validity period. Result: $($LongestValidCertThmbprt -eq $CertThumbprt). Context: '$ENV:USERNAME'."

    #Are we using the longest cert we could? If so, we've got nothing to do, time to quit
    If ($LongestValidCertThmbprt -eq $CertThumbprt){
        Write-EventLog -LogName Application -Source $CustomSourceName -EntryType Information -EventId $EventID -Message "This machine is already using the certificate with the longest validity period. Finishing script execution. Context: '$ENV:USERNAME'."
        exit 0
    }

    #Is there no certificate that satisfies the conditions for $LongestValidCertThmbprt?
    #! Error condition:
    #1) listener is enabled
    #2) listener is using an invalid cert (expired, name mismatch, self signed)
    #3) there is no valid cert available in cert store
    if (($LongestValidCertThmbprt -eq $null) ) {
        Write-EventLog -LogName Application -Source $CustomSourceName -EntryType Error -EventId $EventID -Message "This machine's WinRM HTTPS listener is configured with an invalid certificate (expiration, name mismatch etc.); no other valid certificates are available. Aborting script execution. Context: '$ENV:USERNAME'."
        exit 1
    }

    #Do we have a longer cert available and we're not using it?  Let's fix that
    If ($LongestValidCertThmbprt -ne $CertThumbprt){
        #Remove current listener and create a new one using the longest valid cert
        Remove-WSManInstance -ResourceURI winrm/config/listener -SelectorSet @{Address="*";Transport="HTTPS"}
        New-WSManInstance -ResourceURI winrm/config/listener -SelectorSet @{Address="*";Transport="HTTPS"} -ValueSet @{Hostname=$fqdn;CertificateThumbprint=$LongestValidCertThmbprt}
        Write-EventLog -LogName Application -Source $CustomSourceName -EntryType Information -EventId $EventID -Message "WinRM HTTPS listener has been updated to use a certificate with a longer validity period. Old: '$CertThumbprt' New: '$LongestValidCertThmbprt'. Finishing script execution. Context: '$ENV:USERNAME'."
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
            Write-EventLog -LogName Application -Source $CustomSourceName -EntryType Error -EventId $EventID -Message "No valid certificate available to enable a listener. Aborting script execution. Context: '$ENV:USERNAME'."
            exit 1
        }

        #Cert has expired
        if ($LongestValidCert.NotAfter -le (Get-Date)){
            Write-EventLog -LogName Application -Source $CustomSourceName -EntryType Error -EventId $EventID -Message "!error condition: The only valid certificate available has expired. Aborting script execution. Context: '$ENV:USERNAME'."
            exit 1
        }

    #Valid cert is available, enabling WinRM over HTTPS
    New-WSManInstance -ResourceURI winrm/config/listener -SelectorSet @{Address="*";Transport="HTTPS"} -ValueSet @{Hostname=$fqdn;CertificateThumbprint=$LongestValidCert.Thumbprint} -ErrorVariable winRMerror | Out-Null
    if ($WinrmError){
       #! error condition: WinRM HTTPS listener creation failed
       Write-EventLog -LogName Application -Source $CustomSourceName -EntryType Error -EventId $EventID -Message "!error condition: Error occurred during listener creation. Aborting script execution. Context: '$ENV:USERNAME'."
       Write-Log "!error text: $WinrmError"
       exit 1
    }
    #Remove the following else{} block if you uncomment the setspn block
    else {
        $LongestValidCertThmbprt = $LongestValidCert.Thumbprint
        Write-EventLog -LogName Application -Source $CustomSourceName -EntryType Information -EventId $EventID -Message "WinRM HTTPS listener has been created successfully, using an existing certificate with thumbprint '$LongestValidCertThmbprt'. Context: '$ENV:USERNAME'."
        exit 0
    }

    # Code below is commented out since I couldn't find any reasons why creating an HTTPS SPN on top of the existing WSMAN SPN is neccessary

    #We need to create a service record to tell the domain we're listening on https, let's do that below
    # $fqdn = [System.Net.Dns]::GetHostByName(($env:ComputerName)).HostName.ToLower()
    # $SPNoutput = Invoke-Expression "setspn -S HTTPS/$fqdn $($env:COMPUTERNAME)" -ErrorVariable spnerror

    # #test for https record in output of prev cmd
    # if ($out = $SPNoutput | select-string HTTPS) {
    #     Write-EventLog -LogName Application -Source $CustomSourceName -EntryType Information -EventId $EventID -Message "success!  SPN seems to have been created, output [$($out.ToString().Trim())]"
    #     Write-EventLog -LogName Application -Source $CustomSourceName -EntryType Information -EventId $EventID -Message "output from SPN command $SPNoutput"
    #     exit 0
    # }else{
    #     Write-EventLog -LogName Application -Source $CustomSourceName -EntryType Error -EventId $EventID -Message "!error condition: failed to create SPN! output [$SPNoutput] error [$SPNerror]"
    #     exit 1
    # }

}