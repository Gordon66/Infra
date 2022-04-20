<#
   .SYNOPSIS
        Script for creating report files for Active Directory Federeation Services Farm 
   .DESCRIPTION
        Script for creating report files for Active Directory Federeation Services Farm 

        Get-ADFSOverview  - exports details on general ADFS farm configuration 
        Server-Report - exports HW and OS  details of ADFS farm servers 
        Get-RPOverview - exports details on relying parties configured in ADFS farm 
        Get-CPOverview - exports details on claim providers configured in ADFS farm 
        GET-WSUSDetails - exports ADFS farm servers details on their WSUS(Update server) registrations 
        Get-ADFSuptime -  exports ADFS farm servers details on last reboots and running times 

        Constrains:
              You have to run the script on a ADFS farm node as an administrator in order to read ADFS farm proprties.  
                
    .INPUTS 
        
    .PARAMETER  global:DNSroot
        defines the root of the active directory domain of the ADFS farm

    .PARAMETER  global:RootFolder
        define folder path for oputput files
               
    .OUTPUTS:
        CSV Files in the defined rootfolder path 
    
                       
    .EXAMPLE
        

    .NOTES
        
        Version: 1.0
        Creator: Richard Sidor
        Date:    31-01-2022
            
        Changes
        -------------------------------------
        Date:      Version  Initials  Changes 
        31-01-2022 1.0      RS        Initial version
        
        
    .LINK
        
 #>

Param([Parameter(mandatory=$false,valuefrompipeline=$true,Position=0)]
[string]$global:DNSroot = "", 
[Parameter(mandatory=$false,valuefrompipeline=$true,Position=1)]
[string]$global:RootFolder = ""
)


 # Check if the runtime is in admin user context
if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") -eq $false){
write-host "Please run as administrator on a ADFS farm node in order to read ADFS farm details ." 
pause
exit 
}


$MyOS = (Get-CimInstance Win32_OperatingSystem).ProductType
[string]$global:Timestamp = (get-date).ToString('yyyy-M-d_HH-mm')
[array]$global:urls = @()


if ($MyOS -gt 1 -and (Get-WindowsFeature -Name ADFS-Federation).Installed -eq $true){
 

if ([string]::IsNullOrWhitespace($global:DNSroot)){
try {if ((get-module activedirectory) -eq $true) {[string]$global:DNSroot = $(get-addomain).DNSRoot}}
catch {[string]$global:DNSroot = $env:USERDNSDOMAIN }}

if ([string]::IsNullOrWhitespace($global:RootFolder)) {[string]$global:RootFolder = "$env:USERPROFILE\desktop\ADFS_$($global:DNSroot)-$($global:Timestamp)"}
if (!(test-path $global:RootFolder)) {new-item -ItemType Directory $global:RootFolder}

try {$global:computers = (Get-AdfsFarmInformation).farmnodes}
catch { Write-host "Could not get ADFS Farm nodes!"}

}

#Data export help functions 

Function create-table ($Input_object){
    $results = @()

    [array]$attributes = $Input_object | gm | ?{$_.MemberType -like "*Property*"}

    foreach ($o in $Input_object){
        
        $result = [PSCustomObject]@{}
        
        foreach($p in $attributes){
            $rslt = @()
            $text = $NULL

            [string]$value = $(if ($o.$($p.name)){if ($p.Definition -match "System.Collections.Generic.Dictionary" ) {
                for([int]$n = 0; $n -le $($o.$($p.name).keys[0].count-1);$n++) {$rslt += "$($o.$($p.name).keys[$n])-$($o.$($p.name)[$($o.$($p.name).keys[$n])])"}
                            $rslt -join "`r`n"} 
            elseif ($p.Definition -match "System.Collections.Hashtable" ) {
                Foreach ($p in in $o.$($p.name).GetEnumerator()){
                [string]$text += $($($p.trim() | ft -Wrap | Out-String).tostring()) }
                $text.ToString() -join "`r`n"
                }               
            elseif ($p.Definition -match "\[\]" -or $p.Definition -match "System.Collections.Generic.List" ) {$o.$($p.name) -join "`r`n" }  
            else {$($o.$($p.name) -join "`r`n")}
            } else {try{$($o.$($p.name).tostring())} catch {}})

            Add-Member -inputobject $result  -MemberType NoteProperty -Name $($p.Name) -Value $($value -join "`r`n") -Force
        }

        $results += $result
    }

    return $results
}

Function folder-backup {
    
    Param( [Parameter(mandatory=$true,valuefrompipeline=$true,Position=0)]
    [String]$BackupFolder,
    [Parameter(mandatory=$true,valuefrompipeline=$true,Position=1)]
    [array]$from)

        if (!(test-path "$BackupFolder")){new-item -ItemType Directory "$BackupFolder" -Force}
        [string]$FolderRoot = $($BackupFolder -replace "$(($BackupFolder -split "\\")[($BackupFolder -split "\\").count-1])","")
        [string]$File_name = $(($BackupFolder -split "\\")[($BackupFolder -split "\\").count-1])

        foreach ($obj in $from) {
         $fn = $(if (($obj.name) -or ($obj.ID)) { $($obj.name),($obj.ID) -join "-"} 
                    else {New-Guid})

            try {$obj| ConvertTo-Json | Out-File "$($BackupFolder)\$($fn).json"} 
            catch {Write-host "Could not export to json object:  $($fn)"
                write-host $error[0].psbase.TargetObject "`r`n"  -ForegroundColor Green
                write-host $error[0].psbase.ErrorDetails "`r`n" -ForegroundColor Yellow
                write-host $error[0].PSbase.Exception "`r`n" -ForegroundColor Yellow
                write-host $error[0].PSbase.message "`r`n" -ForegroundColor Yellow  }

            create-table $obj| export-csv -path "$($BackupFolder)\$($fn).csv" -Delimiter ";" -NoTypeInformation -Encoding UTF8 }
          
            try{$from | ConvertTo-Json | Out-File "$FolderRoot\$($File_name).json"}

            catch{$from.getenumerator() | select key,value | ConvertTo-Json | Out-File "$FolderRoot\$($File_name).json" -Force
                if (!($?)) {write-host "Could not export object: $File_name" -ForegroundColor Yellow
                write-host $error[0].psbase.TargetObject "`r`n"  -ForegroundColor Green
                write-host $error[0].psbase.ErrorDetails "`r`n" -ForegroundColor Yellow
                write-host $error[0].PSbase.Exception "`r`n" -ForegroundColor Yellow
                write-host $error[0].PSbase.message "`r`n" -ForegroundColor Yellow }}

            finally {create-table $from | export-csv -path "$FolderRoot\$($File_name).csv" -Delimiter ";" -NoTypeInformation -Encoding UTF8}               
     }



#Report functions 

Function Get-ADFSOverview {

if(!($global:DNSroot)){
    try {$global:DNSroot = $(get-addomain).DNSRoot}
    catch {$global:DNSroot = $env:USERDNSDOMAIN}

}

if (!($global:Timestamp )){[string]$global:Timestamp = (get-date).ToString('yyyy-M-d_HH-mm')}

if (!($global:computers)){$global:computers = (Get-AdfsFarmInformation).farmnodes}

if (!($global:RootFolder)) {[string]$global:RootFolder = "$env:USERPROFILE\desktop\ADFS_$($global:DNSroot)-$($global:Timestamp)"}
if (!(test-path $global:RootFolder)) {new-item -ItemType Directory $global:RootFolder}

#Reading ADFS properties

    $Properties = Get-AdfsProperties 
    $AzureMfaConfigured = Get-AdfsAzureMfaConfigured
    $WebConfig = Get-AdfsWebConfig 
    $SyncProperties = Get-AdfsSyncProperties
    $CertificateAuthority = Get-AdfsCertificateAuthority
    $FarmInformation = Get-AdfsFarmInformation 

        Add-Member -inputobject $Properties -MemberType NoteProperty -Name AzureMfaConfigured -Value $AzureMfaConfigured -Force
        Add-Member -inputobject $Properties -MemberType NoteProperty -Name CurrentFarmBehavior -Value $FarmInformation.CurrentFarmBehavior -Force
        Add-Member -inputobject $Properties -MemberType NoteProperty -Name FarmNodes -Value $($FarmInformation.FarmNodes.fqdn -join "`r`n") -Force
        Add-Member -inputobject $Properties -MemberType NoteProperty -Name FarmRoles -Value $FarmInformation.FarmRoles -Force
        Add-Member -inputobject $Properties -MemberType NoteProperty -Name ActiveThemeName -Value $WebConfig.ActiveThemeName -Force
        Add-Member -inputobject $Properties -MemberType NoteProperty -Name CDCCookieReader -Value $WebConfig.CDCCookieReader -Force
        Add-Member -inputobject $Properties -MemberType NoteProperty -Name CDCCookieWriter -Value $WebConfig.CDCCookieWriter -Force
        Add-Member -inputobject $Properties -MemberType NoteProperty -Name HRDCookieLifetime -Value $WebConfig.HRDCookieLifetime -Force
        Add-Member -inputobject $Properties -MemberType NoteProperty -Name HRDCookieEnabled -Value $WebConfig.HRDCookieEnabled -Force
        Add-Member -inputobject $Properties -MemberType NoteProperty -Name ContextCookieEnabled -Value $WebConfig.ContextCookieEnabled -Force
        Add-Member -inputobject $Properties -MemberType NoteProperty -Name SyncProperties -Value $SyncProperties.Role -Force
        Add-Member -inputobject $Properties -MemberType NoteProperty -Name ADFS_Server -Value $(try {(Get-ADComputer -Identity (hostname)).DNSHostName} catch {hostname}) -Force
        Add-Member -inputobject $Properties -MemberType NoteProperty -Name CertificateAuthorityMode -Value $CertificateAuthority.CertificateAuthorityMode -Force
        Add-Member -inputobject $Properties -MemberType NoteProperty -Name EnrollmentAgentCertificateTemplateName -Value $CertificateAuthority.EnrollmentAgentCertificateTemplateName -Force
        Add-Member -inputobject $Properties -MemberType NoteProperty -Name LogonCertificateTemplateName -Value $CertificateAuthority.LogonCertificateTemplateName -Force
        Add-Member -inputobject $Properties -MemberType NoteProperty -Name WindowsHelloCertificateTemplateName -Value $CertificateAuthority.WindowsHelloCertificateTemplateName -Force
        Add-Member -inputobject $Properties -MemberType NoteProperty -Name VPNCertificateTemplateName -Value $CertificateAuthority.VPNCertificateTemplateName -Force
        Add-Member -inputobject $Properties -MemberType NoteProperty -Name PrimaryIssuerCertificate -Value $CertificateAuthority.PrimaryIssuerCertificate -Force
        Add-Member -inputobject $Properties -MemberType NoteProperty -Name AdditionalIssuerCertificates -Value $CertificateAuthority.AdditionalIssuerCertificates -Force
        Add-Member -inputobject $Properties -MemberType NoteProperty -Name AutoEnrollEnabled -Value $CertificateAuthority.AutoEnrollEnabled -Force
        Add-Member -inputobject $Properties -MemberType NoteProperty -Name WindowsHelloCertificateProxyEnabled -Value $CertificateAuthority.WindowsHelloCertificateProxyEnabled -Force
        Add-Member -inputobject $Properties -MemberType NoteProperty -Name CertificateGenerationThresholdDays -Value $CertificateAuthority.CertificateGenerationThresholdDays -Force

    if ($Properties){$FarmInformation| ConvertTo-Json | Out-File "$RootFolder\FarmInformation.json"
                    create-table $Properties | export-csv "$RootFolder\_Properties.csv" -Delimiter ";" -NoTypeInformation -Encoding UTF8
                    create-table $FarmInformation | export-csv "$RootFolder\_Farminformation.csv" -Delimiter ";" -NoTypeInformation -Encoding UTF8}

    $Certificates = Get-AdfsCertificate | select *
    if ($Certificates){$Certificates| ConvertTo-Json -depth 5 | Out-File "$RootFolder\Certificates.json"
                    $Certificates | export-csv "$RootFolder\Certificates.csv" -Delimiter ";" -NoTypeInformation -Encoding UTF8}

    $SslCertificate = Get-AdfsSslCertificate | select *    
    if ($SslCertificate){$SslCertificate| ConvertTo-Json -Depth 5 | Out-File "$RootFolder\SslCertificate.json"
                    $SslCertificate | export-csv "$RootFolder\SslCertificate.csv" -Delimiter ";" -NoTypeInformation -Encoding UTF8}
        
    $AttributeStores = Get-AdfsAttributeStore
    if ($AttributeStores){folder-backup -BackupFolder $RootFolder\AttributeStores -from $AttributeStores
                    $AttributeStores| ConvertTo-Json -Depth 10 | Out-File "$RootFolder\AttributeStores.json"
                    }

    [array]$AuthenticationProviders = Get-AdfsAuthenticationProvider
    if ($AuthenticationProviders){folder-backup -BackupFolder $RootFolder\AuthenticationProviders -from $AuthenticationProviders
                    $AuthenticationProviders > $RootFolder\AuthenticationProviders_transcript.csv
                    }
    
    $Endpoints = Get-AdfsEndpoint 
    if ($Endpoints){folder-backup -BackupFolder $RootFolder\Endpoints -from $Endpoints
                    #$Endpoints | export-csv "$RootFolder\Endpoints.csv" -Delimiter ";" -NoTypeInformation -Encoding UTF8
                    }

    [array]$WebThemes = Get-AdfsWebTheme | select Name,IsBuiltinTheme
    if ($WebThemes){$WebThemes | export-csv "$RootFolder\WebThemes.csv" -Delimiter ";" -NoTypeInformation -Encoding UTF8}
    
    $GlobalAuthenticationPolicies = Get-AdfsGlobalAuthenticationPolicy 
    if ($GlobalAuthenticationPolicies){$GlobalAuthenticationPolicies | ConvertTo-Json -Depth 50 | Out-File "$RootFolder\GlobalAuthenticationPolicy.json"
                create-table $GlobalAuthenticationPolicies | export-csv "$RootFolder\GlobalAuthenticationPolicies.csv" -Delimiter ";" -NoTypeInformation -Encoding UTF8}
                
    $ClaimsProviderTrusts = Get-AdfsClaimsProviderTrust
    if ($ClaimsProviderTrusts){folder-backup -BackupFolder $RootFolder\ClaimsProviderTrusts -from $ClaimsProviderTrusts
                    $ClaimsProviderTrusts| ConvertTo-Json -Depth 5 | Out-File "$RootFolder\ClaimsProviderTrusts.json"
                    #create-table $ClaimsProviderTrusts | export-csv "$RootFolder\ClaimsProviderTrusts.csv" -Delimiter ";" -NoTypeInformation -Encoding UTF8
                    $ClaimsProviderTrusts > $RootFolder\ClaimsProviderTrusts_transcript.csv
                    }
    
    $RelyingPartyTrusts = Get-ADFSRelyingPartyTrust
    if ($RelyingPartyTrusts){folder-backup -BackupFolder $RootFolder\RelyingPartyTrusts -from $RelyingPartyTrusts
                    $RelyingPartyTrusts| ConvertTo-Json -Depth 5 | Out-File "$RootFolder\RelyingPartyTrusts.json"                    
                    $RelyingPartyTrusts > "$RootFolder\RelyingPartyTrusts_transcript.csv" 
                    }
        
    $RelyingPartyWebContent = Get-AdfsRelyingPartyWebContent
    if ($RelyingPartyWebContent){$RelyingPartyWebContent | ConvertTo-Json -Depth 5 | Out-File "$RootFolder\RelyingPartyWebContent.json"
                    create-table $RelyingPartyWebContent | export-csv "$RootFolder\RelyingPartyWebContent.csv" -Delimiter ";" -NoTypeInformation -Encoding UTF8}

    $RelyingPartyTrustsGroups = Get-AdfsRelyingPartyTrustsGroup
    if ($RelyingPartyTrustsGroups){ folder-backup -BackupFolder $RootFolder\RelyingPartyTrusts -from $RelyingPartyTrustsGroups
                    $RelyingPartyTrustsGroups | ConvertTo-Json -Depth 5| Out-File "$RootFolder\RelyingPartyTrustsGroups.json"
                    $RelyingPartyTrustsGroups > "$RootFolder\RelyingPartyTrustsGroups_transcript.csv" }

    $WebApplicationProxyRelyingPartyTrust = Get-AdfsWebApplicationProxyRelyingPartyTrust 
    if ($WebApplicationProxyRelyingPartyTrust){ $WebApplicationProxyRelyingPartyTrust | ConvertTo-Json -Depth 5| Out-File "$RootFolder\GlobalAuthenticationPolicy.json"
                    create-table $WebApplicationProxyRelyingPartyTrust | export-csv "$RootFolder\WebApplicationProxyRelyingPartyTrust.csv" -Delimiter ";" -NoTypeInformation -Encoding UTF8}
    
    $TrustedFederationPartner = Get-AdfsTrustedFederationPartner
    if ($TrustedFederationPartner){$TrustedFederationPartner | Convertto-Json -Depth 5 | Out-File "$RootFolder\TrustedFederationPartner.json"
                    create-table $TrustedFederationPartner | export-csv "$RootFolder\TrustedFederationPartner.csv" -Delimiter ";" -NoTypeInformation -Encoding UTF8}

    $ScopeDescription = Get-AdfsScopeDescription
    if ($ScopeDescription){$ScopeDescription | Convertto-Json -Depth 5 | Out-File "$RootFolder\ScopeDescription.json"
                    create-table $ScopeDescription | export-csv "$RootFolder\ScopeDescription.csv" -Delimiter ";" -NoTypeInformation -Encoding UTF8}

    $RegistrationHosts = Get-AdfsRegistrationHosts
    if ($RegistrationHosts){$RegistrationHosts | Convertto-Json -Depth 5 | Out-File "$RootFolder\RegistrationHosts.json"
                    create-table $RegistrationHosts | export-csv "$RootFolder\RegistrationHosts.csv" -Delimiter ";" -NoTypeInformation -Encoding UTF8}

    $NonClaimsAwareRelyingPartyTrust = Get-AdfsNonClaimsAwareRelyingPartyTrust
    if ($NonClaimsAwareRelyingPartyTrust){$NonClaimsAwareRelyingPartyTrust | Convertto-Json -Depth 5 | Out-File "$RootFolder\NonClaimsAwareRelyingPartyTrust.json"
                    create-table $NonClaimsAwareRelyingPartyTrust | export-csv "$RootFolder\NonClaimsAwareRelyingPartyTrust.csv" -Delimiter ";" -NoTypeInformation -Encoding UTF8}
    
    $LocalClaimsProviderTrust = Get-AdfsLocalClaimsProviderTrust
    if ($LocalClaimsProviderTrust){folder-backup -BackupFolder $RootFolder\LocalClaimsProviderTrust -from $LocalClaimsProviderTrust
                    $LocalClaimsProviderTrust | Convertto-Json -Depth 20 | Out-File "$RootFolder\LocalClaimsProviderTrust.json"
                    $LocalClaimsProviderTrust > $RootFolder\LocalClaimsProviderTrust_transcript.csv
                    }

    $GlobalWebContent = Get-AdfsGlobalWebContent
    if ($GlobalWebContent){$GlobalWebContent | Convertto-Json -Depth 5 | Out-File "$RootFolder\GlobalWebContent.json"
    create-table $GlobalWebContent | export-csv "$RootFolder\GlobalWebContent.csv" -Delimiter ";" -NoTypeInformation -Encoding UTF8}
    
    $DeviceRegistrationUpnSuffix = Get-AdfsDeviceRegistrationUpnSuffix
    if ($DeviceRegistrationUpnSuffix){ $DeviceRegistrationUpnSuffix | Convertto-Json -Depth 50 | Out-File "$RootFolder\DeviceRegistrationUpnSuffix.json"
                     create-table $DeviceRegistrationUpnSuffix | export-csv "$RootFolder\DeviceRegistrationUpnSuffix.csv" -Delimiter ";" -NoTypeInformation -Encoding UTF8}
    
    $DeviceRegistration = Get-AdfsDeviceRegistration
    if ($DeviceRegistration){$DeviceRegistration | Convertto-Json -Depth 5 | Out-File "$RootFolder\DeviceRegistration.json"
    create-table $DeviceRegistration | export-csv "$RootFolder\DeviceRegistration.csv" -Delimiter ";" -NoTypeInformation -Encoding UTF8
                    $DeviceRegistration > "$RootFolder\DeviceRegistration_transcript.csv" }
    
    $Clients = Get-AdfsClient
    if ($Clients){$Clients | Convertto-Json -Depth 5 | Out-File "$RootFolder\Client.json"
                create-table $Clients | export-csv "$RootFolder\Clients.csv" -Delimiter ";" -NoTypeInformation -Encoding UTF8}
    
    $ClaimsProviderTrustsGroup = Get-AdfsClaimsProviderTrustsGroup
    if ($ClaimsProviderTrustsGroup){$ClaimsProviderTrustsGroup | Convertto-Json -Depth 5 | Out-File "$RootFolder\ClaimsProviderTrustsGroup.json"
                    create-table $ClaimsProviderTrustsGroup | export-csv "$RootFolder\ClaimsProviderTrustsGroup.csv" -Delimiter ";" -NoTypeInformation -Encoding UTF8}
    
    $ClaimDescription = Get-AdfsClaimDescription
    if ($ClaimDescription){$ClaimDescription | Convertto-Json -Depth 5 | Out-File "$RootFolder\ClaimDescription.json"
                    create-table $ClaimDescription | export-csv "$RootFolder\ClaimDescription.csv" -Delimiter ";" -NoTypeInformation -Encoding UTF8}
    
    $AuthenticationProviderWebContent = Get-AdfsAuthenticationProviderWebContent
    if ($AuthenticationProviderWebContent){$AuthenticationProviderWebContent | Convertto-Json -Depth 50 | Out-File "$RootFolder\AuthenticationProviderWebContent.json"
                    create-table $AuthenticationProviderWebContent | export-csv "$RootFolder\AuthenticationProviderWebContent.csv" -Delimiter ";" -NoTypeInformation -Encoding UTF8}
    
    $ApplicationPermission = Get-AdfsApplicationPermission
    if ($ApplicationPermission){$ApplicationPermission | Convertto-Json -Depth 50 | Out-File "$RootFolder\ApplicationPermission.json"
                    create-table $ApplicationPermission | export-csv "$RootFolder\ApplicationPermission.csv" -Delimiter ";" -NoTypeInformation -Encoding UTF8}
    
    $AdditionalAuthenticationRule = Get-AdfsAdditionalAuthenticationRule
    if ($AdditionalAuthenticationRule){$AdditionalAuthenticationRule | Convertto-Json -Depth 5 | Out-File "$RootFolder\AdditionalAuthenticationRule.json"
                    $AdditionalAuthenticationRule | export-csv "$RootFolder\AdditionalAuthenticationRule.csv" -Delimiter ";" -NoTypeInformation -Encoding UTF8}
    

    $ApplicationGroups = Get-AdfsApplicationGroup 
    if ($ApplicationGroups){folder-backup -BackupFolder $RootFolder\ApplicationGroups -from $ApplicationGroups
                    $ApplicationGroups| Convertto-Json -Depth 20 | Out-File "$RootFolder\ApplicationGroups.json"                                                          
                    $ApplicationGroups | select Name,ApplicationGroupIdentifier,Description,@{N="Applications";E={$_.Applications.name -join "`r`n"}},enabled | Export-Csv -Path $RootFolder\ApplicationGroups_transcript.csv -Delimiter ";" -NoTypeInformation -Encoding UTF8 }

    $ServerApplications = Get-AdfsServerApplication
    if ($ServerApplications){ 
                    folder-backup -BackupFolder $RootFolder\ServerApplications -from $ServerApplications
                    $ServerApplications| Convertto-Json -Depth 10 | Out-File "$RootFolder\ServerApplications.json"
                    #create-table $ServerApplications | export-csv -path "$RootFolder\ServerApplications.csv" -Delimiter ";" -NoTypeInformation -Encoding UTF8
                    $ServerApplications > "$RootFolder\ServerApplications_transcript.csv"
                    }

    $NativeClientApplications = Get-AdfsNativeClientApplication 
                    if ($NativeClientApplications){
                        folder-backup -BackupFolder $RootFolder\NativeClientApplications -from $NativeClientApplications              
                        $NativeClientApplications| Convertto-Json -Depth 5 | Out-File "$RootFolder\NativeClientApplications.json"
                        #create-table $NativeClientApplications | export-csv -path  "$RootFolder\NativeClientApplications.csv" -Delimiter ";" -NoTypeInformation -Encoding UTF8
                        $NativeClientApplications > "$RootFolder\NativeClientApplications_transcript.csv"
                    }

    $WebApiApplications = Get-AdfsWebApiApplication 
    if ($WebApiApplications){   
                    folder-backup -BackupFolder $RootFolder\WebApiApplications -from $WebApiApplications
                    $WebApiApplications | Convertto-Json -Depth 20 | Out-File "$RootFolder\WebApiApplications.json"
                    $WebApiApplications > "$RootFolder\WebApiApplications-transcript.csv" 
                    }
    

    }

Function Server-Report {
 

 if(!($global:DNSroot)){
    try {$global:DNSroot = $(get-addomain).DNSRoot}
    catch {$global:DNSroot = $env:USERDNSDOMAIN}


}

if (!($global:Timestamp )){[string]$global:Timestamp = (get-date).ToString('yyyy-M-d_HH-mm')}

if (!($global:computers)){[array]$global:computers = (Get-AdfsFarmInformation).farmnodes}

if (!($global:RootFolder)) {[string]$global:RootFolder = "$env:USERPROFILE\desktop\ADFS_$($global:DNSroot)-$($global:Timestamp)"}
if (!(test-path $global:RootFolder)) {new-item -ItemType Directory $global:RootFolder}

[array]$ERRORS = @()
[array]$FailedComputers = @()
[array]$DetailsList = @()

[array]$DCs = $global:computers.fqdn | sort


foreach ($dc in $DCs) {
[array]$full_computers += Get-ADComputer $($DC -replace ".$($global:DNSroot)","") -Properties distinguishedname,operatingSystem,Description,memberof,servicePrincipalName 
}

Foreach ($comp in $full_computers) { 
$result = $()       
    
    $memberof = $comp.memberof 
    $SPNs = $comp.servicePrincipalName
           
        
            $HostAdapters = gwmi -query "Select  IPAddress,DefaultIPGateway,DNSDomain,DNSServerSearchOrder,MACAddress From Win32_NetworkAdapterConfiguration Where IPEnabled = True" -computer $($comp.Name)
            $HostInfo = gwmi -query "Select roles,TotalPhysicalMemory,NumberOfProcessors,NumberOfLogicalProcessors From Win32_ComputerSystem" -computer $($comp.Name)
            $OSInfo = gwmi -query "Select OSArchitecture,Caption,Codeset,Countrycode,InstallDate,LastBootUpTime From Win32_OperatingSystem" -computer $($comp.Name)
            $HostHardware = gwmi -query "Select vendor,name from Win32_ComputerSystemProduct" -computer $($comp.Name)

            $OSArchitecture = $OSInfo.OSArchitecture
            $HostOSInfo = $OSInfo.Caption
            $Codeset = $OSInfo.Codeset
            $Countrycode = $OSInfo.Countrycode
            $InstallDate = $OSInfo.InstallDate.SubString(0,12)
            $InstallDate = [datetime]::ParseExact($InstallDate,'yyyyMMddHHmm',$null)
            $LastBootUpTime = $OSInfo.LastBootUpTime.SubString(0,12)
            $LastBootUpTime = [datetime]::ParseExact($LastBootUpTime,'yyyyMMddHHmm',$null)

            $HostHardwareType = $HostHardware.name
            $HostHardwareBrand = $HostHardware.vendor
            $HostHardwareSerial = $HostHardware.IdentifyingNumber
            
            $ServerRoles = $HostInfo.roles
            [int]$RAM = [math]::Round($HostInfo.TotalPhysicalMemory/1073741824,0)
            [int]$CPU = $HostInfo.NumberOfProcessors
            [int]$Cores = $HostInfo.NumberOfLogicalProcessors.ToString()

            $ServerLan = $HostAdapters |Where-Object {$_.DefaultIPGateway -ne $Null}
         
            [int]$ServerLanIPaddressCount = $ServerLan.IPAddress.Count
            [string]$Registereddomain = $HostAdapters.DNSDomain 

            $DNSServerSearchOrder = $HostAdapters.DNSServerSearchOrder 
            $MACAddress = $HostAdapters.MACAddress
            
            $Runningservices = (Get-service -computer $($comp.Name) | ?{$_.status -eq "Running"}|select name).name
            $Software = (Get-WmiObject -computer $($comp.Name)  -Class Win32_Product).name

            if($comp.operatingSystem -notlike "*2008*") {$Features = (Get-WindowsFeature -computer $($comp.Name) | ?{$_.installed -eq "True"}|select name).name}
            if($comp.operatingSystem -like "*2008*") {$Features =  Invoke-Command -computer $($comp.Name) -ScriptBlock {(Get-WindowsFeature | ?{$_.installed -eq "True"}|select name).name} }
          
                            
            $diskspace =   Get-CimInstance -ClassName Win32_LogicalDisk -filter "DriveType=3" -computer $($comp.name)| Select SystemName,DeviceID,@{Name="Size"; 
            Expression={"{0:N3}" -f ($_.size/1gb)}},@{Name="FreeSpace"; 
            Expression={"{0:N3}" -f ($_.freespace/1gb)}}, @{Name="LowSpace"; 
            Expression={"{0:N3}" -f ($_.freespace / $_.size -lt .200)}}  


$result = [PSCustomObject]@{Name = $comp.Name
            DN = $comp.DistinguishedName
            Description = $comp.Description 
            memberof = $memberof -join "`r`n"
            SPNs = $SPNs -join "`r`n"
            HostOSInfo = $HostOSInfo
            OSArchitecture=$OSArchitecture
            HostHardwareType= $HostHardwareType 
            HostHardwareBrand= $HostHardwareBrand 
            HostHardwareSerial= $HostHardwareSerial 
            ServerRoles = $ServerRoles -join "`r`n"
            Features = $Features -join "`r`n"
            Codeset = $Codeset
            Countrycode = $Countrycode
            InstallDate= $InstallDate 
            LastBootUpTime=$LastBootUpTime
            RAM= $RAM 
            CPU= $CPU 
            Cores= $Cores 
            DiskCount = $diskspace.DeviceID.count
            ServerLan =  $ServerLan.IPAddress -join "`r`n"
            ServerLanIPaddressCount= $ServerLanIPaddressCount 
            Gateway = $HostAdapters.DefaultIPGateway -join "`r`n" 
            Disksnames = $diskspace.DeviceID -join "`r`n "
            Diskssize  = $diskspace.size -join "`r`n "
            FreeDiskpace = $diskspace.freespace -join "`r`n "
            Fulldisks = $diskspace.Lowspace -join "`r`n "
            Registereddomain =$Registereddomain
            Runningservices = $Runningservices -join "`r`n "
            RS_count = $Runningservices.count
            Software = $Software -join "`r`n "
            DNSServerSearchOrder = $DNSServerSearchOrder -join "`r`n "
            MACAddress = $MACAddress -join "`r`n "
}
   
  #  $x++
    
    [array]$DetailsList += $result
    
    }

if ($DetailsList){          
$DetailsList | select Name,DN,Description,memberof,SPNs,HostOSInfo,OSArchitecture,Codeset,Countrycode,InstallDate,LastBootUpTime,ServerRoles,Features,Runningservices,`
RS_count,Software,HostHardwareType,HostHardwareBrand,HostHardwareSerial,RAM,CPU,Cores,DiskCount,Disksnames,Diskssize,FreeDiskpace,Fulldisks,ServerLanIPaddressCount,`
ServerLan,MACAddress,Gateway,Registereddomain,DNSServerSearchOrder |  Export-Csv -Path $Rootfolder\Server-TD.csv -NoTypeInformation -Delimiter ";" -Encoding UTF8 -force 
}

foreach ($record in $DetailsList){if ($record.MACAddress -eq "" -and $record.DiskCount -eq 0){$FailedComputers += $record}}

if ($FailedComputers) { $FailedComputers | select name,distinguishedName,Description,OperatingSystem  | Out-File $Rootfolder\Failed-TD-$Timestamp.txt }
      
$style = @"
<style>
    body{font-family: Calibri, Candara, Segoe, "Segoe UI", Optima, Arial, sans-serif; font-size: 10pt;}
    h1{font-family: Calibri, Candara, Segoe, "Segoe UI", Optima, Arial, sans-serif; font-size: 14pt;}
    h2{font-family: Calibri, Candara, Segoe, "Segoe UI", Optima, Arial, sans-serif; font-size: 9pt;}
    p{font-family: Calibri, Candara, Segoe, "Segoe UI", Optima, Arial, sans-serif; font-size: 12pt;}
    table{border: 1px solid black; border-collapse: collapse; width: 100%}
    th{border: 1px solid black; background: #070C4E; padding: 5px; text-align:left; color:#fff;}
    td{border: 1px solid black; padding: 5px; }
    .True {background: red ; color: white ;}
    .False {background: green ; color: white ;}
</style>      
"@

[array]$report = $DetailsList | Sort-Object Name 

[xml]$html = $report| ConvertTo-Html -Fragment

1..($html.table.tr.count-1) | foreach {
#enumerate each TD
$td = $html.table.tr[$_]
#create a new class attribute
$class = $html.CreateAttribute("class")
 
#set the class value based on the item value

Switch ($td.childnodes.item(19).'#text') {
    "0"  { $class.value = "True" }
    $Null { $class.value = "True" }
    Default { $class.value = "False"} 
            }
$td.childnodes.item(19).attributes.append($class) 

$class = $html.CreateAttribute("class")
Switch ($td.childnodes.item(26).'#text') {
    "True" { $class.value = "True"  }
    Default { $class.value = "False"} 
            }
$td.childnodes.item(26).attributes.append($class)            

$class = $html.CreateAttribute("class")
Switch ($td.childnodes.item(31).'#text') {
    ""  { $class.value = "True" }
    $Null { $class.value = "True" }
    Default { $class.value = "False"} 
            }
$td.childnodes.item(31).attributes.append($class)            

}

$title = "<br><h1> Server report $($Timestamp)</h1></br>" 
$title += $html.InnerXml 

[string]$htmlMail = ConvertTo-Html  -head $style -body $title -as Table -PostContent "<h2>Report created on - $Timestamp</h2>" 

if ($htmlMail) {$htmlMail > $Rootfolder\Server-TD-$($Timestamp).html}

}

Function Get-RPOverview {

 if(!($global:DNSroot)){
    try {$global:DNSroot = $(get-addomain).DNSRoot}
    catch {$global:DNSroot = $env:USERDNSDOMAIN}


}

if (!($global:Timestamp )){[string]$global:Timestamp = (get-date).ToString('yyyy-M-d_HH-mm')}


if (!($global:RootFolder)) {[string]$global:RootFolder = "$env:USERPROFILE\desktop\ADFS_$($global:DNSroot)-$($global:Timestamp)"}
if (!(test-path $global:RootFolder)) {new-item -ItemType Directory $global:RootFolder}


$style = @"
<style>
    body {font-family: Calibri, Candara, Segoe, "Segoe UI", Optima, Arial, sans-serif; font-size: 10pt;}
    h1 {font-family: Calibri, Candara, Segoe, "Segoe UI", Optima, Arial, sans-serif; font-size: 14pt;}
    p{font-family: Calibri, Candara, Segoe, "Segoe UI", Optima, Arial, sans-serif; font-size: 12pt;}
    table {border: 1px solid black; border-collapse: collapse; width: 100%}
    th {border: 1px solid black; background: #070C4E; padding: 5px; text-align:left; color:#fff;}
    td {border: 1px solid black; padding: 5px;}
    .Expired {background: red ; color: white;}
    .Unencrypted {background: orange ; color: black;}
    .Warning {background: yellow ; color: black;}
    .Valid {background: green ; color: white;}
</style>
"@


$RPINFO = get-adfsrelyingpartytrust | sort RelyingPartyName
$RPOverview =@()

if ($RPINFO){
ForEach ($RP in $RPINFO){
    $RPOverview += [pscustomobject] @{

        RelyingPartyName = [string]$RP.Name
        Identifier = [string]$rp.Identifier
        Enabled = [boolean]$rp.Enabled
        Environment = $(IF ($RP.PSComputerName -like "P*") {"PROD"} ELSE {"NONPROD"})        
        Protocol = [string]$RP.ProtocolProfile 
        EncryptClaims = [boolean]$rp.EncryptClaims
        EncryptionCertificate =$(IF($RP.EncryptionCertificate -eq $null) {"No encryption applied."} Else {"Encrypted"})
        EncryptionCertValidTo = $(If($rp.EncryptionCertificate -ne $null){$RP.EncryptionCertificate.notafter -f "mm/dd/yyyy hh:mm"} else {"Unencrypted"})
        MonitoringEnabled = $rp.MonitoringEnabled
        LastMonitoredon = $( IF($RP.LastMonitoredTime -gt (get-date -Year 1900 -Date 1 -Month 1 -Hour 1)){$RP.LastMonitoredTime  -f "mm/dd/yyyy hh:mm"} ELSE{"Not monitored"})
        LastPolicyCheckSuccesfull = $RP.LastPublishedPolicyCheckSuccessful
        RequestSigningCertificate = $(IF($RP.RequestSigningCertificate.count -eq 0) {"Not signing"} Else{"Claims signed"})
        RequestSigningCertificatevalidTo = $(IF($RP.RequestSigningCertificate.Count -NE 0){[datetime]$RP.RequestSigningCertificate.notafter  -f "mm/dd/yyyy hh:mm"} ELSE {"Not signing"})
        AccessControlPolicyName = $rp.AccessControlPolicyName
        MFAEnforced = $(IF($rp.AdditionalAuthenticationRules.Length -eq 0) {$False} Else{$True})
        MetadataUrl = $($rp.MetadataUrl.AbsoluteUri -join "`r`n")
        SamlEndpoints  = $(($rp.SamlEndpoints.location.AbsoluteUri | sort -Unique) -join "`r`n")
        WSFedEndpoint = $(($rp.WSFedEndpoint.AbsoluteUri | sort -Unique) -join "`r`n")
        Notes = [string]$rp.Notes
    }
}


$RPOverview | Export-Csv -Path $Rootfolder\ADFS_RP_Overview.csv -Delimiter ";" -NoTypeInformation -Force -Encoding UTF8

[xml]$html = $RPOverview | ConvertTo-Html -Fragment
1..($($html.table.tr.count)-1) | foreach {
$td = $html.table.tr[$_] #enumerate each thread (row) of the Table 
$class = $html.CreateAttribute("class") #create a new class attribute for each cell
 
#set the class value based on the item value


if ([string]$td.childnodes.item(7).'#text' -eq "Unencrypted") {$class.value = "Unencrypted"}
elseif ([datetime]$td.childnodes.item(7).'#text' -ge $(get-date) -and [datetime]$td.childnodes.item(7).'#text' -le $(get-date).AddDays(14)) {
    $class.value = "Warning" }
elseif ([datetime]$td.childnodes.item(7).'#text' -le $(get-date)) {
    $class.value = "Expired" }
else {$class.value = "Valid"}           

#append the class to the cell 
$td.childnodes.item(7).attributes.append($class)
}

1..($($html.table.tr.count)-1) | foreach {
$td = $html.table.tr[$_] #enumerate each thread (row) of the Table 
$class = $html.CreateAttribute("class") #create a new class attribute for each cell
 
#set the class value based on the item value

if ([string]$td.childnodes.item(9).'#text' -eq "Not monitored") {$class.value = "Unencrypted"}
elseif ([datetime]$td.childnodes.item(9).'#text' -le $(get-date) -and [datetime]$td.childnodes.item(9).'#text' -gt $(get-date).AddDays(-14)) {
    $class.value = "Valid" }
elseif ([datetime]$td.childnodes.item(9).'#text' -le $(get-date).AddDays(-14)) {
    $class.value = "Expired" }
else {$class.value = "Warning"}           

#append the class to the cell 
$td.childnodes.item(9).attributes.append($class)
}

1..($($html.table.tr.count)-1) | foreach {
$td = $html.table.tr[$_] #enumerate each thread (row) of the Table 
$class = $html.CreateAttribute("class") #create a new class attribute for each cell
 
#set the class value based on the item value

if ([string]$td.childnodes.item(12).'#text' -eq "Not signing") {$class.value = "Unencrypted"}
elseif ([datetime]$td.childnodes.item(12).'#text' -ge $(get-date) -and [datetime]$td.childnodes.item(12).'#text' -le $(get-date).AddDays(14)) {
    $class.value = "Warning" }
elseif ([datetime]$td.childnodes.item(12).'#text' -le $(get-date)) {
    $class.value = "Expired" }
else {$class.value = "Valid"}           

#append the class to the cell 
$td.childnodes.item(12).attributes.append($class)
}

[string]$htmlMail = ConvertTo-Html -Head $style -body $html.InnerXml -PostContent "<h6> Report created at $Timestamp</h6>"
$htmlMail | Out-File $Rootfolder\RP-report.html 
explorer $Rootfolder\RP-report.html
$global:urls += ($($RPINFO | ?{$_.enabled -eq $true}).metadataurl.AbsoluteUri+$($RPINFO | ?{$_.enabled -eq $true}).SamlEndpoints.location.AbsoluteUri+$($RPINFO | ?{$_.enabled -eq $true}).WSFedEndpoint.AbsoluteUri) | sort -Unique
}
else {Write-host "Could not get Claim PRovider Information." }
}

Function Get-CPOverview {

if(!($global:DNSroot)){
    try {$global:DNSroot = $(get-addomain).DNSRoot}
    catch {$global:DNSroot = $env:USERDNSDOMAIN}

}

if (!($global:Timestamp )){[string]$global:Timestamp = (get-date).ToString('yyyy-M-d_HH-mm')}

if (!($global:computers)){[array]$global:computers = (Get-AdfsFarmInformation).farmnodes}

if (!($global:RootFolder)) {[string]$global:RootFolder = "$env:USERPROFILE\desktop\ADFS_$($global:DNSroot)-$($global:Timestamp)"}
if (!(test-path $global:RootFolder)) {new-item -ItemType Directory $global:RootFolder}



$style = @"
<style>
    body {font-family: Calibri, Candara, Segoe, "Segoe UI", Optima, Arial, sans-serif; font-size: 10pt;}
    h1 {font-family: Calibri, Candara, Segoe, "Segoe UI", Optima, Arial, sans-serif; font-size: 14pt;}
    p{font-family: Calibri, Candara, Segoe, "Segoe UI", Optima, Arial, sans-serif; font-size: 12pt;}
    table {border: 1px solid black; border-collapse: collapse; width: 100%}
    th {border: 1px solid black; background: #070C4E; padding: 5px; text-align:left; color:#fff;}
    td {border: 1px solid black; padding: 5px;}
    .Expired {background: red ; color: white;}
    .Unencrypted {background: orange ; color: black;}
    .Warning {background: yellow ; color: black;}
    .Valid {background: green ; color: white;}
</style>
"@


$CPINFO = Get-AdfsClaimsProviderTrust | sort ClaimProviderName

if ($CPINFO){
$CPOverview =@()
ForEach ($CP in $CPINFO){
    $CPOverview += [pscustomobject] @{

        ClaimProviderName = [string]$CP.Name
        Identifier = [string]$CP.Identifier
        Enabled = [boolean]$CP.Enabled
        Environment = $(IF ($(Hostname) -like "P*") {"PROD"} ELSE {"NONPROD"})
        MetadataUrl = $($cp.MetadataUrl.AbsoluteUri -join "`r`n")
        SamlEndpoints  = $(($cp.SamlEndpoints.location.AbsoluteUri | sort -Unique) -join "`r`n")
        Protocol = [string]$CP.ProtocolProfile 
        EncryptClaims = [boolean]$CP.EncryptClaims
        EncryptionCertificate =$(IF($CP.EncryptionCertificate -eq $null) {"No encryption applied."} Else {"Encrypted"})
        EncryptionCertValidTo = $(If($CP.EncryptionCertificate -ne $null){$CP.EncryptionCertificate.notafter -f "mm/dd/yyyy hh:mm"} else {"Unencrypted"})
        MonitoringEnabled = $CP.MonitoringEnabled
        LastMonitoredOn = $(IF($CP.LastMonitoredTime -gt (get-date -Year 1900 -Date 1 -Month 1 -Hour 1)){$CP.LastMonitoredTime  -f "mm/dd/yyyy hh:mm"} ELSE {"Not monitored"})
        LastPolicyCheckSuccesfull = $CP.LastPublishedPolicyCheckSuccessful
        LastUpdateTime = $(IF($CP.LastUpdateTime -gt (get-date -Year 1900 -Date 1 -Month 1 -Hour 1)){$CP.LastUpdateTime  -f "mm/dd/yyyy hh:mm"} ELSE {"Not updating"})             
        AutoUpdateEnabled = $($CP.AutoUpdateEnabled)
        SupportsMFA = $($CP.SupportsMFA)
        OrganizationInfo  = $cp.OrganizationInfo 
        Notes = [string]$CP.Notes
    }
}



$CPOverview | Export-Csv -Path $Rootfolder\ADFS_CP_Overview.csv -Delimiter ";" -NoTypeInformation -Force -Encoding UTF8

[xml]$html = $CPOverview | ConvertTo-Html -Fragment

1..($($html.table.tr.count)-1) | foreach {
$td = $html.table.tr[$_] #enumerate each thread (row) of the Table 
$class = $html.CreateAttribute("class") #create a new class attribute for each cell
 
#set the class value based on the item value


if ([string]$td.childnodes.item(9).'#text' -eq "Unencrypted") {$class.value = "Unencrypted"}
elseif ([datetime]$td.childnodes.item(9).'#text' -ge $(get-date) -and [datetime]$td.childnodes.item(9).'#text' -le $(get-date).AddDays(14)) {
    $class.value = "Warning" }
elseif ([datetime]$td.childnodes.item(9).'#text' -le $(get-date)) {
    $class.value = "Expired" }
else {$class.value = "Valid"}           

#append the class to the cell 
$td.childnodes.item(9).attributes.append($class)
}

1..($($html.table.tr.count)-1) | foreach {
$td = $html.table.tr[$_] #enumerate each thread (row) of the Table 
$class = $html.CreateAttribute("class") #create a new class attribute for each cell
 
#set the class value based on the item value

if ([string]$td.childnodes.item(11).'#text' -eq "Not monitored") {$class.value = "Unencrypted"}
elseif ([datetime]$td.childnodes.item(11).'#text' -le $(get-date) -and [datetime]$td.childnodes.item(11).'#text' -gt $(get-date).AddDays(-14)) {
    $class.value = "Valid" }
elseif ([datetime]$td.childnodes.item(11).'#text' -le $(get-date).AddDays(-14)) {
    $class.value = "Expired" }
else {$class.value = "Warning"}           

#append the class to the cell 
$td.childnodes.item(11).attributes.append($class)
}

1..($($html.table.tr.count)-1) | foreach {
$td = $html.table.tr[$_] #enumerate each thread (row) of the Table 
$class = $html.CreateAttribute("class") #create a new class attribute for each cell
 
#set the class value based on the item value

if ([string]$td.childnodes.item(13).'#text' -eq "Not updating") {$class.value = "Unencrypted"}
elseif ([datetime]$td.childnodes.item(13).'#text' -le $(get-date) -and [datetime]$td.childnodes.item(13).'#text' -gt $(get-date).AddDays(-14)) {
    $class.value = "Valid" }
elseif ([datetime]$td.childnodes.item(13).'#text' -le $(get-date).AddDays(-14)) {
    $class.value = "Expired" }
else {$class.value = "Warning"}           

#append the class to the cell 
$td.childnodes.item(13).attributes.append($class)
}


[string]$htmlMail = ConvertTo-Html -Head $style -body $html.InnerXml -PostContent "<h6>Report created at $Timestamp</h6>"
$htmlMail | Out-File $Rootfolder\CP-report.html 
explorer $Rootfolder\CP-report.html
$global:urls += ( $($CPINFO | ?{$_.enabled -eq $true}).metadataurl.AbsoluteUri+$($CPINFO | ?{$_.enabled -eq $true}).SamlEndpoints.location.AbsoluteUri) | sort -Unique
}

else {Write-host "Could not get Claim Provider Information." }
}

Function GET-WSUSDetails{


 if(!($global:DNSroot)){
    try {$global:DNSroot = $(get-addomain).DNSRoot}
    catch {$global:DNSroot = $env:USERDNSDOMAIN }


}

if (!($global:Timestamp )){[string]$global:Timestamp = (get-date).ToString('yyyy-M-d_HH-mm')}

if (!($global:computers)){[array]$global:computers = (Get-AdfsFarmInformation).farmnodes}

if (!($global:RootFolder)) {[string]$global:RootFolder = "$env:USERPROFILE\desktop\ADFS_$($global:DNSroot)-$($global:Timestamp)"}
if (!(test-path $global:RootFolder)) {new-item -ItemType Directory $global:RootFolder}

$global:Updates = @()
$global:WSUS = @()


foreach( $computer in $computers ){  
$global:WSUS +=Invoke-Command -ComputerName $Computer -Command { Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"  | Select-Object PSComputerName, WUServer }       
    }

$global:Updates   += Get-HotFix -ComputerName $computers

$global:Updates | Export-Csv -Path "$Rootfolder\Updates-overview.csv" -Delimiter ";" -NoTypeInformation -Append  -Encoding UTF8
$global:WSUS | Export-Csv -Path "$Rootfolder\WSUS-Regitrations.csv" -Delimiter ";" -NoTypeInformation -Append -Encoding UTF8
}

Function Get-ADFSuptime {

if(!($global:DNSroot)){
    try {$global:DNSroot = $(get-addomain).DNSRoot}
    catch {$global:DNSroot = $env:USERDNSDOMAIN}

        
}

if (!($global:Timestamp )){[string]$global:Timestamp = (get-date).ToString('yyyy-M-d_HH-mm')}

if (!($global:computers)){$global:computers = (Get-AdfsFarmInformation).farmnodes}

if (!($global:RootFolder)) {[string]$global:RootFolder = "$env:USERPROFILE\desktop\ADFS_$($global:DNSroot)-$($global:Timestamp)"}
if (!(test-path $global:RootFolder)) {new-item -ItemType Directory $global:RootFolder}

[array]$results = @()

foreach ($comp in $computers) {
$Prop = Get-CimInstance -ComputerName $comp  -ClassName win32_operatingsystem
$result = [PSCustomObject]@{Server=  $Prop.CSName
                LastBootUpTime = [datetime]$Prop.LastBootUpTime
                "Uptime (Days)" = ((Get-Date) - ([datetime]$Prop.LastBootUpTime)).Days}

if ($result) {$results +=$result}
}
if ($results){$results|ft -wrap > $RootFolder\ADFS_Uptime_$($global:Timestamp).csv
return $results}
}

if ($global:computers){
    Get-ADFSOverview
    Server-Report
    Get-RPOverview
    Get-CPOverview
    Get-WSUSDetails
    Get-ADFSuptime

if ($urls) { 
if (!($global:RootFolder)) {[string]$global:RootFolder = "$env:USERPROFILE\desktop\ADFS_$($global:DNSroot)-$($global:Timestamp)"}
if (!(test-path $global:RootFolder)) {new-item -ItemType Directory $global:RootFolder}

$global:urls = $global:urls | sort -Unique
$global:urls > $global:RootFolder\RP_CP_URLS.csv}
}