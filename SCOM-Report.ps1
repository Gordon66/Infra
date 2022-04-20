<#SCOM ADFS Report 

Script for checking the ADFS functionality 
- Network avaliability of ADFS farm nodes 
- status of ADFS services
- Certificates on ADFS farm nodes 
- connection to configuration SQL database 
- last boot time of the node 

Author: Richard Sidor 
Version: 1.0
Date: 2021-05-19

#>

Function Get-uptime{
$results = @()
$Prop = Get-CimInstance -ClassName win32_operatingsystem
$result = [PSCustomObject]@{Server=  $Prop.CSName
                LastBootUpTime = [datetime]$Prop.LastBootUpTime
                "Uptime (Days)" = ((Get-Date) - ([datetime]$Prop.LastBootUpTime)).Days}

if ($result) {$results +=$result}

return $results
}


[array]$services = @()
[array]$network = @()
[array]$certs = @()
[array]$sql = @()
[array]$failed = @()

[string]$message = $null
[bool]$ok = $false


try {$ADFSproperties = get-adfsproperties
[array]$servers = (Get-AdfsFarmInformation).FarmNodes.fqdn
}

catch {$message += "`r`nCould not get ADFS Farm details."  
    if (!($(Get-WindowsFeature ADFS-Federation).installed)) { 
    $message += "`r`nPlease run the script on one of the ADFS Farm nodes or check Your admin rights for the ADFS farm ."}
    }

if ($ADFSproperties ){


#Reading of farm details

    try {[string]$SQLServer = $($($ADFSproperties.ArtifactDbConnection -split ";")[0] -replace "Data Source=","" -split ",")[0]}
    catch{$SQLServer = ""}
    try {[string]$Port = $($($ADFSproperties.ArtifactDbConnection -split ";")[0] -replace "Data Source=","" -split ",")[1]
    if ($port -like  "*\*"){ $port =  $($port -split "\\")[0]}
     }
    catch {$Port =""}
    

$message += "`r`nChecking details of the ADFS Farm:`r`n"  
$message += "`r`nDisplayname: " + $ADFSproperties.displayname
$message += "`r`nHostname: " +$ADFSproperties.hostname
$message += "`r`nIdentifier: " +$ADFSproperties.Identifier

$message += "`r`nChecking Network avaliability:`r`n"


#Check of network avaliability 
foreach ($comp in $servers){
    try   {$network += tnc $comp -port 443}

    catch {$message += "`r`n$($error[0].psbase.exception.message)"
        [array]$failed +=$comp}    
    }  

if ($failed.count -gt 0 -and ($servers.count -ne  ($network.TcpTestSucceeded | ?{$_ -eq $True}).count)){
        $message += "`r`nCould not connect to all servers: `r`n"
        $message +=  "`r`n" + "$($failed | ft -Wrap | Out-String)"}

elseif ($failed.count -eq 0 -and ($servers.count -eq  ($network.TcpTestSucceeded | ?{$_ -eq $True}).count)) {
        $message += "`r`nAll ADFS servers are avaliable via network.`r`n" }

#Check of ADFS services 
   $message += "`r`n$($network | select ComputerName,TcpTestSucceeded,RemoteAddress | FT -wrap | Out-String)"
   $message += "`r`nChecking status of ADFS services:`r`n"

  try   {$services = Get-service *adfs*  | Select-Object DisplayName,Status }
  catch {$message +=  "`r`nCould not check ADFS services!`r`n"
         $message += "`r`n$($error[0].psbase.exception.message)"
            }

if ($services) {
    if ($($services.status | sort -Unique) -ne "Running") {
        $message +=  "`r`nServer has a stopped ADFS service:`r`n"
        $message +=  "`r`n$($services | ?{$_.status.value -ne "Running"} | ft -Wrap | Out-String)"
        $services | ?{$_.status.value -ne "Running"} | Start-Service
        }
    if ($($services.status | sort -Unique) -eq "Running") {     
        $message +=  "`r`nAll ADFS services are running .`r`n"}
        $message += "`r`n$($services | Select-Object PSComputerName,DisplayName,Status | FT -wrap | Out-String)"
        }

}



#Check of ADFS Certificates
$message +=  "`r`nChecking ADFS Certificates:"
try   {$certs += Get-AdfsCertificate}
catch {$message +=  "`r`nWas not able to check ADFS certificates:`r`n" 
	   $message += "`r`n$($error[0].psbase.exception.message)"
   }

if ($certs){
            $message +=  "`r`nSuccesfully checked certificates!`r`n" 
            [array]$cert_result = $certs.certificate | sort -Unique | select subject,thumbprint,NotAfter 
            $message += "`r`n" + $( $cert_result | FT -wrap | Out-String)
        foreach ($cert in $cert_result){
                    if ($cert.NotAfter -lt  (get-date)) {$message +=  "`r`nWarning an invalid certificate:" 
                    $message += "`r`n$($cert | ?{$_.NotAfter -lt  (get-date) }|FT -wrap | Out-String )"}
        }
    }


#Check of SQL availiability 

$message +=  "`r`n`r`nChecking SQL availiability:`r`n"
Try {$SQL = tnc "$($SQLServer)" -port $($port) } 
Catch {$message +=  "`r`nNot able to connect to SQL Server." }

if ($SQL) { $message += "`r`n" +$($SQL| select PSComputerName,ComputerName,RemotePort,RemoteAddress,TcpTestSucceeded | FT -wrap | Out-String) } 

$message += "`r`nLast boot time:"
$message += "`r`n$(Get-uptime|Out-String)"

#Evaluation of all checks 

if (($ADFSproperties) -and ($servers.count -eq  ($network.TcpTestSucceeded | ?{$_ -eq $True}).count) -and ($sql.TcpTestSucceeded -eq $True) `
-and $services.count -eq ($services.Status | ?{$_ -eq "Running"}).count  ){
 $message += "`r`n" + "Overall Status: OK"
 $ok = $true
 }
 
