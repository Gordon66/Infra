Function search-string {
<#
   .SYNOPSIS
        Script for seartching a string in the files located in folder path 
   .DESCRIPTION
        Script for seartching a string in the files located in folder path 

        Script returns the found string context and file path

        Constrains:
              
                
    .INPUTS 
        
    .PARAMETER  folder
        folder with files You want to search through

    .PARAMETER  query
        string to be search for 
               
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


Param(
[Parameter(mandatory=$true,valuefrompipeline=$true,Position=0)]
[string]$folder, 

[Parameter(mandatory=$true,valuefrompipeline=$true,Position=1)]
[string]$query 
)

$query = $query -replace '[*\\~;(%?.:@/]', '\$&'
[array]$files = gci "$($folder)" -Recurse | ?{$_.Attributes -eq "Archive"}
foreach ($file in $files) {[string]$result  = Get-Content $file.fullname | Select-String "$($query)"
if (!([string]::IsNullOrEmpty($result))) {
write-host `r`n
write-host $($file.fullname) -ForegroundColor Green 
write-host `r`n 
$result}}
}