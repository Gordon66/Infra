function Download-scripts{
[string]$url = @"
https://drive.google.com/file/d/14NK36rLCQXG9XdUkKQdcz6wTFgMOfWgZ
"@
Invoke-WebRequest -Uri $url -method GET -OutFile "C:\Users\cen67155\Documents\Backup - Scripts\Skripty\skripty.zip" -UseDefaultCredentials
}

Function search-scripts {
Param(
[Parameter(mandatory=$true,valuefrompipeline=$true,Position=0)]
[string]$folder, 

[Parameter(mandatory=$true,valuefrompipeline=$true,Position=1)]
[string]$query 
)

$query = $query -replace '[*\\~;(%?.:@/]', '\$&'
[array]$files = gci "$($folder)" -Recurse | ?{$_.Attributes -eq "Archive"}
foreach ($file in $files) {[string]$result  = Get-Content $file.fullname | Select-String "$($query)"
if (!([string]::IsNullOrEmpty($result))) {write-host $file.fullname -ForegroundColor Green ; $result}}
}