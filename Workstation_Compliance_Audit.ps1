#Registry Locations
#HKEY_CLASSES_ROOT   = 2147483648 (HKCR)
#HKEY_CURRENT_USER   = 2147483649 (HKCU)
#HKEY_LOCAL_MACHINE  = 2147483650 (HKLM)
#HKEY_USERS          = 2147483651 (HKU)
#HKEY_CURRENT_CONFIG = 2147483653 (HKCC)

#Registry Keys
$registryAudit = Import-Csv -Path .\ComplianceTest.csv -Header CIS, Key, Value, Location, Setting | Select -Skip 1 #Skips Header in CSV
$device = (Get-WmiObject win32_computersystem).DNSHostName+"."+(Get-WmiObject win32_computersystem).Domain

$wmi = get-wmiobject -list "StdRegProv" -namespace root\cimv2


#Check device compliance to loaded ruleset
$registryAudit | ForEach-Object {
    $cis = $_.CIS
    #Convert root location into value needed
    switch($_.Location){
        HKCR {$root = "2147483648"; break} 
        HKCU {$root = "2147483649"; break} 
        HKLM {$root = "2147483650"; break} 
        HKU  {$root = "2147483651"; break} 
        HKCC {$root = "2147483653"; break} 
    }
    #Export noncompliant settings (Currently just write to host)
    if ($wmi.GetDWORDValue($root,$_.Key,$_.Value).uvalue -ne $_.Setting) {
        $compliant = "Not Compliant"
        Write-Host "$device is $compliant with $cis"
    }
} 

