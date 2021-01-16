$Password = ConvertTo-SecureString "P@ssWord_Here!" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential "domain\username", $Password

#Registry Locations
#HKEY_CLASSES_ROOT   = 2147483648 (HKCR)
#HKEY_CURRENT_USER   = 2147483649 (HKCU)
#HKEY_LOCAL_MACHINE  = 2147483650 (HKLM)
#HKEY_USERS          = 2147483651 (HKU)
#HKEY_CURRENT_CONFIG = 2147483653 (HKCC)

#Registry Keys
$registryAudit = Import-Csv -Path .\ComplianceTest.csv -Header CIS, Key, Value, Location, Setting | Select -Skip 1 #Skips Header in CSV

#Values
$devices = Import-Csv -Path .\devices.csv -Header Device | Select -Skip 1 #Skips header in CSV

$devices | Foreach-Object {
    $device = $_ | Select-Object -ExpandProperty Device
    #Local Check
    if((Get-WmiObject win32_computersystem).DNSHostName+"."+(Get-WmiObject win32_computersystem).Domain -eq $_.Device) {
        $wmi = get-wmiobject -list "StdRegProv" -computername $_.Device
    } else {
        $wmi = get-wmiobject -list "StdRegProv" -computername $_.Device -credential $credential
    }

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
}
