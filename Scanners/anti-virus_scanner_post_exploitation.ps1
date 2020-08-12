function getAntivirusName {  
        $wmiQuery = "SELECT * FROM AntiVirusProduct"                  
        $antivirus = Get-WmiObject -Namespace "root\SecurityCenter2" -Query $wmiQuery  @psboundparameters -ErrorVariable myError -ErrorAction 'SilentlyContinue'             

        if($antivirus){
            return $antivirus.displayName            
            }else{
                $alternateAntivirusQuery=WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct GET displayName /Format:List|?{$_.trim() -ne ""}|%{$_ -replace "displayName=",""}
                if ($alternateAntivirusQuery){                    
                    return $alternateAntivirusQuery
                    }else{
                        write-host "No antivirus software were detected. Hence, namespace querying errors."
                        $rawSearch=((get-wmiobject -class "Win32_Process" -namespace "root\cimv2" | where-object {$_.Name.ToLower() -match "antivirus|endpoint|protection|security|defender|msmpeng"}).Name | Out-String).Trim();
                        if($rawSearch){
                            return $rawSearch
                            }else{
                                return "No antivirus detected."
                                }
                        }
                
                } 
        }
getAntivirusName;
