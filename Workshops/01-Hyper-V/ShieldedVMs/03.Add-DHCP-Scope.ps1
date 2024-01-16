# Configure VMs
# R-DC-1
        $UserName = "Red\Administrator"
        $Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
        $psCred = New-Object System.Management.Automation.PSCredential($UserName, $Password)

        Invoke-Command -VMName R-DC-1 -Credential $psCred -ScriptBlock {
            Install-WindowsFeature -Name "DHCP" -IncludeManagementTools -IncludeAllSubFeature -Restart
            Add-DhcpServerInDC -DnsName R-DC-1.red.contoso.com -IPAddress 172.16.100.11
            Set-ItemProperty –Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12 –Name ConfigurationState –Value 2
            Set-DhcpServerv4DnsSetting -ComputerName "R-DC-1.red.contoso.com" -DynamicUpdates "Always" -DeleteDnsRRonLeaseExpiry $True
            Add-DhcpServerv4Scope -name "Corpnet" -StartRange 172.16.100.1 -EndRange 172.16.100.254 -SubnetMask 255.255.255.0 -State Active
            Add-DhcpServerv4ExclusionRange -ScopeID 172.16.100.0 -StartRange 172.16.100.1 -EndRange 172.16.100.49
            Set-DhcpServerv4OptionValue -OptionID 3 -Value 172.16.100.1 -ScopeID 172.16.100.0 -ComputerName R-DC-1.red.contoso.com
            Set-DhcpServerv4OptionValue -DnsDomain red.contoso.com -DnsServer 172.16.100.11
        }