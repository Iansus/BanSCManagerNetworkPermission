# Original resource https://p0w3rsh3ll.wordpress.com/2017/10/04/service-control-manager-acl-module/
# Adapted for PowerShell v2+ by François LELIEVRE - 24/04/2019
# Uncomment wanted action at the end of the script (ban / unban / show permissions)

Function Restore-SCManagerPermission {
<#
    .SYNOPSIS
        Restore the default SC Manager permissions

    .DESCRIPTION
        Restore the default SC Manager permissions by removing AccessDenied to NT AUTHORITY\NETWORK

    .EXAMPLE
        Restore-SCManagerPermission -Whatif

    .EXAMPLE
        Restore-SCManagerPermission -Verbose -Confirm:$false

#>
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
Param()
Begin {
    $HT = @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\ServiceGroupOrder\Security'
        ErrorAction = 'Stop'
    }
}
Process {
    if ($PSCmdlet.ShouldProcess(('Item: {0} Property: {1}' -f $HT['Path'],'Security'),'Change binary value')) {

        # Get current permissions
        $csd = $(
            try {
                New-Object -TypeName System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList (
                    $true,
                    $false,
                    ((Get-ItemProperty -Name Security @HT).Security),
                    0
                )
            } catch {
                New-Object -TypeName System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList (
                    $true,
                    $false,
                    ((& (Get-Command "$($env:SystemRoot)\System32\sc.exe") @('sdshow','scmanager'))[1])
                )
            }
        )

        $csd.DiscretionaryAcl | Where-Object { $_.SecurityIdentifier.Value -eq 'S-1-5-2' } | ForEach-Object {
            try {
                $csd.DiscretionaryAcl.RemoveAccessSpecific(
                    ($_.AceType -replace 'AccessDenied','Deny' -replace 'AccessAllowed','Allow'),
                    $_.SecurityIdentifier,
                    $_.AccessMask,
                    0,
                    0
                )
            } catch {
                Write-Warning -Message "Failed to remove access because $($_.Exception.Message)"
            }
        }
        # Commit changes
        try {
            $sddl = $csd.GetSddlForm([System.Security.AccessControl.AccessControlSections]::Access)
            $null = (& (Get-Command "$($env:SystemRoot)\System32\sc.exe") @('sdset','scmanager',"$($sddl)"))
            Write-Verbose -Message 'Successfully restored Service Control Mananger ACL' -Verbose
        } catch {
            Write-Warning -Message "Failed to restore Service Control Mananger ACL because $($_.Exception.Message)"
        }
    }
}
End {}
}

Function Set-SCManagerPermission {
<#
    .SYNOPSIS
        Set the hardened SC Manager permissions

    .DESCRIPTION
        Set the hardened SC Manager permissions by adding AccessDenied to NT AUTHORITY\NETWORK
    .EXAMPLE
        Set-SCManagerPermission -Whatif

    .EXAMPLE
        Set-SCManagerPermission -Verbose -Confirm:$false

#>
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
Param()
Begin {
    $HT = @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\ServiceGroupOrder\Security'
        ErrorAction = 'Stop'
    }
}
Process {
    if ($PSCmdlet.ShouldProcess(('Item: {0} Property: {1}' -f $HT['Path'],'Security'),'Change binary value')) {
        # Get current permissions
        $csd = $(
            try {
                New-Object -TypeName System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList (
                    $true,
                    $false,
                    ((Get-ItemProperty -Name Security @HT).Security),
                    0
                )
            } catch {
                New-Object -TypeName System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList (
                    $true,
                    $false,
                    ((& (Get-Command "$($env:SystemRoot)\System32\sc.exe") @('sdshow','scmanager'))[1])
                )
            }
        )
        # If already present
        if ($csd.DiscretionaryAcl | foreach-object { if ($_.SecurityIdentifier.Value -eq 'S-1-5-2') { return $True } }) {
            # Remove first
            $csd.DiscretionaryAcl | Where-Object { $_.SecurityIdentifier.Value -eq 'S-1-5-2' } | ForEach-Object {
                try {
                    $csd.DiscretionaryAcl.RemoveAccessSpecific(
                        ($_.AceType -replace 'AccessDenied','Deny' -replace 'AccessAllowed','Allow'),
                        $_.SecurityIdentifier,
                        $_.AccessMask,
                        0,
                        0
                    )
                } catch {
                    Write-Warning -Message "Failed to remove access because $($_.Exception.Message)"
                }
            }
        }
        # Add it now
        'S-1-5-2' | ForEach-Object {
            try {
                $csd.DiscretionaryAcl.AddAccess(
                    [System.Security.AccessControl.AccessControlType]::Deny,
                    [System.Security.Principal.SecurityIdentifier]"$($_)",
                    0xF003F, # int accessMask
                    0,
                    0
                )
                Write-Verbose -Message 'Successfully added AccessDenied for NT AUTHORITY\NETWORK'
            } catch {
                Write-Warning -Message "Failed to add access because $($_.Exception.Message)"
            }
        }
        # Commit changes
        try {
            # Reboot would be required with the following method
            # $data = New-Object -TypeName System.Byte[] -ArgumentList $csd.BinaryLength
            # $csd.GetBinaryForm($data,0)
            # Set-ItemProperty @HT -Name Security -Value $data
            $sddl = $csd.GetSddlForm([System.Security.AccessControl.AccessControlSections]::Access)
            $null = (& (Get-Command "$($env:SystemRoot)\System32\sc.exe") @('sdset','scmanager',"$($sddl)"))
            Write-Verbose -Message 'Successfully set binary ACL in the registry' -Verbose
        } catch {
            Write-Warning -Message "Failed to set Security in the registry because $($_.Exception.Message)"
        }
    }
}
End {}
}

Function Get-SCManagerPermission {
<#
    .SYNOPSIS
        Get the current SC Manager permissions

    .DESCRIPTION
        Get the current SC Manager permissions

    .EXAMPLE
        Get-SCManagerPermission

    .EXAMPLE
    Get-SCManagerPermission |
    Select Transl*,Secu*,AccessMask,AceType | ft -AutoSize

#>
[CmdletBinding()]
Param()
Begin {
    $HT = @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\ServiceGroupOrder\Security'
        ErrorAction = 'Stop'
    }
}
Process {
    $(
    try {
        New-Object -TypeName System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList (
            $true,
            $false,
            ((Get-ItemProperty -Name Security @HT).Security),
            0
        )
    } catch {
        New-Object -TypeName System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList (
            $true,
            $false,
            ((& (Get-Command "$($env:SystemRoot)\System32\sc.exe") @('sdshow','scmanager'))[1])
        )
    }
    ).DiscretionaryAcl |
    ForEach-Object {
        $_ | Add-Member -MemberType ScriptProperty -Name TranslatedSID -Value ({
            $this.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value
        }) -PassThru
    }

}
End {}
}

# Uncomment to print permissions over the SCManager
# Get-SCManagerPermission

# Uncomment to harden NT AUTHORITY\NETWORK permissions over the SCManager
Set-SCManagerPermission -Confirm:$False
Get-SCManagerPermission

# Uncomment to restore default permissions over the SCManager
# Restore-SCManagerPermission -Confirm:$False
# Get-SCManagerPermission