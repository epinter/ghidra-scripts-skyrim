$directories = @('include', 'src')
$offsetTableAe = @{ }
$offsetTableSe = @{ }

Set-Content -Path "clib-se.rename" -Value $null
Set-Content -Path "clib-ae.rename" -Value $null
Set-Content -Path "clib-se-code.rename" -Value $null
Set-Content -Path "clib-ae-code.rename" -Value $null
Set-Content -Path "clib-se-offsets.rename" -Value $null
Set-Content -Path "clib-ae-offsets.rename" -Value $null

foreach ($d in $directories) {
    foreach ($file in (Get-ChildItem -Recurse -File -Include '*.cpp','*.h' $d)) {
        $ln = 0
        $usingFound = -1
        $functionName = ''
        foreach ($line in (Get-Content $file)) {
            $ln++
            $offsetSe = -1
            $offsetAe = -1
            if ($line -match '.*\busing\b[^=]*=\s*\bdecltype\b\s*\(&([^)]+)\)\s*;') {
                $functionName = $( $Matches.1 ) -replace '\s', ''
                $usingFound = $ln
                continue
            }
            elseif ($line -match '.*\bREL::Relocation\b<[^{(]*\s*[{(]\s*\bRELOCATION_ID\b\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)\s*[})]' -and $usingFound -eq ($ln - 1)) {
                $offsetSe = $( $Matches.1 )
                $offsetAe = $( $Matches.2 )
            }
            elseif ($line -match '.*\bREL::Relocation\b<[^{(]*\s*[{(]\s*\bOffset::\b.*' -and $usingFound -eq ($ln - 1)) {
                $names = $functionName -split '::'
                $className = $names[0]
                $methodName = $names[1]
                foreach ($ol in (Get-Content "include/RE/Offsets.h")) {
                    if ($ol -match '\s*namespace\b\s*' + [regex]::escape($className) + '.*') {
                        $namespaceFound = $true
                    }
                    elseif ( $ol -match '\s*namespace\b\s*') {
                        $namespaceFound = $false
                    }
                    if ($namespaceFound -and $ol -match '\s*constexpr\s+auto\s+' + $methodName + '\s*=\s*\bRELOCATION_ID\b\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)\s*;') {
                        $offsetSe = $( $Matches.1 )
                        $offsetAe = $( $Matches.2 )
                        #Write-Output "---from offsets $functionName"
                        break
                    }
                }
            }
            else {
                if ($functionName -ne '') {
                    #Write-Output "reset $($functionName)"
                }
                $usingFound = -1
                $functionName = ''
            }

            if ($offsetSe -gt -1 -and $offsetAe -gt -1) {
                $outFuncName = $functionName -replace '<.*>', ''
                #Write-Output "functionName:'$($outFuncName)'; se:'$($offsetSe)'; ae:'$($offsetAe)'"
                Add-Content -Path "clib-se-code.rename" -Value "$offsetSe $( $outFuncName )_*"
                Add-Content -Path "clib-ae-code.rename" -Value "$offsetAe $( $outFuncName )_*"
                try {
                    if ([int]$offsetSe -gt 0) {
                        $offsetTableSe.Add([int]$offsetSe, $outFuncName)
                    }
                    if ([int]$offsetAe -gt 0) {
                        $offsetTableAe.Add([int]$offsetAe, $outFuncName)
                    }
                }
                catch {
                }
                $usingFound = -1
                $functionName = ''
            }
        }
    }
}

$offsetClass = ''
foreach ($ol in (Get-Content "include/RE/Offsets.h")) {
    if ($ol -match '\s*namespace\b\s\b([^\s$]*)\b') {
        $offsetClass = $( $Matches.1 )
    }
    elseif($ol -match '\s*constexpr\s+auto\s+([^=]*)=\s*RELOCATION_ID\b\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)\s*;') {
        $methodName = $( $Matches.1 ) -replace '\s', ''
        $offsetSe = $( $Matches.2 )
        $offsetAe = $( $Matches.3 )
        $outFuncName = $offsetClass + "::" + $methodName
        #Write-Output "------- found $outFuncName $offsetSe $offsetAe"
        Add-Content -Path "clib-ae-offsets.rename" -Value "$offsetAe $( $outFuncName )_*"
        Add-Content -Path "clib-se-offsets.rename" -Value "$offsetSe $( $outFuncName )_*"
        try {
            if (!$offsetTableSe.ContainsKey([int]$offsetSe) -and [int]$offsetSe -gt 0) {
                $offsetTableSe.Add([int]$offsetSe, $outFuncName)
            }
            if (!$offsetTableAe.ContainsKey([int]$offsetAe) -and [int]$offsetAe -gt 0) {
                $offsetTableAe.Add([int]$offsetAe, $outFuncName)
            }
            $offsetTableAe.Add([int]$offsetAe, $outFuncName)
        }
        catch {
        }
    }
}

foreach ($h in ($offsetTableSe.GetEnumerator() | Sort-Object -property:Name)) {
    if ($h.Name -gt 0) {
        Add-Content -Path "clib-se.rename" -Value "$( $h.Name ) $( $h.Value )_*"
    }
}
foreach ($h in ($offsetTableAe.GetEnumerator() | Sort-Object -property:Name)) {
    if ($h.Name -gt 0) {
        Add-Content -Path "clib-ae.rename" -Value "$( $h.Name ) $( $h.Value )_*"
    }
}
