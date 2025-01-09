function Convert-BitStringToHexString {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$BitString
    )
    
    begin {
        if ($BitString.Length % 4 -ne 0) {
            Write-Error "BitString skal have en længde der er delelig med 4"
            return
        }

        $hexStringBuilder = New-Object System.Text.StringBuilder
        for ($index = 0; $index + 4 -le $BitString.Length; $index += 4) {
            $bits = $BitString.Substring($index, 4)
            $val = [Convert]::ToInt32($bits, 2)
            $hex = [Convert]::ToString($val, 16)
            $null = $hexStringBuilder.Append($hex)
        }
        $hexString = $hexStringBuilder.ToString()
        Write-Output $hexString
    }
    
    process {
        
    }
    
    end {
        
    }
}
function New-PSVariableList {
    [CmdletBinding(DefaultParameterSetName = 'Empty')]
    param (
        [Parameter(Mandatory, ParameterSetName = "Hashtable")]
        [hashtable]$Variables,
        [Parameter(Mandatory, ParameterSetName = "List")]
        [System.Collections.Generic.List[System.Management.Automation.PSVariable]]$VariableList,
        [object]$UnderscoreValue
    )
    
    begin {
        $list = New-Object System.Collections.Generic.List[System.Management.Automation.PSVariable]
        if ($PSCmdlet.ParameterSetName -eq "Empty") {
            Write-Output $list -NoEnumerate
        }
        elseif ($PSCmdlet.ParameterSetName -eq "List") {
            foreach ($var in $VariableList) {
                $list.Add($var)
            }
        }
        elseif ($PSCmdlet.ParameterSetName -eq "Hashtable") {
            foreach ($key in $Variables.Keys) {
                $list.Add([psvariable]::new($key, $Variables[$key]))
            }
        }

        if ($UnderscoreValue) {
            $list.Add([psvariable]::new("_", $UnderscoreValue))
        }

        Write-Output $list
    }
    
    process {
        
    }
    
    end {
        
    }
}
function Convert-UserToPayloadValues {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$Values,
        [PSTypeName('Glx.OS2iot.PayloadAdapter')]
        [object]$Adapter
    )
    
    begin {
        if ($null -eq $Adapter) {
            Write-Output $Values
        }
        else {
            $convertedValues = @{}
            $variableList = New-PSVariableList -Variables $Values
            foreach ($key in $Values.Keys) {
                $value = $Values[$key]
                if ($Adapter.PartLookup.ContainsKey($key)) {
                    $adapterPart = $Adapter.PartLookup[$key]
                    if ($adapterPart.ToPayload) {
                        $adapterVars = New-PSVariableList -VariableList $variableList -UnderscoreValue $value
                        $value = $adapterPart.ToPayload.InvokeWithContext($null, $adapterVars) | Select-Object -First 1
                    }
                    elseif ($adapterPart.Lookup) {
                        $stringValue = $value -as [string]
                        if ($adapterPart.Lookup.ContainsKey($stringValue)) {
                            $value = $adapterPart.Lookup[$stringValue]
                        }
                        else {
                            throw "Fejl, værdi '$value' for '$($part.Name)' er ikke i lookup-tabel for adapter: $($Adapter.Name)"
                        }
                    }
                }
                $convertedValues[$key] = $value
            }
            Write-Output $convertedValues
        }
    }
    
    process {
        
    }
    
    end {
        
    }
}
function Merge-UserAndDefaultPayloadTemplateValues {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [PSTypeName('Glx.OS2iot.PayloadTemplate')]
        [object]$Template,
        [Parameter(Mandatory)]
        [hashtable]$Values
    )
    
    begin {
        $outputValues = [ordered]@{}
        foreach ($part in $Template.Parts) {
            $value = $part.DefaultValue
            if ($Values.ContainsKey($part.Name)) {
                $value = $Values[$part.Name]
            }

            if ($part.Name -ne "RESERVED") {
                $outputValues[$part.Name] = $value
            }
        }

        foreach ($key in $Values.Keys) {
            if (!$outputValues.Contains($key)) {
                throw "Fejl, værdi '$key' er ikke en del af payload-skabelonen: $($this.Name)"
            }
        }

        Write-Output $outputValues
    }
    
    process {
        
    }
    
    end {
        
    }
}
function New-PayloadFromTemplateAndHex {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [PSTypeName('Glx.OS2iot.PayloadTemplate')]
        [object]$Template,
        [Parameter(Mandatory)]
        [string]$HexString
    )
    
    begin {
        $binaryString = ""
        foreach ($char in $HexString.ToCharArray()) {
            $int = [Convert]::ToInt32($char.ToString(), 16)
            $binaryString += [Convert]::ToString($int, 2).PadLeft(4, '0')
        }

        $payloadParts = New-List
        foreach ($part in $Template.Parts) {
            $partBits = $binaryString.Substring($part.Offset, $part.Bits)
            $partValue = [Convert]::ToInt64($partBits, 2)
            $payloadPart = New-OS2IotPayloadPart -Name $part.Name -Size $part.Size -Value $partValue -SizeUnit $part.SizeUnit
            $payloadParts.Add($payloadPart)
        }

        $payload = New-OS2IotPayload -Parts $payloadParts
        Write-Output $payload
    }
    
    process {
        
    }
    
    end {
        
    }
}
function New-PayloadFromTemplateAndValues {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ParameterSetName = "TemplateValues")]
        [Parameter(Mandatory, ParameterSetName = "TemplateHex")]
        [PSTypeName('Glx.OS2iot.PayloadTemplate')]
        [object]$Template,
        [Parameter(Mandatory, ParameterSetName = "TemplateValues")]
        [hashtable]$Values,
        [Parameter(ParameterSetName = "TemplateValues")]
        [PSTypeNameAttribute('Glx.OS2iot.PayloadAdapter')]
        [object]$Adapter
    )
    
    begin {
        $convertedValues = Convert-UserToPayloadValues -Values $Values -Adapter $Adapter
        $payloadValues = Merge-UserAndDefaultPayloadTemplateValues -Template $Template -Values $convertedValues

        $isValid = Test-PayloadTemplateValues -Values $payloadValues -Template $Template
        if ($isValid) {
            $payloadParts = New-List
            foreach ($templatePart in $Template.Parts) {
                $value = $payloadValues[$templatePart.Name]
                $payloadPart = New-OS2IotPayloadPart -Name $templatePart.Name -Size $templatePart.Size -Value $value -SizeUnit $templatePart.SizeUnit
                $payloadParts.Add($payloadPart)
            }
            
            $payload = New-OS2IotPayload -Parts $payloadParts
            Write-Output $payload
        }
    }
    
    process {
        
    }
    
    end {
        
    }
}
function Test-PayloadTemplateValues {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$Values,
        [Parameter(Mandatory)]
        [PSTypeName('Glx.OS2iot.PayloadTemplate')]
        [object]$Template
    )
    
    begin {
        $result = $true
        $varList = New-PSVariableList
        foreach ($part in $Template.Parts) {
            if ($part.Name -eq "RESERVED" -or !$Values.ContainsKey($part.Name)) {
                continue
            }

            $value = $Values[$part.Name]
            if ($value -lt $part.MinValue -or $value -gt $part.MaxValue) {
                $result = $false
                Write-Error "Fejl, værdi '$value' for '$($part.Name)' er udenfor tilladt interval: $($part.MinValue) - $($part.MaxValue)"
                break
            }
            $psVar = [psvariable]::new($part.Name, $value)
            $varList.Add($psVar)
        }

        
        if ($Template.ValidationScript) {
            $errorCountBefore = $Error.Count
            $Template.ValidationScript.InvokeWithContext($null, $varList)
            if ($Error.Count -gt $errorCountBefore) {
                return
            } 
        }

        Write-Output $result
    }
    
    process {
        
    }
    
    end {
        
    }
}
function Get-OS2iotApplication {
    [CmdletBinding()]
    param (
        <#[string]$Filter,
        [string]$OrderOn,#>
        [int]$OrganizationId,
        [int]$PageSize = 100
    )
    
    begin {
        $urlParams = @{}
        if ($Filter) {
            $urlParams.Add("sort", $Filter)
        }

        if ($OrderOn) {
            $urlParams.Add("orderOn", $OrderOn)
        }

        if ($OrganizationId) {
            $urlParams.Add("organizationId", $OrganizationId)
        }

        if ($PageSize) {
            $urlParams.Add("limit", $PageSize)
        }

        $results = Invoke-OS2iot -Endpoint "/application" -Method "GET" -UrlParams $urlParams
    }
    
    process {
        foreach ($result in $results) {
            $result.PSObject.TypeNames.Insert(0, "Glx.OS2iot.Application")
        }
    }
    
    end {
        Write-Output $results
    }
}
function Get-OS2iotApplicationDetails {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [int]$ApplicationId
    )
    
    begin {
        $results = Invoke-OS2iot -Endpoint "/application/$ApplicationId" -Method "GET"
    }
    
    process {
        foreach ($result in $results) {
            $result.PSObject.TypeNames.Insert(0, "Glx.OS2iot.ApplicationDetails")
        }
    }
    
    end {
        Write-Output $results
    }
}
function Connect-OS2iot {
    [CmdletBinding()]
    param (
        [string]$ApiKey,
        [Uri]$Url = "https://backend.os2iot.gate21.dk",
        [string]$ApiVersion = "v1"
    )
    
    begin {
        $script:_os2_connection_info = [PSCustomObject]@{
            IsConnected = $false
            ApiKey = $null
            ApiUrl = $null
            ApiVersion = $null
        }

        if (!$Url.IsAbsoluteUri) {
            $Url = [uri]"https://$Url"
        }

        $baseUrl = $Url.Scheme + "://" + $Url.Host.TrimEnd('/') + "/api/"
        $testUrl = $baseUrl + "$ApiVersion/healthcheck"

        $header = @{
            "x-api-key" = $ApiKey
        }

        $output = Invoke-RestMethod -Uri $testUrl -Headers $header
        if ($output -eq "OK") {
            $script:_os2_connection_info = [PSCustomObject]@{
                IsConnected = $true
                ApiKey = $ApiKey
                ApiUrl = $baseUrl
                ApiVersion = $ApiVersion
            }
        }
        else {
            Write-Error "Kunne ikke forbinde til OS2iot på url: '$testUrl' med den angivne API-nøgle."
        }
    }
    
    process {
        
    }
    
    end {
        
    }
}
function Invoke-OS2iot {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Endpoint,
        [string]$Method = "GET",
        [hashtable]$UrlParams,
        [object]$Body,
        [string]$ContentType
    )
    
    begin {
        $paginationLimit = 100
        if ($UrlParams -and $UrlParams.ContainsKey("limit")) {
            $paginationLimit = $UrlParams["limit"]
        }

        if ($script:_os2_connection_info.IsConnected -ne $true) {
            Write-Error "Der er ikke oprettet forbindelse til OS2iot. Opret forbindelse med Connect-OS2iot først"
            return
        }

        $connectionInfo = $script:_os2_connection_info

        $endpointUrl = $connectionInfo.ApiUrl
        $endpoint = $Endpoint.TrimStart('/')
        if ($Endpoint -match "v\d+") {
            $endpointUrl += $Endpoint
        }
        else {
            $endpointUrl += $connectionInfo.ApiVersion + "/" + $Endpoint
        }

        
        $objects = New-List
        do {
            $hasMoreData = $false
            $requestUrl = $endpointUrl
            if ($UrlParams) {
                $requestUrl += "?"
                $i = 0
                foreach ($key in $UrlParams.Keys) {
                    $requestUrl += "$key=$($UrlParams[$key])"
                    if ($i -lt $UrlParams.Count - 1) {
                        $requestUrl += "&"
                    }
                    $i++
                }
            }
            $params = @{
                UseBasicParsing = $true
                Uri             = $requestUrl
                Headers         = @{
                    "x-api-key" = $connectionInfo.ApiKey
                    "accept"    = "application/json;charset=utf-8"
                }
                Method          = $Method
            }

            if ($Body) {
                $params.Body = $Body
                if (!$ContentType) {
                    $ContentType = "application/json;charset=utf-8"
                }
            }
            if ($ContentType) {
                $params.ContentType = $ContentType
            }

            $result = Invoke-RestMethod @params
            $hasDataProp = $null -ne ($result.PSObject.Properties | Where-Object { $_.Name -eq "data" })
            if ($hasDataProp) {
                $objects.AddRange($result.data)
            }
            elseif ($null -ne $result) {
                if ($result -is [array] -and $result.Length -gt 0) {
                    $objects.AddRange($result)
                }
                else {
                    $objects.Add($result)
                }
            }

            if ($result.data -and $result.count -and $objects.count -lt $result.count) {
                $hasMoreData = $true
                if (!$UrlParams.ContainsKey("offset")) {
                    $UrlParams["offset"] = 0
                }
                $UrlParams["offset"] = $UrlParams["offset"] + $paginationLimit
            }
        }
        while ($hasMoreData)

        Write-Output $objects
    }
    
    process {
        
    }
    
    end {
        
    }
}
function Add-OS2iotDeviceDownlink {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [int]$DeviceId,
        [Parameter(ParameterSetName = 'Payload')]
        [PSTypeName('Glx.OS2iot.Payload')]
        [object]$Payload,
        [Parameter(ParameterSetName = 'RawPayload')]
        [object]$RawPayload,
        [int]$FPort = 1,
        [bool]$Confirmed = $true
    )
    
    begin {
        if ($RawPayload) {
            if ($RawPayload -is [string]) {
                $isBitString = $RawPayload -match '^[01]+$'
                $isHexString = $RawPayload -match '^[0-9A-Fa-f]+$'
                if ($isBitString) {
                    $Payload = ([System.Convert]::ToUInt64($RawPayload, 2) | ForEach-Object { $_.ToString("X2") }) -join ""
                }
                elseif ($isHexString) {
                    $Payload = $RawPayload
                }
                else {
                    Write-Error "RawPayload skal være en bit-streng, hex-streng eller et array af tal"
                    return
                }
            }
            else {
                $numberArray = $RawPayload -as [int64[]]
                if ($numberArray) {
                    $Payload = ($numberArray | ForEach-Object { $_.ToString("X2") }) -join ""
                }
                else {
                    Write-Error "RawPayload skal være en bit-streng, hex-streng eller et array af tal"
                    return
                }
            }
        }

        $data = @{
            data = $Payload.HexString
            port = $FPort
            confirmed = $Confirmed
        } | ConvertTo-Json
    }
    
    process {
        $result = Invoke-OS2Iot -Endpoint "/iot-device/$DeviceId/downlink" -Method Post -Body $data -ContentType "application/json"
        $result.PSObject.TypeNames.Insert(0, "Glx.OS2iot.Device.Downlink")
        Write-Output $result
    }
    
    end {
        
    }
}
function Get-OS2iotDevice {
    [CmdletBinding(DefaultParameterSetName = "DeviceId")]
    param (
        [Parameter(Mandatory, ParameterSetName = "DeviceId")]
        [int]$DeviceId,
        [Parameter(Mandatory, ParameterSetName = "All")]
        [switch]$All
    )
    
    begin {
        $results = $null
        if ($PSCmdlet.ParameterSetName -eq "DeviceId") {
            $results = Invoke-OS2iot -Endpoint "/iot-device/$DeviceId" -Method "GET"
        }
        elseif ($PSCmdlet.ParameterSetName -eq "All") {
            $results = New-List
            $apps = Get-OS2iotApplication
            foreach ($app in $apps) {
                foreach ($dev in $app.iotDevices) {
                    $results.Add($dev)
                }
            }
        }
    }
    
    process {
        foreach ($result in $results) {
            $result.PSObject.TypeNames.Insert(0, "Glx.OS2iot.Device")
        }
    }
    
    end {
        Write-Output $results
    }
}
function Get-OS2iotDeviceDownlink {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [int]$DeviceId,
        [ValidateSet("Queued", "Sent", "All")]
        [string]$Type = "Queued"
    )
    
    begin {
        $results = New-List
        if ($Type -in @("Queued", "All")) {
            $queued = Invoke-OS2iot -Endpoint "/iot-device/$DeviceId/downlink" -Method "GET"
            $results.AddRange($queued)
        }

        if ($Type -in @("Sent", "All")) {
            $sent = Invoke-OS2iot -Endpoint "/iot-device/$DeviceId/historicalDownlink/" -Method "GET"
            $results.AddRange($sent)
        }
    }
    
    process {
        foreach ($result in $results) {
            $result.PSObject.TypeNames.Insert(0, "Glx.OS2iot.Device.Downlink")
        }
    }
    
    end {
        Write-Output $results
    }
}
function Get-OS2iotDeviceStats {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [int]$DeviceId
    )
    
    begin {
        $results = Invoke-OS2iot -Endpoint "/iot-device/stats/$DeviceId" -Method "GET"
    }
    
    process {
        foreach ($result in $results) {
            $result.PSObject.TypeNames.Insert(0, "Glx.OS2iot.Device.Stats")
        }
    }
    
    end {
        Write-Output $results
    }
}
function Remove-OS2iotDevice {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [int]$DeviceId
    )
    
    begin {
        $null = Invoke-OS2iot -Endpoint "/iot-device/$DeviceId" -Method "DELETE"
    }
    
    process {
    }
    
    end {
    }
}
function Set-OS2iotDevice {
    [CmdletBinding(DefaultParameterSetName = "LoRaWAN")]
    param (
        [Parameter(Mandatory)]
        [int]$DeviceId,
        [ValidateNotNullOrWhiteSpace()]
        [string]$Name,
        [string]$Comment,
        [string]$CommentOnLocation,
        [int]$DeviceModelId,
        [decimal]$Latitude,
        [decimal]$Longitude,
        [System.Collections.Specialized.OrderedDictionary]$Metadata,
        [ValidateSet("AddOnly", "Merge", "Replace")]
        [string]$MetadataMode = "Merge",
        [Parameter(ParameterSetName = "LoRaWAN")]
        [int]$LoraDeviceProfileId,
        [Parameter(ParameterSetName = "LoRaWAN")]
        [int]$LoraOtaaApplicationKey,
        [Parameter(ParameterSetName = "LoRaWAN")]
        [bool]$LoraSkipFCntCheck,
        [Parameter(ParameterSetName = "SigFox")]
        [int]$SigfoxGroupId,
        [Parameter(ParameterSetName = "MQTTInternal")]
        [Parameter(ParameterSetName = "MQTTExternalPassword")]
        [Parameter(ParameterSetName = "MQTTExternalCertificate")]
        [ValidateSet("Certificate", "Password")]
        [string]$MqttAuthentication,
        [Parameter(ParameterSetName = "MQTTInternal")]
        [Parameter(ParameterSetName = "MQTTExternalPassword")]
        [string]$MqttUsername,
        [Parameter(ParameterSetName = "MQTTInternal")]
        [Parameter(ParameterSetName = "MQTTExternalPassword")]
        [securestring]$MqttPassword,
        [Parameter(ParameterSetName = "MQTTExternalPassword")]
        [Parameter(ParameterSetName = "MQTTExternalCertificate")]
        [string]$MqttUrl,
        [Parameter(ParameterSetName = "MQTTExternalPassword")]
        [Parameter(ParameterSetName = "MQTTExternalCertificate")]
        [int]$MqttPort,
        [Parameter(ParameterSetName = "MQTTExternalPassword")]
        [Parameter(ParameterSetName = "MQTTExternalCertificate")]
        [string]$MqttTopic,
        [Parameter(ParameterSetName = "MQTTExternalCertificate")]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$MqttCertificate
    )
    
    begin {
        $device = Get-OS2iotDevice -DeviceId $DeviceId
        if (!$device) {
            return
        }

        $currentvalues = @{
            "name" = $device.name
            "type" = $device.type
            "longitude" = $device.location.coordinates[0]
            "latitude" = $device.location.coordinates[1]
            "commentOnLocation" = $device.commentOnLocation
            "comment" = $device.comment
            "metadata" = $device.metadata | ConvertFrom-Json
            "deviceModelId" = $device.deviceModel.id
            "id" = $device.id
            "applicationId" = $device.application.id
        }

        if ($null -eq $currentvalues.metadata) {
            $currentvalues.metadata = [PSCustomObject]@{}
        }

        if ($device.lorawanSettings) {
            $currentvalues["lorawanSettings"] = $device.lorawanSettings
        }
        if ($device.sigfoxSettings) {
            $currentvalues["sigfoxSettings"] = $device.sigfoxSettings
        }
        if ($device.mqttInternalBrokerSettings) {
            $currentvalues["mqttInternalBrokerSettings"] = $device.mqttInternalBrokerSettings
        }
        if ($device.mqttExternalBrokerSettings) {
            $currentvalues["mqttExternalBrokerSettings"] = $device.mqttExternalBrokerSettings
        }

        $shouldUpdate = $false
        $propsToUpdate = New-List
        $nonLoraProps = @("SigfoxGroupId", "MqttAuthentication", "MqttUsername", "MqttPassword", "MqttUrl", "MqttPort", "MqttTopic", "MqttCertificate")
        $nonSigfoxProps = @("LoraDeviceProfileId", "LoraOtaaApplicationKey", "LoraSkipFCntCheck", "MqttAuthentication", "MqttUsername", "MqttPassword", "MqttUrl", "MqttPort", "MqttTopic", "MqttCertificate")
        $nonMqttInternalProps = @("LoraDeviceProfileId", "LoraOtaaApplicationKey", "LoraSkipFCntCheck", "SigfoxGroupId", "MqttUrl", "MqttPort", "MqttTopic", "MqttCertificate")
        $nonMqttExternalProps = @("LoraDeviceProfileId", "LoraOtaaApplicationKey", "LoraSkipFCntCheck", "SigfoxGroupId")
        $nonHttpProps = @("LoraDeviceProfileId", "LoraOtaaApplicationKey", "LoraSkipFCntCheck", "SigfoxGroupId", "MqttAuthentication", "MqttUsername", "MqttPassword", "MqttUrl", "MqttPort", "MqttTopic", "MqttCertificate")
    }
    
    process {
        $simpleProps = @("Name", "Comment", "CommentOnLocation", "DeviceModelId", "Latitude", "Longitude")
        foreach ($prop in $simpleProps) {
            if ($PSBoundParameters.ContainsKey($prop) -and $PSBoundParameters[$prop] -ne $currentvalues[$prop]) {
                $currentvalues[$prop] = $PSBoundParameters[$prop]
                $propsToUpdate.Add($prop)
            }
        }

        if ($PSBoundParameters.ContainsKey("Metadata")) {
            foreach ($key in $Metadata.Keys) {
                $metaValue = $Metadata[$key] -as [string]
                $propExists = $null -ne ($currentvalues.metadata.PSObject.Properties | Where-Object { $_.Name -eq $key })
                if (!$propExists) {
                    Add-Member -InputObject $currentvalues.metadata -MemberType NoteProperty -Name $key -Value $metaValue -Force
                    $propsToUpdate.Add("Metadata")
                }
                elseif ($MetadataMode -in @("Merge", "Replace") -and $currentvalues.metadata.$key -ne $metaValue) {
                    $currentvalues.metadata.$key = $metaValue
                    $propsToUpdate.Add("Metadata")
                }
            }
        }

        if ($device.type -eq "LORAWAN") {
            foreach ($prop in $nonLoraProps) {
                if ($PSBoundParameters.ContainsKey($prop)) {
                    Write-Error "Parameteren '$prop' kan ikke sættes på LoRaWAN devices"
                    return
                }
            }

            if ($PSBoundParameters.ContainsKey("LoraDeviceProfileId") -and $LoraDeviceProfileId -ne $currentvalues.lorawanSettings.deviceProfileId) {
                $currentvalues.lorawanSettings.deviceProfileId = $LoraDeviceProfileId
                $propsToUpdate.Add("LoraDeviceProfileId")
            }
            if ($PSBoundParameters.ContainsKey("LoraOtaaApplicationKey") -and $LoraOtaaApplicationKey -ne $currentvalues.lorawanSettings.otaaApplicationKey) {
                $currentvalues.lorawanSettings.otaaApplicationKey = $LoraOtaaApplicationKey
                $propsToUpdate.Add("LoraOtaaApplicationKey")
            }
            if ($PSBoundParameters.ContainsKey("LoraSkipFCntCheck") -and $LoraSkipFCntCheck -ne $currentvalues.lorawanSettings.skipFCntCheck) {
                $currentvalues.lorawanSettings.skipFCntCheck = $LoraSkipFCntCheck
                $propsToUpdate.Add("LoraSkipFCntCheck")
            }
        }
        elseif ($device.type -eq "SIGFOX") {
            foreach ($prop in $nonSigfoxProps) {
                if ($PSBoundParameters.ContainsKey($prop)) {
                    Write-Error "Parameteren '$prop' kan ikke sættes på Sigfox devices"
                    return
                }
            }

            if ($PSBoundParameters.ContainsKey("SigfoxGroupId") -and $SigfoxGroupId -ne $currentvalues.sigfoxSettings.groupId) {
                $currentvalues.sigfoxSettings.groupId = $SigfoxGroup
                $propsToUpdate.Add("SigfoxGroupId")
            }
        }
        elseif ($device.type -eq "GENERIC_HTTP") {
            foreach ($prop in $nonHttpProps) {
                if ($PSBoundParameters.ContainsKey($prop)) {
                    Write-Error "Parameteren '$prop' kan ikke sættes på Generic Http devices"
                    return
                }
            }
        }
        elseif ($device.type -eq "MQTT_INTERNAL_BROKER") {
            foreach ($prop in $nonMqttInternalProps) {
                if ($PSBoundParameters.ContainsKey($prop)) {
                    Write-Error "Parameteren '$prop' kan ikke sættes på MQTT Internal Broker devices"
                    return
                }
            }

            if ($PSBoundParameters.ContainsKey("MqttAuthentication") -and $MqttAuthentication -ne $currentvalues.mqttInternalBrokerSettings.authentication) {
                $currentvalues.mqttInternalBrokerSettings.authentication = $MqttAuthentication
                $propsToUpdate.Add("MqttAuthentication")
            }

            if ($currentvalues.mqttInternalBrokerSettings.authentication -eq "CERTIFICATE") {
                foreach ($prop in @("MqttUsername", "MqttPassword")) {
                    if ($PSBoundParameters.ContainsKey($prop)) {
                        Write-Error "Parameteren '$prop' kan ikke sættes på MQTT Internal Broker devices med certificate authentication"
                        return
                    }
                }
            }

            if ($PSBoundParameters.ContainsKey("MqttUsername") -and $MqttUsername -ne $currentvalues.mqttInternalBrokerSettings.username) {
                $currentvalues.mqttInternalBrokerSettings.username = $MqttUsername
                $propsToUpdate.Add("MqttUsername")
            }

            if ($PSBoundParameters.ContainsKey("MqttPassword") -and $MqttPassword -ne $currentvalues.mqttInternalBrokerSettings.password) {
                $currentvalues.mqttInternalBrokerSettings.password = $MqttPassword
                $propsToUpdate.Add("MqttPassword")
            }
        }
        elseif ($device.type -eq "MQTT_EXTERNAL_BROKER") {
            foreach ($prop in $nonMqttExternalProps) {
                if ($PSBoundParameters.ContainsKey($prop)) {
                    Write-Error "Parameteren '$prop' kan ikke sættes på MQTT External Broker devices"
                    return
                }
            }

            if ($PSBoundParameters.ContainsKey("MqttAuthentication") -and $MqttAuthentication -ne $currentvalues.mqttExternalBrokerSettings.authentication) {
                $currentvalues.mqttExternalBrokerSettings.authentication = $MqttAuthentication
                $propsToUpdate.Add("MqttAuthentication")
            }

            if ($currentvalues.mqttExternalBrokerSettings.authentication -eq "PASSWORD") {
                if ($PSBoundParameters.ContainsKey("MqttCertificate")) {
                    Write-Error "Parameteren 'MqttCertificate' kan ikke sættes på MQTT External Broker devices med password authentication"
                    return
                }
            }
            elseif ($currentvalues.mqttExternalBrokerSettings.authentication -eq "CERTIFICATE") {
                foreach ($prop in @("MqttUsername", "MqttPassword")) {
                    if ($PSBoundParameters.ContainsKey($prop)) {
                        Write-Error "Parameteren '$prop' kan ikke sættes på MQTT External Broker devices med certificate authentication"
                        return
                    }
                }
            }

            if ($PSBoundParameters.ContainsKey("MqttUrl") -and $MqttUrl -ne $currentvalues.mqttExternalBrokerSettings.url) {
                $currentvalues.mqttExternalBrokerSettings.url = $MqttUrl
                $propsToUpdate.Add("MqttUrl")
            }

            if ($PSBoundParameters.ContainsKey("MqttPort") -and $MqttPort -ne $currentvalues.mqttExternalBrokerSettings.port) {
                $currentvalues.mqttExternalBrokerSettings.port = $MqttPort
                $propsToUpdate.Add("MqttPort")
            }

            if ($PSBoundParameters.ContainsKey("MqttTopic") -and $MqttTopic -ne $currentvalues.mqttExternalBrokerSettings.topic) {
                $currentvalues.mqttExternalBrokerSettings.topic = $MqttTopic
                $propsToUpdate.Add("MqttTopic")
            }

            if ($PSBoundParameters.ContainsKey("MqttUsername") -and $MqttUsername -ne $currentvalues.mqttExternalBrokerSettings.username) {
                $currentvalues.mqttExternalBrokerSettings.username = $MqttUsername
                $propsToUpdate.Add("MqttUsername")
            }

            if ($PSBoundParameters.ContainsKey("MqttPassword") -and $MqttPassword -ne $currentvalues.mqttExternalBrokerSettings.password) {
                $currentvalues.mqttExternalBrokerSettings.password = $MqttPassword
                $propsToUpdate.Add("MqttPassword")
            }

            if ($PSBoundParameters.ContainsKey("MqttCertificate") -and $MqttCertificate -ne $currentvalues.mqttExternalBrokerSettings.certificate) {
                $currentvalues.mqttExternalBrokerSettings.certificate = $MqttCertificate
                $propsToUpdate.Add("MqttCertificate")
            }
        }
    }
    
    end {
        $metadataJson = $currentvalues.metadata | ConvertTo-Json -Compress
        $currentvalues.metadata = $metadataJson

        $body = $currentvalues | ConvertTo-Json -Compress
        if ($propsToUpdate.Count -gt 0) {
            $updatedDevice = Invoke-OS2Iot -Endpoint "/iot-device/$DeviceId" -Method "PUT" -Body $Body
            $updatedDevice.PSObject.TypeNames.Insert(0, "Glx.OS2iot.Device")
            Write-Output $updatedDevice
        }
        else {
            Write-Output $device
        }
    }
}
function ConvertFrom-OS2iotMetadataJson {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$MetadataJson,
        [Parameter(Mandatory, ParameterSetName = 'Template')]
        [PSTypeNameAttribute('Glx.OS2iot.MetadataTemplate')]
        [object]$Template
    )
    
    begin {
        $metadataObj = [ordered]@{
            Exists  = ![string]::IsNullOrWhiteSpace($MetadataJson)
            IsValid = $true
            Values  = [ordered]@{}
            MissingValues = New-List
        }

        if ($PSCmdlet.ParameterSetName -eq 'Template') {
            foreach ($part in $Template.Parts) {
                $metadataObj.Values[$part.Name] = $null
            }
        }

        if ($metadataObj.Exists) {
            $metadata = ConvertFrom-Json $MetadataJson

            if ($PSCmdlet.ParameterSetName -eq 'Template') {
                foreach ($part in $Template.Parts) {
                    $partName = $part.Name
                    $partExists = ($metadata.PSObject.Properties | Where-Object { $_.Name -eq $partName }).Count -gt 0
                    if ($partExists) {
                        $partValue = $metadata.$partName
                    }
                    else {
                        $metadataObj.MissingValues.Add($partName)
                        if ($part.DefaultValue) {
                            $partValue = $part.DefaultValue
                        }
                        else {
    
                        }
                    }

                    if ($part.ValueType -eq 'Integer') {
                        $partValue = [int]$partValue
                    }
                    elseif ($part.ValueType -eq 'Decimal') {
                        $partValue = [Decimal]$partValue
                    }
                    elseif ($part.ValueType -eq 'Bool') {
                        $partValue = [bool]$partValue
                    }
                    
                    if ($part.ValueTable) {
                        if ($null -eq $partValue -or !$part.ValueTable.ContainsKey($partValue)) {
                            $metadataObj.IsValid = $false
                            if ($part.OnInvalidValue -eq 'Stop') {
                                Write-Error "Ugyldig værdi for $partName i metadata"
                                return
                            }
                            elseif ($part.OnInvalidValue -eq 'UseDefault') {
                                $partValue = $part.ValueTable[$part.DefaultValue]
                            }
                        }
                        else {
                            $partValue = $part.ValueTable[$partValue]
                        }
                    }
                    if ($part.MinValue) {
                        if ($partValue -lt $part.MinValue) {
                            $metadataObj.IsValid = $false
                            if ($part.OnInvalidValue -eq 'Stop') {
                                Write-Error "Værdi for $partName i metadata er mindre end minimumsgrænse"
                                return
                            }
                            elseif ($part.OnInvalidValue -eq 'UseDefault') {
                                $partValue = $part.DefaultValue
                            }
                        }
                    }
                    if ($part.MaxValue) {
                        if ($partValue -gt $part.MaxValue) {
                            $metadataObj.IsValid = $false
                            if ($part.OnInvalidValue -eq 'Stop') {
                                Write-Error "Værdi for $partName i metadata er større end maksimumsgrænse"
                                return
                            }
                            elseif ($part.OnInvalidValue -eq 'UseDefault') {
                                $partValue = $part.DefaultValue
                            }
                        }
                    }

                    $metadataObj.Values[$partName] = $partValue
                }
            }
        }
    }
    
    process {
        
    }
    
    end {
        Write-Output $metadataObj
    }
}
function Get-OS2iotOrganization {
    [CmdletBinding()]
    param (
        [int]$PageSize = 100
    )
    
    begin {
        $urlParams = @{}

        if ($PageSize) {
            $urlParams.Add("limit", $PageSize)
        }

        $results = Invoke-OS2iot -Endpoint "/organization" -Method "GET" -UrlParams $urlParams
    }
    
    process {
        foreach ($result in $results) {
            $result.PSObject.TypeNames.Insert(0, "Glx.OS2iot.Organization")
        }
    }
    
    end {
        Write-Output $results
    }
}
function Get-OS2iotOrganizationDetails {
    [CmdletBinding()]
    param (
        [int]$OrganizationId
    )
    
    begin {
        $results = Invoke-OS2iot -Endpoint "/organization/$OrganizationId" -Method "GET"
    }
    
    process {
        foreach ($result in $results) {
            $result.PSObject.TypeNames.Insert(0, "Glx.OS2iot.OrganizationDetails")
        }
    }
    
    end {
        Write-Output $results
    }
}
function New-OS2iotPayload {
    [CmdletBinding(DefaultParameterSetName = "Parts")]
    param (
        [Parameter(Mandatory, ParameterSetName = "Parts")]
        [PSTypeName('Glx.OS2iot.PayloadPart')]
        [object[]]$Parts,
        [Parameter(Mandatory, ParameterSetName = "TemplateValues")]
        [Parameter(Mandatory, ParameterSetName = "TemplateHex")]
        [PSTypeName('Glx.OS2iot.PayloadTemplate')]
        [object]$Template,
        [Parameter(Mandatory, ParameterSetName = "TemplateValues")]
        [hashtable]$Values,
        [Parameter(ParameterSetName = "TemplateValues")]
        [PSTypeNameAttribute('Glx.OS2iot.PayloadAdapter')]
        [object]$Adapter,
        [Parameter(Mandatory, ParameterSetName = "TemplateHex")]
        [string]$HexString
    )
    
    begin {
        $bitStringBuilder = New-Object System.Text.StringBuilder

        if ($PSCmdlet.ParameterSetName -eq "TemplateValues") {
            New-PayloadFromTemplateAndValues -Template $Template -Values $Values -Adapter $Adapter
        }
        elseif ($PSCmdlet.ParameterSetName -eq "TemplateHex") {
            New-PayloadFromTemplateAndHex -Template $Template -HexString $HexString
        }
        elseif ($PSCmdlet.ParameterSetName -eq "Parts") {
            $payload = [PSCustomObject]@{
                PSTypeName = 'Glx.OS2iot.Payload'
                Values     = [ordered]@{}
                BitString  = ""
                HexString  = ""
                Parts      = $Parts
                Size       = 0
            }
    
            foreach ($part in $Parts) {
                $payload.Values[$part.Name] = $part.Value
                $null = $bitStringBuilder.Append($part.BitString)
                $payload.Size += $part.Bits
            }
                
            if ($bitStringBuilder.Length % 8 -ne 0) {
                Write-Error "Fejl, payload længde går ikke op i 8: '$($bitStringBuilder.Length)'"
                return
            }
    
            $payload.BitString = $bitStringBuilder.ToString()
            $payload.HexString = Convert-BitStringToHexString -BitString $payload.BitString
            
            Write-Output $payload
        }
        
        
    }
    
    process {
    }
    
    end {
        
    }
}
function New-OS2iotPayloadPart {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Name,
        [ValidateRange(1, 8)]
        [Parameter(Mandatory, ParameterSetName = 'Value')]
        [int]$Size,
        [Parameter(Mandatory, ParameterSetName = 'Value')]
        [int64]$Value,
        [Parameter(Mandatory, ParameterSetName = 'BitString')]
        [string]$BitString,
        [ValidateSet("Bit", "Hex", "Byte")]
        [string]$SizeUnit = "Bit"
    )
    
    begin {
        $bitSize = $Size
        if ($SizeUnit -eq "Hex") {
            $bitSize *= 4
        } elseif ($SizeUnit -eq "Byte") {
            $bitSize *= 8
        }

        $object = [PSCustomObject]@{
            PSTypeName = 'Glx.OS2iot.PayloadPart'
            Name = $Name
            Size = $Size
            SizeUnit = $SizeUnit
            Bits = $bitSize
            Value = $Value
            BitString = $BitString
            
        }
        
        if ($PSCmdlet.ParameterSetName -eq 'Value') {
            $object.BitString = [Convert]::ToString($Value, 2).PadLeft($bitSize, '0')
        } else {
            $object.Value = [Convert]::ToInt64($BitString, 2)
            $object.Size = $BitString.Length
        }

        Write-Output $object
    }
    
    process {
        
    }
    
    end {
        
    }
}
function New-OS2iotMetadataTemplate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [PSTypeName('Glx.OS2iot.MetadataTemplatePart')]
        [object[]]$Parts
    )
    
    begin {
        $template = [PSCustomObject]@{
            PSTypeName = 'Glx.OS2iot.MetadataTemplate'
            Name = $Name
            Parts = $Parts
            DefaultValues = [ordered]@{}
        }
    }
    
    process {
        foreach ($part in $parts) {
            $template.DefaultValues[$part.Name] = $part.DefaultValue
        }
    }
    
    end {
        Write-Output $template
    }
}
function New-OS2iotMetadataTemplatePart {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Name,
        [ValidateSet("String", "Integer", "Decimal", "Boolean", "DateTime")]
        [string]$ValueType,
        [System.Nullable[Decimal]]$MinValue = $null,
        [System.Nullable[Decimal]]$MaxValue = $null,
        [hashtable]$ValueTable,
        [object]$DefaultValue,
        [ValidateSet("Stop", "UseDefault")]
        [string]$OnInvalidValue = "UseDefault"
    )
    
    begin {
        $part = [PSCustomObject]@{
            PSTypeName = 'Glx.OS2iot.MetadataTemplatePart'
            Name = $Name
            ValueType = $ValueType
            DefaultValue = $DefaultValue
            MinValue = $MinValue
            MaxValue = $MaxValue
            ValueTable = $ValueTable
            OnInvalidValue = $OnInvalidValue
        }

        Write-Output $part
    }
    
    process {
    }
    
    end {
        
    }
}
function New-OS2iotPayloadAdapter {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [PSTypeName('Glx.OS2iot.PayloadAdapterPart')]
        [object[]]$Parts
    )
    
    begin {
        $adapter = [PSCustomObject]@{
            PSTypeName = 'Glx.OS2iot.PayloadAdapter'
            Name = $Name
            Parts = $Parts
            PartLookup = $Parts | New-Hashtable -KeyProperty Name -OnDuplicateKey KeepAll
        }

        Write-Output $adapter
    }
    
    process {
        
    }
    
    end {
        
    }
}
function New-OS2iotPayloadAdapterPart {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory, ParameterSetName = "ScriptBlock")]
        [scriptblock]$ToPayload,
        [Parameter(ParameterSetName = "ScriptBlock")]
        [scriptblock]$FromPayload,
        [Parameter(ParameterSetName = "Lookup")]
        [hashtable]$Lookup
    )
    
    begin {
        $reverseLookup = @{}
        if ($Lookup) {
            foreach ($key in $Lookup.Keys) {
                $value = $Lookup[$key]
                if ($reverseLookup.ContainsKey($value.ToString())) {
                    Write-Error "Fejl, der er flere nøgler med samme værdi: $value i lookup-tabel for adapter: $Name"
                    return
                }
                $reverseLookup[$value.ToString()] = $key
            }
        }

        $part = [PSCustomObject]@{
            PSTypeName = 'Glx.OS2iot.PayloadAdapterPart'
            Name = $Name
            ToPayload = $ToPayload
            FromPayload = $FromPayload
            Lookup = $Lookup
            ReverseLookup = $reverseLookup
        }
        Write-Output $part
    }
    
    process {
        
    }
    
    end {
        
    }
}
function New-OS2iotPayloadTemplate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [PSTypeName('Glx.OS2iot.PayloadTemplatePart')]
        [object[]]$Parts,
        [ValidateSet("Bit", "Hex", "Byte")]
        [string]$DefaultSizeUnit = "Bit",
        [scriptblock]$ValidationScript
    )
    
    begin {
        $template = [PSCustomObject]@{
            PSTypeName       = 'Glx.OS2iot.PayloadTemplate'
            Name             = $Name
            Size             = [int]($Parts | Measure-Object -Property Size -Sum | Select-Object -ExpandProperty Sum)
            Parts            = $Parts
            DefaultSizeUnit  = $DefaultSizeUnit
            ValidationScript = $ValidationScript
        }

        $offset = 0
        $partTable = @{}
        foreach ($part in $Parts) {
            if ($part.Name -ne "RESERVED" -and $partTable.ContainsKey($part.Name)) {
                Write-Error "Fejl, der er flere dele med samme navn: $($part.Name) i payload-skabelon: $Name"
                return
            }
            $part.Offset = $offset
            if (!$part.SizeUnit) {
                $part.SizeUnit = $DefaultSizeUnit
            }

            $sizeBits = $part.Size
            if ($part.SizeUnit -eq "Hex") {
                $sizeBits *= 4
            }
            elseif ($part.SizeUnit -eq "Byte") {
                $sizeBits *= 8
            }
            $part.Bits = $sizeBits

            $bitMaxValue = [Math]::Pow(2, $sizeBits) - 1
            if ($bitMaxValue -lt $part.MaxValue) {
                $part.MaxValue = $bitMaxValue
            }

            if ($MaxValue -gt $bitMaxValue) {
                Write-Error "MaxValue '$MaxValue' er større end maximum værdien for et $bits-bit tal: $bitMaxValue"
                return
            }
            elseif ($part.DefaultValue -gt $part.MaxValue -or $part.DefaultValue -lt $part.MinValue) {
                Write-Error "DefaultValue '$($part.DefaultValue)' er udenfor tilladt interval: $($part.MinValue) - $($part.MaxValue)"
                return
            }

            $offset += $sizeBits
            $template.Size = $offset
        }
        Write-Output $template
    }
    
    process {
        
    }
    
    end {
        
    }
}
function New-OS2iotPayloadTemplatePart {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Name,
        [ValidateRange(1, 8)]
        [Parameter(Mandatory)]
        [int]$Size,
        #[int]$Offset,
        [int]$MinValue = 0,
        [uint32]$MaxValue = [uint32]::MaxValue,
        [uint32]$DefaultValue,
        [ValidateSet("Bit", "Hex", "Byte")]
        [string]$SizeUnit
    )
    
    begin {
        $bits = $Size
        if ($SizeUnit -eq "Hex") {
            $bits *= 4
        } 
        elseif ($SizeUnit -eq "Byte") {
            $bits *= 8
        }

        $object = [PSCustomObject]@{
            PSTypeName = 'Glx.OS2iot.PayloadTemplatePart'
            Name = $Name
            Size = $Size
            SizeUnit = $SizeUnit
            Bits = $bits
            Offset = $null
            MinValue = $MinValue
            MaxValue = $MaxValue
            DefaultValue = $DefaultValue
        }

        Write-Output $object
    }
    
    process {
        
    }
    
    end {
        
    }
}


# SIG # Begin signature block
# MIIg5wYJKoZIhvcNAQcCoIIg2DCCINQCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUcIWXsfVqYquMhclCZ06OFgry
# khKgghsVMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0B
# AQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVk
# IElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz
# 7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS
# 5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7
# bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfI
# SKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jH
# trHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14
# Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2
# h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt
# 6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPR
# iQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ER
# ElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4K
# Jpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB/zAd
# BgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReuir/SS
# y4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAC
# hjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURS
# b290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAGBgRV
# HSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9mqyh
# hyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxSA8hO
# 0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/6Fmo
# 8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSMb++h
# UD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt9H5x
# aiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMIIGrjCCBJag
# AwIBAgIQBzY3tyRUfNhHrP0oZipeWzANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQG
# EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl
# cnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjIw
# MzIzMDAwMDAwWhcNMzcwMzIyMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQg
# UlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAxoY1BkmzwT1ySVFVxyUDxPKRN6mXUaHW0oPRnkyibaCw
# zIP5WvYRoUQVQl+kiPNo+n3znIkLf50fng8zH1ATCyZzlm34V6gCff1DtITaEfFz
# sbPuK4CEiiIY3+vaPcQXf6sZKz5C3GeO6lE98NZW1OcoLevTsbV15x8GZY2UKdPZ
# 7Gnf2ZCHRgB720RBidx8ald68Dd5n12sy+iEZLRS8nZH92GDGd1ftFQLIWhuNyG7
# QKxfst5Kfc71ORJn7w6lY2zkpsUdzTYNXNXmG6jBZHRAp8ByxbpOH7G1WE15/teP
# c5OsLDnipUjW8LAxE6lXKZYnLvWHpo9OdhVVJnCYJn+gGkcgQ+NDY4B7dW4nJZCY
# OjgRs/b2nuY7W+yB3iIU2YIqx5K/oN7jPqJz+ucfWmyU8lKVEStYdEAoq3NDzt9K
# oRxrOMUp88qqlnNCaJ+2RrOdOqPVA+C/8KI8ykLcGEh/FDTP0kyr75s9/g64ZCr6
# dSgkQe1CvwWcZklSUPRR8zZJTYsg0ixXNXkrqPNFYLwjjVj33GHek/45wPmyMKVM
# 1+mYSlg+0wOI/rOP015LdhJRk8mMDDtbiiKowSYI+RQQEgN9XyO7ZONj4KbhPvbC
# dLI/Hgl27KtdRnXiYKNYCQEoAA6EVO7O6V3IXjASvUaetdN2udIOa5kM0jO0zbEC
# AwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFLoW2W1N
# hS9zKXaaL3WMaiCPnshvMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9P
# MA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcB
# AQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggr
# BgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAI
# BgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQB9WY7Ak7Zv
# mKlEIgF+ZtbYIULhsBguEE0TzzBTzr8Y+8dQXeJLKftwig2qKWn8acHPHQfpPmDI
# 2AvlXFvXbYf6hCAlNDFnzbYSlm/EUExiHQwIgqgWvalWzxVzjQEiJc6VaT9Hd/ty
# dBTX/6tPiix6q4XNQ1/tYLaqT5Fmniye4Iqs5f2MvGQmh2ySvZ180HAKfO+ovHVP
# ulr3qRCyXen/KFSJ8NWKcXZl2szwcqMj+sAngkSumScbqyQeJsG33irr9p6xeZmB
# o1aGqwpFyd/EjaDnmPv7pp1yr8THwcFqcdnGE4AJxLafzYeHJLtPo0m5d2aR8XKc
# 6UsCUqc3fpNTrDsdCEkPlM05et3/JWOZJyw9P2un8WbDQc1PtkCbISFA0LcTJM3c
# HXg65J6t5TRxktcma+Q4c6umAU+9Pzt4rUyt+8SVe+0KXzM5h0F4ejjpnOHdI/0d
# KNPH+ejxmF/7K9h+8kaddSweJywm228Vex4Ziza4k9Tm8heZWcpw8De/mADfIBZP
# J/tgZxahZrrdVcA6KYawmKAr7ZVBtzrVFZgxtGIJDwq9gdkT/r+k0fNX2bwE+oLe
# Mt8EifAAzV3C+dAjfwAL5HYCJtnwZXZCpimHCUcr5n8apIUP/JiW9lVUKx+A+sDy
# Divl1vupL0QVSucTDh3bNzgaoSv27dZ8/DCCBrwwggSkoAMCAQICEAuuZrxaun+V
# h8b56QTjMwQwDQYJKoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoT
# DkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJT
# QTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTAeFw0yNDA5MjYwMDAwMDBaFw0z
# NTExMjUyMzU5NTlaMEIxCzAJBgNVBAYTAlVTMREwDwYDVQQKEwhEaWdpQ2VydDEg
# MB4GA1UEAxMXRGlnaUNlcnQgVGltZXN0YW1wIDIwMjQwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQC+anOf9pUhq5Ywultt5lmjtej9kR8YxIg7apnjpcH9
# CjAgQxK+CMR0Rne/i+utMeV5bUlYYSuuM4vQngvQepVHVzNLO9RDnEXvPghCaft0
# djvKKO+hDu6ObS7rJcXa/UKvNminKQPTv/1+kBPgHGlP28mgmoCw/xi6FG9+Un1h
# 4eN6zh926SxMe6We2r1Z6VFZj75MU/HNmtsgtFjKfITLutLWUdAoWle+jYZ49+wx
# GE1/UXjWfISDmHuI5e/6+NfQrxGFSKx+rDdNMsePW6FLrphfYtk/FLihp/feun0e
# V+pIF496OVh4R1TvjQYpAztJpVIfdNsEvxHofBf1BWkadc+Up0Th8EifkEEWdX4r
# A/FE1Q0rqViTbLVZIqi6viEk3RIySho1XyHLIAOJfXG5PEppc3XYeBH7xa6VTZ3r
# OHNeiYnY+V4j1XbJ+Z9dI8ZhqcaDHOoj5KGg4YuiYx3eYm33aebsyF6eD9MF5IDb
# PgjvwmnAalNEeJPvIeoGJXaeBQjIK13SlnzODdLtuThALhGtyconcVuPI8AaiCai
# JnfdzUcb3dWnqUnjXkRFwLtsVAxFvGqsxUA2Jq/WTjbnNjIUzIs3ITVC6VBKAOlb
# 2u29Vwgfta8b2ypi6n2PzP0nVepsFk8nlcuWfyZLzBaZ0MucEdeBiXL+nUOGhCjl
# +QIDAQABo4IBizCCAYcwDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwFgYD
# VR0lAQH/BAwwCgYIKwYBBQUHAwgwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZI
# AYb9bAcBMB8GA1UdIwQYMBaAFLoW2W1NhS9zKXaaL3WMaiCPnshvMB0GA1UdDgQW
# BBSfVywDdw4oFZBmpWNe7k+SH3agWzBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8v
# Y3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2
# VGltZVN0YW1waW5nQ0EuY3JsMIGQBggrBgEFBQcBAQSBgzCBgDAkBggrBgEFBQcw
# AYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMFgGCCsGAQUFBzAChkxodHRwOi8v
# Y2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hB
# MjU2VGltZVN0YW1waW5nQ0EuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQA9rR4fdplb
# 4ziEEkfZQ5H2EdubTggd0ShPz9Pce4FLJl6reNKLkZd5Y/vEIqFWKt4oKcKz7wZm
# Xa5VgW9B76k9NJxUl4JlKwyjUkKhk3aYx7D8vi2mpU1tKlY71AYXB8wTLrQeh83p
# XnWwwsxc1Mt+FWqz57yFq6laICtKjPICYYf/qgxACHTvypGHrC8k1TqCeHk6u4I/
# VBQC9VK7iSpU5wlWjNlHlFFv/M93748YTeoXU/fFa9hWJQkuzG2+B7+bMDvmgF8V
# lJt1qQcl7YFUMYgZU1WM6nyw23vT6QSgwX5Pq2m0xQ2V6FJHu8z4LXe/371k5QrN
# 9FQBhLLISZi2yemW0P8ZZfx4zvSWzVXpAb9k4Hpvpi6bUe8iK6WonUSV6yPlMwer
# wJZP/Gtbu3CKldMnn+LmmRTkTXpFIEB06nXZrDwhCGED+8RsWQSIXZpuG4WLFQOh
# tloDRWGoCwwc6ZpPddOFkM2LlTbMcqFSzm4cd0boGhBq7vkqI1uHRz6Fq1IX7TaR
# QuR+0BGOzISkcqwXu7nMpFu3mgrlgbAW+BzikRVQ3K2YHcGkiKjA4gi4OA/kz1YC
# sdhIBHXqBzR0/Zd2QwQ/l4Gxftt/8wY3grcc/nS//TVkej9nmUYu83BDtccHHXKi
# bMs/yXHhDXNkoPIdynhVAku7aRZOwqw6pDCCCA4wggX2oAMCAQICE14AAqxZem5S
# QqNkcs4AAAACrFkwDQYJKoZIhvcNAQELBQAwYDESMBAGCgmSJomT8ixkARkWAmRr
# MRgwFgYKCZImiZPyLGQBGRYIZ2xhZHNheGUxFjAUBgoJkiaJk/IsZAEZFgZpbnRl
# cm4xGDAWBgNVBAMTD0dMWC1neGFmMjExMC1DQTAeFw0yNDEwMjEwODM0MTdaFw0y
# NTEwMjEwODM0MTdaMCYxJDAiBgNVBAMTG0dYQUYxNTIxLmludGVybi5nbGFkc2F4
# ZS5kazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALCE1bLoq230b+5D
# PTMFqEiiZaVL1HGhXrC/B+zMJrfJ3BAhitllb6ST32bB5UuWJCOCfP9FfOC/xb5A
# QYUz7nfSmlixyuB9iMJKd6C4mzf0xVGYFx5mCc3YxGhG0OmUAMifv+hJ5lDY/bra
# o0/C2lk0U0G4KQcNIDaVsv2ZISsa9u2gjESsZC6++NdEcladQvcQZaAtp7zuJcX8
# aPLPhGV139uypg2/sYsKPPNv72a91hn4hoQrC5WT/XtI911ZUXGrHYIu/HnlsRvF
# 64TukwdGfIIflallDye1A0WefkfXVBc46PhXeCSUvZRwhGX+WoZnYLj+bJ5A7wo7
# rpNTxjUCAwEAAaOCA/kwggP1MDwGCSsGAQQBgjcVBwQvMC0GJSsGAQQBgjcVCIT5
# kU2mgE6CtYcnhavTeIPCkXt0gvPPJYadyTcCAWQCAQEwJwYDVR0lBCAwHgYIKwYB
# BQUHAwEGCCsGAQUFBwMDBggrBgEFBQcDAjALBgNVHQ8EBAMCBaAwMwYJKwYBBAGC
# NxUKBCYwJDAKBggrBgEFBQcDATAKBggrBgEFBQcDAzAKBggrBgEFBQcDAjAdBgNV
# HQ4EFgQUr8X1In9ftHsDj/0cZ8HQSJ7AQ88wHwYDVR0jBBgwFoAUxCoweWCVIypI
# 0Nc3X/nhSEoeQbgwggEgBgNVHR8EggEXMIIBEzCCAQ+gggELoIIBB4aBwWxkYXA6
# Ly8vQ049R0xYLWd4YWYyMTEwLUNBLENOPUdYQUYyMTEwLENOPUNEUCxDTj1QdWJs
# aWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9u
# LERDPWludGVybixEQz1nbGFkc2F4ZSxEQz1kaz9jZXJ0aWZpY2F0ZVJldm9jYXRp
# b25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnSGQWh0
# dHA6Ly9HWEFGMjExMC5pbnRlcm4uZ2xhZHNheGUuZGsvQ2VydEVucm9sbC9HTFgt
# Z3hhZjIxMTAtQ0EuY3JsMIIBbQYIKwYBBQUHAQEEggFfMIIBWzCBuAYIKwYBBQUH
# MAKGgatsZGFwOi8vL0NOPUdMWC1neGFmMjExMC1DQSxDTj1BSUEsQ049UHVibGlj
# JTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixE
# Qz1pbnRlcm4sREM9Z2xhZHNheGUsREM9ZGs/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29i
# amVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwaQYIKwYBBQUHMAKGXWh0
# dHA6Ly9HWEFGMjExMC5pbnRlcm4uZ2xhZHNheGUuZGsvQ2VydEVucm9sbC9HWEFG
# MjExMC5pbnRlcm4uZ2xhZHNheGUuZGtfR0xYLWd4YWYyMTEwLUNBLmNydDAzBggr
# BgEFBQcwAYYnaHR0cDovL0dYQUYyMTEwLmludGVybi5nbGFkc2F4ZS5kay9vY3Nw
# MCYGA1UdEQQfMB2CG0dYQUYxNTIxLmludGVybi5nbGFkc2F4ZS5kazBNBgkrBgEE
# AYI3GQIEQDA+oDwGCisGAQQBgjcZAgGgLgQsUy0xLTUtMjEtMTM2MDAwMzc5NC01
# MDAzMzA5NTAtOTUyMjk4Ni0xNTEyOTYwDQYJKoZIhvcNAQELBQADggIBAC/gVJ6k
# ociarQaS3rv4TAXOBMm7wDmJhjhsa2Qq03QNknOZAYvEfCYgbaf+ISwdPUIZ3PM4
# Y1zfP3aiWWosYY6JERGaxq5VF4Hw4+doLKWWb+G2DJjru8KXG+oFDGGX4RLrl5qP
# kA4FbBHsqAqTtou0vFvLadTsZujQ8dxpRN1txcz/PNN8xi6Yf2BUWrFwrJCCAMTa
# pqSQK3CfFaKfbn4Wayx0fZg+YFs85+DNOVPjThSHirbNXSzhs6PvNz1e2znLl3Qd
# UQpnW4WTBkMYjA5Kfbdlzrg4S3qQwfdIumWzPCXim7fzU0ORbM/foUDSM5rfNTZA
# rW+7xYX16Xnp2TzruryLXRruB1QbSJfhWHiyMyxCI33QnaflFowXQjPk+/AXFOe3
# x775X8aFRp5qmQnVHu6e3ws+94BsG/XhYERIUGReSeaZ4VRB575zFFeU6C22sP7x
# IRFWVQD7PHEXpuc5O6RuPDVi1mbZw4DNXkwOmAJ/k2NY3Sao3PGVHkjWjLFiKDI0
# khR4zAp6DiqCvdtB6da+/1nG7cvOJem9ivpgIyyyrej2BUNfBsh6m667ZUeckp++
# ZPU9DtPeZul/IKYhzCKS67ms7kihGd5kfqnkeUWR/S0uyK446mFgxSJZ0UXz23iF
# Ys3cjW0l3TjjkTLl39wXQnbP2S2qzAnITgOvMYIFPDCCBTgCAQEwdzBgMRIwEAYK
# CZImiZPyLGQBGRYCZGsxGDAWBgoJkiaJk/IsZAEZFghnbGFkc2F4ZTEWMBQGCgmS
# JomT8ixkARkWBmludGVybjEYMBYGA1UEAxMPR0xYLWd4YWYyMTEwLUNBAhNeAAKs
# WXpuUkKjZHLOAAAAAqxZMAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKAC
# gAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsx
# DjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQYevo14g5Wcv2vLrRy/zHm
# Lb4UzzANBgkqhkiG9w0BAQEFAASCAQCW8po35q3voTKtfWTeA8DV3lwrzwPLseCO
# nQOpA9D+OP7CBSGSyU5HNsCrEwJuDCVjGlUAUXolHdHdotGq4lR7zD1gfWsTzhC/
# TBFm2iZRG1DOcOmfoT+MEzMb2G3MnFF/bDUTLffmFHmhNsS6fJW0L7fD/eKp2jdQ
# Cz6m/+25ZYP+22ex//HpF1FaNa3zhcAjmj68zhWsgU7fdu8RzxsMUgvw0FvDPJpd
# Vcy1fPRJYQmLznHU5noil7HB9ja6j46R/zqLRYL4z3mGiUiPcrE43yyDi17djP0b
# QoEC+stVRgZqzNiPBhJ55CiUjmNKYH4BrTC/HRMCrcZKbmA2+0dLoYIDIDCCAxwG
# CSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoT
# DkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJT
# QTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQC65mvFq6f5WHxvnpBOMzBDAN
# BglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZI
# hvcNAQkFMQ8XDTI0MTIxNzIyMjcyMlowLwYJKoZIhvcNAQkEMSIEIDACLZeUZDUs
# zp+/rG1KgOmk2FAGlcv0s6yIiMUyaSHDMA0GCSqGSIb3DQEBAQUABIICAC8TYCDj
# haekUAyUtz2kqEDew9vGSs9DhK7beBTznDgIMGLI0vZzt3GIN+f27848UnUadtmA
# qoXZMdnXNao2gt/YPA6rplDJGQ2+9dsYRmcXaaPAmBnKM+908dklTMispGIZJjJn
# DXzM8bGT4ZBs/oCQlJ/T5fIxlksGwrkDbSyPQxmV0GEQYx8TT3zXS5PjKgDG7x84
# QVrFlJhfrJAmv3oPQWFmg8dAtHQnyh1nYIHjuMZTWlAgWSEIjhnycnxqBWEW41pZ
# dci4avj9DGtG4BfaMJbkJ+YtDUGTzzCMqOkU+hCUoN2wa1u9muQ4iZSwCws40da8
# uhrDyEvO24Woz6uF01Xl2BF9JmkE9vTGryb7lONZfq1crJ83viCSYyAcKwgm3MkW
# 4KnHyq1WZZlKikpE4wXCnwIzQpG6Qy7cKoWDNGlJ9aikB9iEksn2YbsJdCuovmhT
# V5WjXcKYaiLrqJauFbR5bgh57oVTUnJorhdcjSGARVxqNpU1b+/pClPQtogoFeSJ
# /Al+KSQ99lbebpwyZdQ2inVONSSdnCt9McHDTWNifEb7Vnf0JpLZAHLY8nWupOUZ
# N37nhATM5kjz29mrEONgvkl/OQodPwrsFLG7x+8sGpyoAYIEa++7lhwALK94YxKk
# i6OcviuHdZvRlFOLdZh5XRiLIVF195EIs74G
# SIG # End signature block
