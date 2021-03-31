###########################################################
<# 
## Instructions ##

# Setup
- [stop neo4j service if running]
- uncomment following in neo4j.conf and save change
#dbms.security.auth_enabled=false
[will disable auth for Localhost only]
- start neo4j service
- load watchdog.ps1

# Basic usage
-Single Group:
$Data = Datadog <groupname>

-Default Group List:
$Data = WatchDog <domainname>

-TotalImpact
$Data | TotalImpact

-Text Report:
$Data | ReportDog 

##
#>

#################################################### Vars

## Group List [Customize if needed]
$GroupList = @(
    <###############| NAME                                       |SID [regex]             #>
    <######################################################################################>
    [PSCustomObject]@{Name='Account Operators'                   ;SID='S-1-5-32-548'      }
    [PSCustomObject]@{Name='Administrators'                      ;SID='S-1-5-32-544'      }
    [PSCustomObject]@{Name='Allowed RODC Password Replication'   ;SID='^S-1-5-21-.*-571$' }
    [PSCustomObject]@{Name='Backup Operators'                    ;SID='S-1-5-32-551'      }
    [PSCustomObject]@{Name='Certificate Service DCOM Access'     ;SID='S-1-5-32-574'      }
    [PSCustomObject]@{Name='Cert Publishers'                     ;SID='^S-1-5-21-.*-517$' }
    [PSCustomObject]@{Name='Distributed DCOM Users'              ;SID='S-1-5-32-562'      }
    [PSCustomObject]@{Name='Domain Admins'                       ;SID='^S-1-5-21-.*-512$' }
    [PSCustomObject]@{Name='Domain Controllers'                  ;SID='^S-1-5-21-.*-516$' }
    [PSCustomObject]@{Name='Enterprise Admins'                   ;SID='S-1-5-21-.*-519'      }#HeadOnly
    [PSCustomObject]@{Name='Event Log Readers'                   ;SID='S-1-5-32-573'      }
    [PSCustomObject]@{Name='Group Policy Creators Owners'        ;SID='^S-1-5-21-.*-520$' }
    [PSCustomObject]@{Name='Hyper-V Admistrators'                ;SID='S-1-5-32-578'      }
    [PSCustomObject]@{Name='Pre-Windows 2000 compatible Access'  ;SID='S-1-5-32-554'      }
    [PSCustomObject]@{Name='Print Operators'                     ;SID='S-1-5-32-550'      }
    [PSCustomObject]@{Name='Protected Users'                     ;SID='^S-1-5-21-.*-525$' }
    [PSCustomObject]@{Name='Remote Desktop Users'                ;SID='S-1-5-32-555'      }
    [PSCustomObject]@{Name='Schema Admins'                       ;SID='S-1-5-21-.*-518'      }#HeadOnly
    [PSCustomObject]@{Name='Server Operators'                    ;SID='S-1-5-32-549'      }
    [PSCustomObject]@{Name='Incoming Forest Trust Builders'      ;SID='S-1-5-32-557'      }#HeadOnly
    [PSCustomObject]@{Name='Cryptographic Operators'             ;SID='S-1-5-32-569'      }
    [PSCustomObject]@{Name='Key Admins'                          ;SID='^S-1-5-21-.*-526$' }#HeadOnly
    [PSCustomObject]@{Name='Enterprise Key Admins'               ;SID='^S-1-5-21-.*-527$' }#HeadOnly
    )###################### Add more SIDS if needed... ####################################
    


Enum ScanType{
    Mini
    MiniX
    Mimi
    MimiX
    Standard
    StandardX
    Advanced
    AdvancedX
    Extreme
    ExtremeX
    Custom
    }

####################################################### DataDog Obj

# DataDog Object format
Class DataDog{
    [String]$Group
    [String]$SID
    [String]$Description
    [int]$DirectMbrCount
    [int]$NestedMbrCount
    [int]$PathCount
    [int]$UserPathCount
    [Array]$NodeWeight
    [String[]]$Cypher   
    }

###########################################################

<#
.Synopsis
   Time
.DESCRIPTION
   Time
.EXAMPLE
   Time
#>
function Time{Get-Date -F hh:mm:ss}

###########################################################

<#
.Synopsis
   Invoke Cypher
.DESCRIPTION
   Post Cypher Query to REST API
   Cypher $Query [$Params] [-expand <prop,prop>]
   Post Cypher Query to BH
.EXAMPLE
    $query="MATCH (n:User) RETURN n"
    Cypher $Query -Expand $Null
#>

function ConvertTo-B64String {
    param(
        [Parameter(Mandatory=$true,Position=1)]
        [string]$InputString
    )
    begin{}
    process{
        $encodedString = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($inputString))
    }
    end{
        return $encodedString
    }
}

function createBasicCred {
    param(
        [Parameter(Mandatory=$false,Position=1)]
        [pscredential]$Cred
    )
    Begin{}
    Process{
        if($null -eq $Cred){
            $Cred = Get-Credential -Message "Please enter your credentials"
        }
        $credPass = (New-Object System.Management.Automation.PSCredential -ArgumentList $Cred.UserName,$Cred.Password).GetNetworkCredential().Password
        $basicCred = ConvertTo-B64String -InputString "$($Cred.UserName):$credPass"
    }
    End{
        return $basicCred
    }
}

function createNeo4jHeaders {
    param(
        [Parameter(Mandatory=$false,Position=1)]
        [pscredential]$neo4jCredential 
    )
    Begin{}
    Process{
        $basicCred = createBasicCred -Cred $neo4jCredential
        $headers = @{
            "Accept"="application/json; charset=UTF-8";
            "Content-Type"="application/json";
            "Authorization"="Basic $basicCred"
        }
    }
    End{
        return $headers
    }
}

function Invoke-Cypher{
    [CmdletBinding()]
    [Alias('Cypher')]
    Param(
        # Cypher Query
        [Parameter(Mandatory=$true,Position=1)][string]$Query,
        # Query Params [optional]
        [Parameter(Mandatory=$false,Position=2)][Hashtable]$Params,
        # Expand Props [Default to .data.data /  Use -Expand $Null for raw objects]
        [Parameter(Mandatory=$false,Position=3)][Alias('x')][String[]]$Expand=@('data','data'),
        # Server for neo4j
        [Parameter(Mandatory=$false,Position=4)][string]$Server = "localhost",
        # Port for neo4j
        [Parameter(Mandatory=$false,Position=5)][int]$Port = 7474,
        # Credential for neo4jDB... can exclude if removed requirement for local auth
        [Parameter(Mandatory=$false,Position=6)][pscredential]$neo4jCredential
        )
    # Uri 
    $Uri = "http://$Server`:$Port/db/data/cypher"
    # Header
    $Header= createNeo4jHeaders -neo4jCredential $neo4jCredential
    # Query [spec chars to unicode]
    $Query=$($Query.ToCharArray()|%{$x=[Byte][Char]"$_";if($x-gt191-AND$x-le255){'\u{0:X4}'-f$x}else{$_}})-join''
    # Body
    if($Params){$Body = @{params=$Params; query=$Query}|Convertto-Json}
    else{$Body = @{query=$Query}|Convertto-Json}
    # Call
    #Write-Verbose "[+][$(Time)] Querying Database..."
    Write-Verbose "[+][$(Time)] $Query" <#Ckeck $Body if strange chars#>
    $Reply = Try{Invoke-RestMethod -Uri $Uri -Method Post -Headers $Header -Body $Body -verbose:$false}Catch{$Oops = $Error[0].ErrorDetails.Message}
    # Format obj
    if($Oops){Write-Warning "$((ConvertFrom-Json $Oops).message)";Return}
    if($Expand){$Expand | %{$Reply = $Reply.$_}} 
    # Output Reply
    if($Reply){Return $Reply}
    }
#End

###########################################################

function Backup-Neo4jDB {
    param(
        [Parameter(Mandatory=$false,Position=1)]
        [string]$Neo4jInstallDir,

        [Parameter(Mandatory=$false,Position=2)]
        [string]$DBName = "BloodHoundExampleDB"
    )
    begin{
        if ($null -eq $Neo4jInstallDir -or $Neo4jInstallDir.Length -eq 0){
            $Neo4jInstallDir = ((gwmi win32_service | ?{$_.Name -eq "Neo4j"} | select PathName).pathname -split "bin\\tools\\prunsrv-[a-zA-A0-9]+?.exe")[0]
        }
        $dbDir = "{0}\data\databases" -f $Neo4jInstallDir.TrimEnd("\")
        $db = "{0}\{1}.graphdb" -f $dbDir, $DBName.TrimEnd(".graphdb")
        $date = (get-date)
        $timestamp = "{0}_{1}_{2}_{3}{4}{5}" -f $date.Month, $date.Day, $date.Year, $date.Hour, $date.Minute, $date.Second
        $backupDir = "{0}\backups\{1}" -f $dbDir.TrimEnd("\"), $timestamp
        
    }
    process{
        if ((Test-Path $backupDir) -ne $true){
            New-Item -Path $backupDir -Type Directory
        }
        Copy-Item -Path $db -Destination $backupDir -Recurse
    }
    end{
        return "{0}\{1}.graphdb" -f $backupDir, $DBName
    }
}

function Get-Neo4jBackups {
    param(
        [Parameter(Mandatory=$false,Position=1)]
        [string]$BackupDir
    )
    begin{
        if ($null -eq $BackupDir -or $backupDir.Length -eq 0){
            $installDir = ((gwmi win32_service | ?{$_.Name -eq "Neo4j"} | select PathName).pathname -split "bin\\tools\\prunsrv-[a-zA-A0-9]+?.exe")[0]
            $BackupDir = ("{0}\data\databases\backups" -f $installDir)
        }
        $info = @()
    }
    process{
        $backups = (gci $BackupDir -Directory).FullName
        foreach($b in $backups){
            $db = (gci $b -Directory).Name
            $info += @{"Path"=$b;"DB"=$db}
        }
        $info = $info | Sort-Object -Property Path
    }
    end{
        return $info
    }
}

function Restore-Neo4jDB {
    param(
        [Parameter(Mandatory=$false,Position=1)]
        [string]$Neo4jInstallDir,

        [Parameter(Mandatory=$false,Position=2)]
        [string]$DBName = "BloodHoundExampleDB",

        [Parameter(Mandatory=$false,Position=3)]
        [string]$BackupDB
    )
    begin{
        if ($null -eq $Neo4jInstallDir -or $Neo4jInstallDir.Length -eq 0){
            $Neo4jInstallDir = ((gwmi win32_service | ?{$_.Name -eq "Neo4j"} | select PathName).pathname -split "bin\\tools\\prunsrv-[a-zA-A0-9]+?.exe")[0]
        }
        if ($null -eq $BackupDB -or $BackupDB.Length -eq 0){
            $backups = Get-Neo4jBackups
            if ($backups.gettype().Name -eq 'Hashtable'){
                $BackupDB = "{0}\{1}" -f $backups.Path, $backups.DB
            }
            else{
                $BackupDB = "{0}\{1}" -f $backups[0].Path, $backups[0].DB
            }            
        }
        #RUN AS ADMIN TO FORCE STOP/START THE SERVICE OR IT WILL FAIL
        $dbDir = "{0}\data\databases" -f $Neo4jInstallDir.TrimEnd("\")
        $currDB = "{0}\{1}.graphdb" -f $dbDir, $DBName
    }
    process{
        try{
            Stop-Service -Name neo4j -Force -ErrorAction Stop
            Remove-Item -Path $currDB -Recurse -Force -ErrorAction Stop
            Copy-Item -Path $BackupDB -Destination $dbDir -Recurse -Force -ErrorAction Stop
            Start-Service -Name neo4j -ErrorAction Stop
        }
        catch{
            Write-Error "Failed to restore database, ensure that you are running in an administrative prompt"
        }
    }
    end{}
}

function Get-EdgeInfo{
    param(
        [Parameter(Mandatory=$true,Position=1)][string]$StartNodeName,
        [Parameter(Mandatory=$true,Position=2)][string]$StartNodeLabel,
        [Parameter(Mandatory=$true,Position=3)][string]$EdgeType,
        [Parameter(Mandatory=$true,Position=4)][string]$EndNodeName,
        [Parameter(Mandatory=$true,Position=5)][string]$EndNodeLabel,
        [Parameter(Mandatory=$false,Position=6)][string]$OutDir,
        [Parameter(Mandatory=$false,Position=7)][string]$Server = "localhost",
        # Port for neo4j
        [Parameter(Mandatory=$false,Position=8)][int]$Port = 7474,
        # Credential for neo4jDB... can exclude if removed requirement for local auth
        [Parameter(Mandatory=$false,Position=9)][pscredential]$neo4jCredential
    )
    begin{
        $StartNodeName = $StartNodeName.ToUpper()
        $EndNodeName = $EndNodeName.ToUpper()
        if ($null -ne $OutDir -and $outDir.Length -gt 1){
            $OutDir = "{0}\RemovedEntities\Edges" -f $OutDir.Trim("\")
            if ((Test-Path $OutDir) -ne $true){
                New-Item -Path $OutDir -ItemType Directory
            }
        }
        $Header = createNeo4jHeaders -neo4jCredential $neo4jCredential
        $pathInfo = @{}
    }
    process{
        # get node and edge info
        $path = Cypher -Query "match p=(n:$StartNodeLabel {name:`"$StartNodeName`"})-[r:$EdgeType]->(m:$EndNodeLabel {name:`"$EndNodeName`"}) return labels(n),n,type(r),r,labels(m),m" `
            -Server $Server -Port $Port -neo4jCredential $neo4jCredential -Expand data

        $start = @{"Label"=$path[0];"NodeInfo"=$path[1]}
        $startProperties = irm -method get -uri $start.NodeInfo.properties -headers $Header 
        $startNode = @{"Label"=$start.Label;"Properties"=$startProperties}
        $pathInfo.Add("Start",$startNode)

        $edge = @{"Type"=$path[2];"EdgeInfo"=$path[3]}
        $edgeProperties = irm -method get -uri $edge.EdgeInfo.properties -headers $Header 
        $relationship = @{"Type"=$edge.Type;"Properties"=$edgeProperties}
        $pathInfo.Add("Edge",$relationship)

        $end = @{"Label"=$path[4];"NodeInfo"=$path[5]}
        $endProperties = irm -method get -uri $end.NodeInfo.properties -headers $Header 
        $endNode = @{"Label"=$end.Label;"Properties"=$endProperties}
        $pathInfo.Add("End",$endNode)
    }
    end{
        if ($null -ne $OutDir -and $OutDir.length -gt 1){
            $rel = "({0})-{1}-({2})" -f $pathInfo.Start.Properties.name, $pathInfo.Edge.Type, $pathInfo.End.Properties.name
            $outfile = "{0}\{1}.json" -f $outDir, $rel
            Out-File -FilePath $OutFile -InputObject ($pathInfo | Convertto-Json -Depth 20)
            return $outfile
        }
        else{
            return $pathInfo
        }
    }
}

function Remove-Edge{
    param(
        [Parameter(Mandatory=$true,Position=1)][string]$StartNodeName,
        [Parameter(Mandatory=$true,Position=2)][string]$StartNodeLabel,
        [Parameter(Mandatory=$true,Position=3)][string]$EdgeType,
        [Parameter(Mandatory=$true,Position=4)][string]$EndNodeName,
        [Parameter(Mandatory=$true,Position=5)][string]$EndNodeLabel,
        [Parameter(Mandatory=$false,Position=6)][string]$OutDir,
        [Parameter(Mandatory=$false,Position=7)][string]$Server = "localhost",
        # Port for neo4j
        [Parameter(Mandatory=$false,Position=8)][int]$Port = 7474,
        # Credential for neo4jDB... can exclude if removed requirement for local auth
        [Parameter(Mandatory=$false,Position=9)][pscredential]$neo4jCredential,
        [Parameter(Mandatory=$false,Position=10)][switch]$NoBackup
    )
    begin{
        $StartNodeName = $StartNodeName.ToUpper()
        $EndNodeName = $EndNodeName.ToUpper()
        if ($NoBackup -eq $false){
            $backups = Get-Neo4jBackups
            if ($backups.gettype().Name -eq 'Hashtable'){
                $backup = "{0}\{1}" -f $backups.Path, $backups.DB
            }
            else{
                $backup = "{0}\{1}" -f $backups[0].Path, $backups[0].DB
            }   
        }
        else {
            $backup = "no backup"
        }
        #write node info and related edges to disk so it's recoverable
        $filepath = Get-EdgeInfo -StartNodeName $StartNodeName -StartNodeLabel $StartNodeLabel -EdgeType $EdgeType -EndNodeName $EndNodeName -EndNodeLabel $EndNodeLabel `
            -OutDir $OutDir -Server $Server -Port $Port -neo4jCredential $neo4jCredential
        $logfile = ("{0}\graph_operations.csv" -f ((get-item $filepath | select -Property Directory).Directory.parent.fullname))
        $log = @{"Operation"="DELETE EDGE";"NodeName"=("({0})-[{1}]->({2})" -f $StartNodeName,$EdgeType,$EndNodeName);`
        "NodeLabel"=("({0})-[{1}]->({2})" -f $StartNodeLabel,$EdgeType,$EndNodeLabel);"Backup"=$backup}
    }
    process{
        $query = "match p=(n:$StartNodeLabel {name:`"$StartNodeName`"})-[r:$EdgeType]->(m:$EndNodeLabel {name:`"$EndNodeName`"}) DELETE r"
        Cypher -Query $query -Server $Server -Port $Port -neo4jCredential $neo4jCredential
    }
    end{
        $log | foreach-object {[PSCustomObject]$_} | Export-Csv -Path $logfile -Append -NoTypeInformation
    }
}

function Get-NodeInfo{
    param(
        [Parameter(Mandatory=$true,Position=1)][string]$NodeName,
        [Parameter(Mandatory=$true,Position=2)][string]$NodeLabel,
        [Parameter(Mandatory=$false,Position=3)][string]$OutDir,
        [Parameter(Mandatory=$false,Position=4)][string]$Server = "localhost",
        # Port for neo4j
        [Parameter(Mandatory=$false,Position=5)][int]$Port = 7474,
        # Credential for neo4jDB... can exclude if removed requirement for local auth
        [Parameter(Mandatory=$false,Position=6)][pscredential]$neo4jCredential
    )
    begin{
        $NodeName = $NodeName.ToUpper()
        if ($null -ne $OutDir -and $outDir.Length -gt 1){
            $OutDir = "{0}\RemovedEntities\Nodes" -f $OutDir.Trim("\")
            if ((Test-Path $OutDir) -ne $true){
                New-Item -Path $OutDir -ItemType Directory
            }
        }
        $Header = createNeo4jHeaders -neo4jCredential $neo4jCredential
        $nodeInfo = @{}
    }
    process{
        # get node info
        $node = Cypher -Query "match (n:$NodeLabel {name:`"$NodeName`"}) return n" -Server $Server -Port $Port -neo4jCredential $neo4jCredential -Expand data
        $nodeId = $node.metadata.id
        $nodeInfo.Add("Properties",$node.data)
        $nodeInfo.Add("Label",$node.metadata.labels)
        $nodeInfo.Add("Edges",@())

        # get node relationship info
        $relationships = irm -Method Get -Uri $node.all_relationships -Headers $Header
        foreach($relationship in $relationships){
            $edge = @{"Type"=$relationship.metadata.type;"Properties"=$relationship.data}
            if ($relationship.start.EndsWith($nodeId)){
                $edge.Add('Start_objectid',$nodeInfo.Properties.objectid)
                $edge.Add('Start_label',$nodeInfo.Label)
            }
            else {
                $start_obj = irm -Method Get -Uri $relationship.start -Headers $Header
                $edge.Add('Start_objectid',$start_obj.data.objectid)
                $edge.Add('Start_label',$start_obj.metadata.labels)
            }
            if ($relationship.end.EndsWith($nodeId)){
                $edge.Add('End_objectid',$nodeInfo.Properties.objectid)
                $edge.Add('End_label',$nodeInfo.Label)
            }
            else{
                $end_obj = irm -Method Get -Uri $relationship.end -Headers $Header
                $edge.Add('End_objectid',$end_obj.data.objectid)
                $edge.Add('End_label',$end_obj.metadata.labels)
            }
            $nodeInfo.Edges += $edge
        }
    }
    end{
        if ($null -ne $OutDir -and $OutDir.length -gt 1){
            $outfile = "{0}\{1}.json" -f $outDir, $NodeName
            Out-File -FilePath $OutFile -InputObject ($nodeInfo | Convertto-Json -Depth 20)
            return $outfile
        }
        else{
            return $nodeInfo
        }
    }
}

function Remove-Node{
    param(
        [Parameter(Mandatory=$true,Position=1)][string]$NodeName,
        [Parameter(Mandatory=$true,Position=2)][string]$NodeLabel,
        # Specifying Delete will remove node and all its edges
        [Parameter(Mandatory=$true,Position=3)][switch]$Delete,
        [Parameter(Mandatory=$false,Position=4)][string]$OutDir=".\RemovedEntities",
        [Parameter(Mandatory=$false,Position=5)][string]$Server = "localhost",
        # Port for neo4j
        [Parameter(Mandatory=$false,Position=6)][int]$Port = 7474,
        # Credential for neo4jDB... can exclude if removed requirement for local auth
        [Parameter(Mandatory=$false,Position=7)][pscredential]$neo4jCredential,
        [Parameter(Mandatory=$false,Position=8)][switch]$NoBackup
    )
    begin{
        $NodeName = $NodeName.ToUpper()
        if ($NoBackup -eq $false){
            $backups = Get-Neo4jBackups
            if ($backups.gettype().Name -eq 'Hashtable'){
                $backup = "{0}\{1}" -f $backups.Path, $backups.DB
            }
            else{
                $backup = "{0}\{1}" -f $backups[0].Path, $backups[0].DB
            }   
        }
        else{
            $backup = "no backup"
        }
        #write node info and related edges to disk so it's recoverable
        $filepath = Get-NodeInfo -NodeName $NodeName -NodeLabel $NodeLabel -OutDir $OutDir -Server $Server -Port $Port -neo4jCredential $neo4jCredential
        $logfile = ("{0}\graph_operations.csv" -f ((get-item $filepath | select -Property Directory).Directory.parent.fullname))
        $log = @{"Operation"="DETACH";"NodeName"=$NodeName;"NodeLabel"=$NodeLabel;"Backup"=$backup}
    }
    process{
        $query = "MATCH (n:$NodeLabel {name:`"$NodeName`"}) DETACH"
        if ($Delete){
            $log.Operation += " DELETE"
            $query += " DELETE"
        }
        $query += " n"
        Cypher -Query $query -Server $Server -Port $Port -neo4jCredential $neo4jCredential
    }
    end{
        $log | foreach-object {[PSCustomObject]$_} | Export-Csv -Path $logfile -Append -NoTypeInformation
    }
}

# this doesn't quick work... and I'm not sure why. Node gets reinserted and looks the same, but weights are coming out different
function Import-Node{
    param(
        [Parameter(Mandatory=$true,Position=1)][string]$NodeFile,
        # Specifying Delete will remove node and all its edges
        [Parameter(Mandatory=$false,Position=2)][switch]$EdgesOnly,
        [Parameter(Mandatory=$false,Position=3)][string]$Server = "localhost",
        # Port for neo4j
        [Parameter(Mandatory=$false,Position=4)][int]$Port = 7474,
        # Credential for neo4jDB... can exclude if removed requirement for local auth
        [Parameter(Mandatory=$false,Position=5)][pscredential]$neo4jCredential
    )
    begin{
        # import the node info... could technically take this from pipeline too
        $nodeInfo = (Get-Content $NodeFile | ConvertFrom-Json)
        $logfile = "{0}\graph_operations.csv" -f ((get-item $NodeFile | select -Property Directory).Directory | select parent).parent
        $log = @{"Operation"="IMPORT";"NodeName"=$nodeInfo.Properties.name;"NodeLabel"=$nodeInfo.Label;;"Backup"=""}

        # generate Node insertion cypher
        if ($EdgesOnly -eq $false){
            $log.Operation += " Node and"
            $propertyNames = ($nodeInfo.Properties | gm | ? {$_.MemberType -eq 'NoteProperty'}).Name
            $setNodeProps = ""
            $setNodeArrayProps = "SET "
            foreach($p in $propertyNames){
                if ($nodeInfo.Properties.($p).gettype().isarray){
                    $arrayStr = ""
                    foreach($e in $nodeInfo.Properties.($p)){
                        if ($e.gettype().Name -eq 'Boolean' -or $e.gettype().Name -eq 'Int32' -or $e.gettype().Name -eq 'Int64'){
                            $arrayStr += "{0}," -f $e
                        }
                        else{
                            $arrayStr += "`"{0}`"," -f $e.replace("\","\\")
                        }
                    }
                    $arrayStr.TrimEnd(",")
                    $setNodeArrayProps += "n.{0} = coalesce(n.{0},[]) + [{1}]," -f $p,$arrayStr
                }
                elseif ($nodeInfo.Properties.($p).gettype().Name -eq 'Boolean' -or $nodeInfo.Properties.($p).gettype().Name -eq 'Int32'`
                 -or $nodeInfo.Properties.($p).gettype().Name -eq 'Int64'){
                    $setNodeProps += "{0}:{1}," -f $p,$nodeInfo.Properties.($p)
                }
                else{
                    $setNodeProps += "{0}:`"{1}`"," -f $p,$nodeInfo.Properties.($p).replace("\","\\")
                }
            }
            $setNodeProps = $setNodeProps.TrimEnd(",")
            $setNodeArrayProps = $setNodeArrayProps.TrimEnd(",")
            $nodeCypher = "MERGE (n:$($nodeInfo.Label -join ":") {$setNodeProps})"
            if ($setNodeArrayProps.Length -gt 1){
                $nodeCypher += " $setNodeArrayProps"
            }
        }
        
        # generate Edge insertion cypher
        $log.Operation += " Edges"
        $edgeCyphers = @()
        foreach($e in $nodeInfo.Edges){
            $set_edge_properties = ""
            $propertyNames = ($e.Properties | gm | ? {$_.MemberType -eq 'NoteProperty'}).Name
            foreach($p in $propertyNames){
                if ($e.Properties.($p).gettype().Name -eq 'Boolean' -or $e.Properties.($p).gettype().Name -eq 'Int32' `
                 -or $e.Properties.($p).gettype().Name -eq 'Int64'){
                    $set_edge_properties += "{0}:{1}," -f $p,$e.Properties.($p)
                }
                else{
                    $set_edge_properties += "{0}:`"{1}`"," -f $p,$e.Properties.($p).replace("\","\\")
                }
            }
            $set_edge_properties = $set_edge_properties.TrimEnd(",")
            $edgeCypher = "MATCH (start:$($e.Start_label -join ":") {objectid:`"$($e.Start_objectid)`"}), (end:$($e.End_label -join ":") {objectid:`"$($e.End_objectid)`"})" + 
            " MERGE (start)-[r:$($e.Type) {$set_edge_properties}]->(end)"
            $edgeCyphers += $edgeCypher
        }
    }
    process{
        if ($EdgesOnly -ne $true){
            Cypher -Query $nodeCypher -Server $Server -Port $Port -neo4jCredential $neo4jCredential 
        }
        # if this ends up being a bottleneck, should be able to pass multiple queries in one request body
        foreach($q in $edgeCyphers){
            Cypher -Query $q -Server $Server -Port $Port -neo4jCredential $neo4jCredential 
        }
        $log | foreach-object {[PSCustomObject]$_} | Export-Csv -Path $logfile -Append -NoTypeInformation
    }
    end{}
}

function Get-GeneralRiskStats{
    param(
        [Parameter(Mandatory=$true,Position=1)][string]$GroupName,
        [Parameter(Mandatory=$false,Position=2)][string]$UserComputerDomain,
        [Parameter(Mandatory=$false,Position=3)][switch]$NoDomainRestriction,
        [Parameter(Mandatory=$false,Position=4)][string]$Server = "localhost",
        # Port for neo4j
        [Parameter(Mandatory=$false,Position=5)][int]$Port = 7474,
        # Credential for neo4jDB... can exclude if removed requirement for local auth
        [Parameter(Mandatory=$false,Position=6)][pscredential]$neo4jCredential
    )
    begin{
        $GroupName = $GroupName.ToUpper()
        if ($NoDomainRestriction){
            $filter = ""
        }
        else{
            if ($null -eq $UserComputerDomain -or $UserComputerDomain.Length -eq 0){
                $UserComputerDomain = $GroupName.split("@")[1]
            }
            $filter = " {domain:'$UserComputerDomain'}"
        }
        $totalUsersQuery = ("MATCH (totalUsers:User{0}) return count(totalUsers)" -f $filter)
        $usersWithPathQuery = ("MATCH shortestPath((pathToDAUsers:User{0})-[*1..]->(g:Group {{name:'{1}'}})) where pathToDAUsers<>g return COUNT(DISTINCT(pathToDAUsers))" -f $filter, $GroupName)
        $totalComputersQuery = ("MATCH (totalComputers:Computer{0}) return count(distinct(totalComputers))" -f $filter)
        $computersWithPathQuery = ("MATCH shortestPath((pathToDAComputers:Computer{0})-[*1..]->(g:Group {{name:'{1}'}})) WHERE pathToDAComputers<>g return COUNT(DISTINCT(pathToDAComputers))" -f $filter, $GroupName)
        $averageUserPathLengthQuery = ("MATCH p = shortestPath((n{0}{1})-[*1..]->(g:Group {{name:'{2}'}})) where n<>g RETURN toInteger(AVG(LENGTH(p))) as avgPathLength" -f ":User",$filter,$GroupName)
        $averageComputerPathLengthQuery = ("MATCH p = shortestPath((n{0}{1})-[*1..]->(g:Group {{name:'{2}'}})) where n<>g RETURN toInteger(AVG(LENGTH(p))) as avgPathLength" -f ":Computer",$filter,$GroupName)
        $averagePathLengthQuery = ("MATCH p = shortestPath((n{0}{1})-[*1..]->(g:Group {{name:'{2}'}})) where n<>g RETURN toInteger(AVG(LENGTH(p))) as avgPathLength" -f "",$filter,$GroupName)
    }
    process{
        $totalUsers = [int](Cypher -Query $totalUsersQuery -neo4jCredential $neo4jCredential -Expand data)[0]
        $usersWithPath = [int](Cypher -Query $usersWithPathQuery -neo4jCredential $neo4jCredential -Expand data)[0]

        $totalComputers = [int](Cypher -Query $totalComputersQuery -neo4jCredential $neo4jCredential -Expand data)[0]
        $computersWithPath = [int](Cypher -Query $computersWithPathQuery -neo4jCredential $neo4jCredential -Expand data)[0]

        $averagePath = [int](Cypher -Query $averagePathLengthQuery -neo4jCredential $neo4jCredential -Expand data)[0]
        $averageUserPath = [int](Cypher -Query $averageUserPathLengthQuery -neo4jCredential $neo4jCredential -Expand data)[0]
        $averageComputerPath = [int](Cypher -Query $averageComputerPathLengthQuery -neo4jCredential $neo4jCredential -Expand data)[0]

        $percentUsers = 100*($usersWithPath/$totalUsers)
        $percentComputers = 100*($computersWithPath/$totalComputers)
    }
    end{
        $stats = [ordered]@{"Destination"=$GroupName;`
            "TotalUsers"=$totalUsers; "UsersWithPath"=$usersWithPath; "PercentUsersWithPath"=$percentUsers; `
            "TotalComputers"=$totalComputers; "ComputersWithPath"=$computersWithPath; "PercentComputersWithPath"=$percentComputers;`
            "AveragePathLength"=$averagePath; "AverageUserPathLength"=$averageUserPath; "AverageComputerPathLength"=$averageComputerPath
        }
        return $stats
    }
}

function Invoke-AllDomainReports {
    param(
        [Parameter(Mandatory=$true,Position=1)]
        [string]$OutputDir,
        [Parameter(Mandatory=$false,Position=2)][string]$Server = "localhost",
        # Port for neo4j
        [Parameter(Mandatory=$false,Position=3)][int]$Port = 7474,
        # Credential for neo4jDB... can exclude if removed requirement for local auth
        [Parameter(Mandatory=$false,Position=4)][pscredential]$neo4jCredential
    )
    begin{
        if ($null -eq $neo4jCredential){
            $neo4jCredential = Get-Credential 
        }
        $domains = (Cypher -Query "MATCH (n:Domain) where n.domain is not null return distinct(n.domain)" -neo4jCredential $neo4jCredential -Expand data -Server $Server -Port $Port)
    }
    process{
        foreach($domain in $domains){
            $d = $domain[0]
            Invoke-WatchDog -Domain $d -Quick -UserDomain $d -neo4jCredential $cred  | 
                ReportDog -neo4jCredential $cred >> "$outputDir\$d`_watchdog.txt";
            Get-GeneralRiskStats -GroupName "DOMAIN ADMINS@$d" -neo4jCredential $cred >> "$outputDir\$d`_general_risk.txt"
        }
    }
    end{}
}

<#
.Synopsis
   BloodHound DB Info
.DESCRIPTION
   Get BloodHound DB node and edge count
.EXAMPLE
   DBInfo
#>
function Get-BloodHoundDBInfo{
    [Alias('DBInfo')]
    Param(
        [Parameter(Mandatory=$false,Position=1)]
        [pscredential]$neo4jCredential
    )
    if ($null -eq $neo4jCredential){
        $neo4jCredential = Get-Credential 
    }
    Write-Verbose "[+][$(Time)] Fetching DB Info..."
    [PSCustomObject]@{
        Domains   = (Cypher 'MATCH (x:Domain) RETURN COUNT(x)' -expand Data -neo4jCredential $neo4jCredential)[0]
        Nodes     = (Cypher 'MATCH (x) RETURN COUNT(x)' -expand Data -neo4jCredential $neo4jCredential)[0] 
        Users     = (Cypher 'MATCH (x:User) WHERE EXISTS(x.domain) RETURN COUNT(x)' -expand Data -neo4jCredential $neo4jCredential)[0]
        Computers = (Cypher 'MATCH (x:Computer) RETURN COUNT(x)' -expand Data -neo4jCredential $neo4jCredential)[0]
        Groups    = (Cypher 'MATCH (x:Group) RETURN COUNT(x)' -expand Data -neo4jCredential $neo4jCredential)[0]
        OUs       = (Cypher 'MATCH (x:OU) RETURN COUNT(x)' -expand Data -neo4jCredential $neo4jCredential)[0]
        GPOs      = (Cypher 'MATCH (x:GPO) RETURN COUNT(x)' -expand Data -neo4jCredential $neo4jCredential)[0]
        Edges     = (Cypher 'MATCH (x)-[r]->() RETURN COUNT(r)' -expand Data -neo4jCredential $neo4jCredential)[0]
        ACLs      = (Cypher "MATCH x=(s)-[r]->(t) WHERE r.isacl=True RETURN COUNT(x)" -Expand Data -neo4jCredential $neo4jCredential)[0]
        Sessions  = (Cypher "MATCH p=(s:Computer)-[r:HasSession]->(t:User) RETURN COUNT(r)" -expand Data -neo4jCredential $neo4jCredential)[0]
        }}
#####End

###########################################################

<#
.Synopsis
   BloodHound DataDog
.DESCRIPTION
   BloodHound node metrics on user shortest path to specified target group
.EXAMPLE
   DataDog 'DOMAIN ADMINS@DOMAIN.LOCAL','BACKUP OPERATORS@DOMAIN.LOCAL'
#>
Function Invoke-DataDog{
    [Alias('DataDog')]
    [OutputType([Datadog])]
    Param(
        # Name of the Group to Scan
        [Parameter(Mandatory=1,ValueFromPipeline=$true,Position=1)][Alias('Group')][String[]]$Name,
        # Limit number of returned path
        [Parameter(Mandatory=0,Position=2)][Int]$Limit=10000,
        # Scan Type
        [Parameter(Mandatory=0,Position=3)][ScanType]$ScanType="Advanced",
        # Switch to All Shortest Paths
        [Parameter(Mandatory=0,Position=4)][Switch]$AllShortest,
        # Switch Quick [less accurate]
        [Parameter(Mandatory=0,Position=5)][Switch]$Quick,
        # Specify user origin
        [Parameter(Mandatory=0,Position=6)][String]$UserDomain,
        # Credential for neo4jDB... can exclude if removed requirement for local auth
        [Parameter(Mandatory=$false,Position=7)][pscredential]$neo4jCredential
        )
    Begin{
        $EdgeList = Switch("$ScanType".ToUpper()){
            MINI     {":MemberOf|AdminTo|HasSIDHistory"}
            MINIX    {":MemberOf|AdminTo|HasSIDHistory|CanRDP|CanPSRemote|ExecuteDCOM"}
            MIMI     {":MemberOf|HasSession|AdminTo|HasSIDHistory"}
            MIMIX    {":MemberOf|HasSession|AdminTo|HasSIDHistory|CanRDP|CanPSRemote|ExecuteDCOM"}
            STANDARD {":MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|ReadLAPSPassword|ReadGMSAPassword"}
            STANTARDX{":MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|ReadLAPSPassword|ReadGMSAPassword|CanRDP|CanPSRemote|ExecuteDCOM"}
            ADVANCED {":MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|ReadLAPSPassword|ReadGMSAPassword|AllowedToDelegate|AddAllowedToAct|AllowedToAct|SQLAdmin|HasSIDHistory"}
            ADVANCEDX{":MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|ReadLAPSPassword|ReadGMSAPassword|AllowedToDelegate|AddAllowedToAct|AllowedToAct|SQLAdmin|HasSIDHistory|CanRDP|CanPSRemote|ExecuteDCOM"}
            EXTREME  {":MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|ReadLAPSPassword|ReadGMSAPassword|AllowedToDelegate|AddAllowedToAct|AllowedToAct|SQLAdmin|HasSIDHistory|Contains|GpLink"}
            EXTREMEX {":MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|ReadLAPSPassword|ReadGMSAPassword|AllowedToDelegate|AddAllowedToAct|AllowedToAct|SQLAdmin|HasSIDHistory|Contains|GpLink|AZContains|AZOwns|AZGlobalAdmin|AZResetPassword|AZRunAs|AZUserAccessAdministrator"}
            CUSTOM   {":MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|ReadLAPSPassword|ExecuteDCOM|AllowedToDelegate|AddAllowedToAct|AllowedToAct"}
            }
        # if All Shortest Path
        if($AllShortest){$q='allShortestPaths'}Else{$q='shortestPath'}
        # If Quick [No Order]
        if($Quick){$order=$Null}Else{$order='ORDER BY LENGTH(p) '}
        if($null -eq $neo4jCredential){
            $neo4jCredential = Get-Credential
        }
        $header = createNeo4jHeaders -neo4jCredential $neo4jCredential
    }
    Process{
        Foreach($Obj in $Name){
            # Get Group
            Write-Verbose "[?][$(Time)] Querying Group by Name"
            $Grp = Cypher "MATCH (g:Group {name:'$Obj'}) RETURN g" -neo4jCredential $neo4jCredential | select Name,objectid,description
            # If Group not found
            if(-NOT $Grp.name){
                Write-Warning "[!][$(Time)] OBJECT NOT FOUND: $Obj`r`n"
                }
            # If Group found
            else{
                # Name & stuff
                $SD   = $Grp.objectid
                $Nme  = $Grp.Name
                $Desc = $Grp.Description
                #if($UserDomain){$WhereDom=" WHERE m.name=~'@$($Grp.Name.split('@')[1])'"}
                if($UserDomain){$WhereDom=" WHERE m.name ENDS WITH '@$($UserDomain.ToUpper())'"}
                Write-Verbose "[*][$(Time)] $Nme"
                # Direct Members
                Write-Verbose "[.][$(Time)] Querying Direct Member Count"
                $Cypher1   = "MATCH (m:User)$WhereDom MATCH p=shortestPath((m)-[r:MemberOf*1]->(n:Group {name:'$NmE'})) RETURN COUNT(m)"
                $DirectMbr = (Cypher $Cypher1 -expand data -neo4jCredential $neo4jCredential)|Select -first 1
                Write-Verbose "[.][$(Time)] > Direct Member: $DirectMbr"
                # Unrolled Members
                Write-Verbose "[.][$(Time)] Querying Nested Member Count"
                $cypher2   = "MATCH (m:User)$WhereDom MATCH p=shortestPath((m)-[r:MemberOf*1..]->(n:Group {name:'$NmE'})) RETURN COUNT(m)"
                $UnrollMbr =(Cypher $Cypher2 -expand data -neo4jCredential $neo4jCredential)|Select -first 1
                Write-Verbose "[.][$(Time)] > Nested Member: $($UnrollMbr-$DirectMbr)"
                # Shortest Path
                $Cypher3   = "MATCH (m:User)$WhereDom MATCH p=$q((m)-[r$EdgeList*1..]->(n:Group {name:'$NmE'})) RETURN p ${Order}LIMIT $Limit"
                Write-Verbose "[.][$(Time)] Querying User Shortest Paths"
                $RawData  = Cypher $Cypher3 -expand data -neo4jCredential $neo4jCredential
                # User Path Count
                $PathCount = $RawData.count
                $UserCount = ($RawData.start|sort -unique).count
                Write-Verbose "[.][$(Time)] > UserPathCount: $UserCount"
                # Node Weight
                Write-Verbose "[.][$(Time)] Grouping Nodes"
                $AllNodeU = $RawData.nodes | Group  | Select name,count
                Write-Verbose "[.][$(Time)] Mesuring Weight"
                $NodeWeight = @(Foreach($x in $AllNodeU){
                    #  Name
                    $Obj=irm $x.Name -Headers $header -Verbose:$false
                    # Dist
                    $Path = $RawData | ? {$_.nodes -match $x.name} | select -first 1
                    $Step = $Path.Nodes.Count-1
                    if($Path){while($Path.Nodes[$Step] -ne $x.name -AND $Step -gt 1){$Step-=1}}
                    # Calc Weight
                    $W=$X|select -expand Count
                    # Out
                    [PScustomObject]@{
                        Type     = if($Obj.metadata.labels.count -gt 1){($Obj.metadata.labels | ? {$_ -ne 'Base'})} else{$Obj.metadata.labels[0]}
                        Name     = $Obj.data.name
                        Distance = ($Path.Nodes.Count)-$Step-1
                        Weight   = $W
                        Impact   = [Math]::Round($W/$RawData.Count*100,1)
                        }
                    })

                # Cypher
                Write-Verbose "[.][$(Time)] Storing Cypher"
                $Cypher = @(
                    $Cypher1.Replace('COUNT(m)','p')
                    $Cypher1.Replace('COUNT(m)','{Type: "Direct", Name: m.name, SID: m.objectid} as obj')
                    $Cypher2.Replace('COUNT(m)','p')
                    $Cypher2.Replace('COUNT(m)','{Type: "Nested", Name: m.name, SID: m.objectid} as obj')
                    $Cypher3
                    $Cypher3.Replace("RETURN p ${Order}LIMIT $limit",'RETURN {Type: "Path", Name: m.name, SID: m.objectid} as obj')
                    )    
                # Output DataDog Obj
                Write-Verbose "[+][$(Time)] Returning Object...`r`n"
                [DataDog]@{
                    Group         = $Nme
                    SID           = $SD
                    Description   = $Desc
                    DirectMbrCount= $DirectMbr
                    NestedMbrCount= $UnrollMbr - $DirectMbr
                    PathCount     = $PathCount
                    UserPathCount = $UserCount
                    NodeWeight    = $NodeWeight
                    Cypher        = $Cypher
                    }}}}
    End{}###########
    }
#End

###########################################################

<#
.Synopsis
   BloodHound Watchdog
.DESCRIPTION
   Collect Path Data from default group for specified domain
.EXAMPLE
   WatchDog domain.local
#>
Function Invoke-WatchDog{
    [Alias('WatchDog')]
    [OutputType([Datadog])]
    Param(
        # Name of the domain to scan
        [Parameter()][String]$Domain,
        # Add extra Group Names
        [Parameter()][String[]]$ExtraGroup,
        # Limit Number of returned paths
        [Parameter(Mandatory=0)][Int]$Limit=10000,
        # Scan Type
        [Parameter()][ScanType]$ScanType='Advanced',
        # Switch to All Shortest Paths
        [Parameter(Mandatory=0)][Switch]$AllShortest,
        # Switch Quick [less accurate]
        [Parameter(Mandatory=0)][Switch]$Quick,
        # Specify user origin
        [Parameter(Mandatory=0)][String]$UserDomain,
        # Credential for neo4jDB... can exclude if removed requirement for local auth
        [Parameter(Mandatory=$false,Position=6)][pscredential]$neo4jCredential
        )
    if($null -eq $neo4jCredential){
        $neo4jCredential = Get-Credential
    }
    # Domain to upper
    $Domain = $Domain.ToUpper()
    ## foreach in list ##
    foreach($Obj in $GroupList){
        # Get Group
        $ObjID = if($Obj.SID -match '^S-1-5-32-'){"$Domain"+"-$($Obj.SID)"}else{"$($Obj.SID)"}
        Write-Verbose "[?][$(Time)] Searching Name by SID"
        $Grp = Cypher "MATCH (g:Group {domain:'$Domain'}) WHERE g.objectid =~ '(?i)$ObjID' RETURN g" -neo4jCredential $neo4jCredential | select Name,objectid,description
        # If Group not found
        if(-NOT $Grp.objectid){
            Write-Warning  "[!][$(Time)] OBJECT NOT FOUND: $($Obj.Name)`r`n"
            }
        # If Group found
        else{DataDog $Grp.name -ScanType $ScanType -AllShortest:$AllShortest -Quick:$Quick -Limit $Limit -UserDomain $UserDomain -neo4jCredential $neo4jCredential}
        }
    ## If Extra ##
    if($ExtraGroup){$ExtraGroup|DataDog -ScanType $ScanType -AllShortest:$AllShortest -Quick:$Quick -Limit $Limit -UserDomain $UserDomain -neo4jCredential $neo4jCredential}     
    }
#End

###########################################################

<#
.Synopsis
   Calc Ttl Impact - INTERNAL
.DESCRIPTION
   Calculate Total Impact from Datadog Object Collection
.EXAMPLE
   $Data | TotalImpact
#>
function Measure-TotalImpact{
    [Alias('TotalImpact')]
    Param(
        # Datadog Objects [Piped from DataDog/WatchDog]
        [Parameter(Mandatory=1,ValueFromPipeline=1)][Datadog[]]$Data,
        # Filter on Node Type [optional]
        [ValidateSet('User','Group','Computer','GPO','OU')]
        [Parameter(Mandatory=0)][Alias('Filter')][String]$Type,
        # Limit to Top X [optional]
        [Parameter(Mandatory=0)][Alias('Limit')][Int]$Top
        ) 
    Begin{[Collections.ArrayList]$Collect=@()}
    Process{foreach($Obj in ($data)){$Null=$Collect.add($Obj)}}
    End{
        # Total Path Count
        $TtlPC=($Collect|measure -prop PathCount -sum).sum
        # Total Unique User Count
        $TtlUC= (($Collect.NodeWeight|? Type -eq User).name| Sort -Unique ).count
        # Total Object
        $Res = $Collect.NodeWeight | ? Distance -ne 0 | Group Name |%{
            $TtlW = ($_.Group|Measure-object -Property Weight -sum).sum
            [PSCustomObject]@{
                Type= $_.Group[0].type
                Name= $_.Name
                Hit=$_|Select -expand Count
                Weight=$TtlW
                Impact=[Math]::Round($TtlW/$TtlPC*100,1)
                }
            }
        $res = $res | Sort Impact -Descending
        if($Type){$Res = $Res | ? type -eq $Type}
        if($Top){$res = $res | select -first $top}
        $res
        }
    }
#End

###########################################################

<#
.Synopsis
   WatchDog Report
.DESCRIPTION
   DataDog/WatchDog to readable text report
.EXAMPLE
   $Data | ReportDog
   Will generate report out of Datadog objects
   $Data holds result of WatchDog/DataDog Command
#>
Function Invoke-ReportDog{
    [Alias('ReportDog')]
    Param(
        [Parameter(ValueFromPipeline=1)][DataDog[]]$Data,
        [Parameter()][String]$File,
        [Parameter()][Switch]$NoDBInfo,
        [Parameter()][Switch]$NoTotal,
        [Parameter(Mandatory=$false,Position=4)][pscredential]$neo4jCredential
        )
    Begin{
        # Empty Collector
        [Collections.ArrayList]$Total=@()
        # If DB Info [Default]
        if(-Not$NoDBInfo){
            if ($null -eq $neo4jCredential){
                $neo4jCredential = Get-Credential
            }
            # DB Info
"##############################
------------------------------
# Reference                  #
------------------------------
weight = total number of times a node appears in paths to the target
impact = % of total weight

------------------------------
# DB Info                    #
------------------------------
$((Get-BloodHoundDBInfo -neo4jCredential $neo4jCredential |Out-String).trim())

##############################"
        }}
    Process{
        Foreach($Obj in $Data){
            # Add to Total
            $Null=$Total.Add($Obj)
            # Output
"
##  $($Obj.group) ##

SID: $($Obj.SID)
Description:
$($Obj.description)

User Count
----------
Direct Members : $($Obj.DirectMbrCount)
Nested Members : $($Obj.NestedMbrCount)
Users w. Paths : $($Obj.UserPathCount)


Top10 - Impact           
--------------

$(($Obj.NodeWeight|Sort Impact -Descending |Where distance -ne 0 |Select -first 10|ft|Out-String).trim())


Top5 User - Impact           
------------------

$(($Obj.NodeWeight|? type -eq user|Sort Impact -Descending |Select -first 5|ft|Out-String).trim())


Top5 Computer - Impact           
----------------------

$(($Obj.NodeWeight|? type -eq Computer|Sort Impact -Descending |Select -first 5|ft|Out-String).trim())


Top5 Group - Impact           
-------------------

$(($Obj.NodeWeight|? type -eq Group|Sort Impact -Descending|Where impact -ne 100|Select -first 5|ft|Out-String).trim())


# Cypher - Query
----------------

$($Obj.Cypher[4])


##############################"
        }}
    End{# If Total
        if(-Not$NoTotal){
            # Target Count
            $TC = $Total.Count
            # Total Path Count
            $PC = ($Total|measure -prop PathCount -sum).sum
            $TI = $Total|TotalImpact


"
## TOTAL IMPACT ##
------------------


Top10 User - TotalImpact [ $TC : $PC : 100 ]
------------------------

$(($TI|Where Type -eq User|Sort Impact -Descending | Select -First 10 | FT | Out-String).trim())


Top10 Computer - TotalImpact [ $TC : $PC : 100 ]
----------------------------

$(($TI|Where Type -eq Computer |Sort Impact -Descending | Select -First 10 | FT | Out-String).trim())


Top10 Group - TotalImpact [ $TC : $PC : 100 ]
-------------------------

$(($TI|Where Type -eq Group|Sort Impact -Descending | Select -First 10 | FT | Out-String).trim())


Top20 Overall - TotalImpact [ $TC : $PC : 100 ]
---------------------------

$(($TI|Sort Impact -Descending | Select -First 20 | FT -AutoSize | Out-String).trim())


##############################

## GROUP COUNT OVERVIEW ##
--------------------------

$($Total| select group,directmbrcount,nestedmbrcount,userpathcount | Out-String)
" 
            }
        }
    }
#####End

###########################################################