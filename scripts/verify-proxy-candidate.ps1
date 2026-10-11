param(
  [string]$Image='workbuddy2api-panel:account-proxy-candidate',
  [ValidateSet('http','socks5','socks5h')][string]$Scheme='http'
)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$id=([guid]::NewGuid().ToString('N')).Substring(0,8)
$network="wbproxy-dev-$id";$volume="wbproxy-fixture-$id"
$fixture="wbproxy-upstream-$id";$candidate="wbproxy-candidate-$id"
$inputDir=Join-Path $repo "output\playwright\candidate-$id"
New-Item -ItemType Directory -Force -Path $inputDir | Out-Null
function DockerOK([string[]]$ArgsList) {
  $result=& docker @ArgsList
  if($LASTEXITCODE -ne 0){throw "docker fixture command failed: $($ArgsList[0])"}
  return $result
}
function WriteJSON($name,$value) {
  $value|ConvertTo-Json -Depth 15|Set-Content -LiteralPath (Join-Path $inputDir $name) -Encoding utf8NoBOM
}
try {
  DockerOK -ArgsList @('network','create',$network)|Out-Null
  $subnet=(DockerOK -ArgsList @('network','inspect',$network)|ConvertFrom-Json)[0].IPAM.Config[0].Subnet
  DockerOK -ArgsList @('volume','create',$volume)|Out-Null
  $cfg=@{
    listen=':7863';api_key='fixture-key';auth_dir='/fixtures/auths';state_file='/fixtures/data/state.json'
    global=@{enabled=$true;chat_base='http://direct-counter:18889';billing_base='http://direct-counter:18889'}
    egress=@{allowed_proxy_cidrs=@($subnet)}
    schedule=@{checkin_enabled=$false;travel_enabled=$false;activity_enabled=$false;keepalive_enabled=$false;blackcat_enabled=$false;growth_enabled=$false;balance_refresh_enabled=$false}
    logging=@{request_archive_enabled=$false}
  }
  WriteJSON 'config.json' $cfg
  WriteJSON 'auth.json' @{auth=@{accessToken='synthetic-initial';refreshToken='synthetic-refresh';expiresAt=[DateTimeOffset]::UtcNow.AddHours(2).ToUnixTimeSeconds();realm='global';domain='synthetic.workbuddy.ai'};account=@{uid='candidate-global';nickname='candidate fixture';enterpriseId='fixture-enterprise'}}
  $slot=@{id='slot-1';name='candidate local proxy';enabled=$true;scheme=$Scheme;host='proxy-fixture';port=18888;transport_generation=1}
  if($Scheme -ne 'http'){
    $slot.port=18890
    $slot.username='synthetic-socks-user'
    $slot.password='synthetic-socks-password'
  }
  WriteJSON 'proxies.json' @{schema_version=1;revision=1;next_slot_seq=2;slots=@{'slot-1'=$slot};bindings=@{'candidate-global'='slot-1'};probe_results=@{}}
  DockerOK -ArgsList @('run','--rm','-v',"$($volume):/fixtures",'-v',"$($inputDir):/input:ro",'alpine:3.20','sh','-c','mkdir -p /fixtures/auths /fixtures/data; cp /input/config.json /fixtures/config.json; cp /input/auth.json /fixtures/auths/workbuddy-candidate-global.json; cp /input/proxies.json /fixtures/data/proxies.json; chmod 600 /fixtures/config.json /fixtures/auths/*.json /fixtures/data/*.json; chown -R 10001:10001 /fixtures')|Out-Null
  $fixtureArgs=@('run','-d','--name',$fixture,'--network',$network,'--network-alias','proxy-fixture','--network-alias','direct-counter','-v',"$($repo):/src:ro")
  if($Scheme -ne 'http'){
    $fixtureArgs+=@('-e','FIXTURE_SOCKS_USER=synthetic-socks-user','-e','FIXTURE_SOCKS_PASSWORD=synthetic-socks-password')
  }
  $fixtureArgs+=@('python:3.12-slim','python','/src/scripts/proxy_candidate_fixture.py')
  DockerOK -ArgsList $fixtureArgs|Out-Null
  DockerOK -ArgsList @('run','-d','--name',$candidate,'--network',$network,'-p','127.0.0.1::7863','-v',"$($volume):/fixtures",$Image,'-config','/fixtures/config.json')|Out-Null
  $inspect=(DockerOK -ArgsList @('inspect',$candidate)|ConvertFrom-Json)[0]
  $port=$inspect.NetworkSettings.Ports.'7863/tcp'[0].HostPort
  $base="http://127.0.0.1:$port";$headers=@{Authorization='Bearer fixture-key'}
  $ready=$false
  for($i=0;$i -lt 40;$i++){
    try{$overview=Invoke-RestMethod "$base/panel/api/overview" -Headers $headers -TimeoutSec 2;$ready=$true;break}catch{Start-Sleep -Milliseconds 250}
  }
  if(!$ready){throw 'candidate did not start'}
  $models=Invoke-RestMethod "$base/v1/models" -Headers $headers
  $chat='{"model":"global:glm-5.2","messages":[{"role":"user","content":"fixture"}],"stream":false}'
  $reply=Invoke-RestMethod "$base/v1/chat/completions" -Method Post -Headers $headers -ContentType application/json -Body $chat
  if($reply.choices[0].message.content -ne 'candidate fixture ok'){throw 'candidate chat fixture mismatch'}
  Invoke-RestMethod "$base/panel/api/accounts/candidate-global/balance" -Method Post -Headers $headers|Out-Null
  Invoke-RestMethod "$base/panel/api/keepalive_all" -Method Post -Headers $headers|Out-Null
  $tokenOK='False'
  for($i=0;$i -lt 40;$i++) {
    $tokenOK=DockerOK -ArgsList @('exec',$candidate,'python3','-c','import json; print(json.load(open("/fixtures/auths/workbuddy-candidate-global.json"))["auth"]["accessToken"] == "synthetic-rotated")')
    if("$tokenOK" -eq 'True'){break}
    Start-Sleep -Milliseconds 250
  }
  if("$tokenOK" -ne 'True'){throw 'asynchronous keepalive did not persist refreshed token'}
  DockerOK -ArgsList @('restart',$candidate)|Out-Null
  $inspect=(DockerOK -ArgsList @('inspect',$candidate)|ConvertFrom-Json)[0]
  $port=$inspect.NetworkSettings.Ports.'7863/tcp'[0].HostPort
  $base="http://127.0.0.1:$port"
  $saved=$null
  for($i=0;$i -lt 40;$i++) {
    try{$saved=Invoke-RestMethod "$base/panel/api/proxies" -Headers $headers -TimeoutSec 2;break}catch{Start-Sleep -Milliseconds 250}
  }
  if($null -eq $saved){throw 'candidate restart did not become ready'}
  if($saved.accounts.'candidate-global'.slot_id -ne 'slot-1'){throw 'restart lost binding'}
  $tokenOK=DockerOK -ArgsList @('exec',$candidate,'python3','-c','import json; print(json.load(open("/fixtures/auths/workbuddy-candidate-global.json"))["auth"]["accessToken"] == "synthetic-rotated")')
  if("$tokenOK" -ne 'True'){throw 'refresh token did not persist across restart'}
  DockerOK -ArgsList @('exec',$fixture,'python','-c','import urllib.request; urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:18888/fixture/break-proxy",method="POST")).read()')|Out-Null
  Start-Sleep -Milliseconds 250
  $failed=Invoke-WebRequest "$base/v1/chat/completions" -Method Post -Headers $headers -ContentType application/json -Body $chat -SkipHttpErrorCheck
  $failureBody=$failed.Content
  if($failureBody -is [byte[]]){$failureBody=[Text.Encoding]::UTF8.GetString($failureBody)}
  WriteJSON 'failure-first.json' @{status=[int]$failed.StatusCode;body="$failureBody"}
  # A proxy TCP close after headers is indistinguishable from upstream EOF;
  # preserve that uncertainty rather than falsely classifying an account fault.
  if($failed.StatusCode -lt 500 -or "$failureBody" -notmatch 'proxy_|upstream_transport_failed|upstream_timeout'){throw 'proxy interruption did not stop request'}
  $counts=DockerOK -ArgsList @('exec',$fixture,'python','-c','import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:18889/fixture/counts").read().decode())')|ConvertFrom-Json
  if($counts.direct -ne 0){throw "candidate leaked $($counts.direct) direct requests"}
  if($Scheme -ne 'http' -and $counts.socks -lt 1){throw 'candidate did not use the SOCKS fixture'}
  $overview=Invoke-RestMethod "$base/panel/api/overview" -Headers $headers
  if($overview.accounts[0].disabled -or $overview.accounts[0].err_total -gt 0){throw 'proxy fault penalized account'}
  $result=@{image=$Image;image_id=$inspect.Image;scheme=$Scheme;chat='PASS';balance='PASS';refresh_restart='PASS';binding_restart='PASS';proxy_failure_status=[int]$failed.StatusCode;direct=$counts.direct;proxy=$counts.proxy;socks=$counts.socks;socks_targets=$counts.socks_targets;paths=$counts.paths;account_not_penalized=$true}
  WriteJSON 'result.json' $result
  $result|ConvertTo-Json -Depth 10
} finally {
  & docker logs $candidate 2>&1|Set-Content -LiteralPath (Join-Path $inputDir 'candidate.log')
  & docker rm -f $candidate $fixture 2>&1|Out-Null
  & docker network rm $network 2>&1|Out-Null
  & docker volume rm $volume 2>&1|Out-Null
}
