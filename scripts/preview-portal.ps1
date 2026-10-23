param([string]$RedisExecutable = $env:UNIPASS_TEST_REDIS_EXECUTABLE)
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($RedisExecutable)) { throw 'Pass -RedisExecutable with an owned local redis-server executable.' }
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    & mvn -B -ntp -pl iam-server -am test '-Dtest=PortalContinuationsTest' '-Dsurefire.failIfNoSpecifiedTests=false'
    if ($LASTEXITCODE -ne 0) { throw 'Preview compilation and verification failed.' }
    [xml]$report = Get-Content -Raw -LiteralPath 'iam-server/target/surefire-reports/TEST-com.unipass.server.PortalContinuationsTest.xml'
    $previewClasspath = ($report.testsuite.properties.property | Where-Object { $_.name -eq 'java.class.path' }).value
    if ([string]::IsNullOrWhiteSpace($previewClasspath)) { throw 'Test classpath is missing.' }
    & java -cp $previewClasspath com.unipass.server.PortalBrowserFixture (Join-Path $projectRoot 'output/playwright') $RedisExecutable
    if ($LASTEXITCODE -ne 0) { throw 'Preview fixture failed.' }
} finally { Pop-Location }
