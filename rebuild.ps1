# Reconstrói o stack do PCAP Analyzer end-to-end via Docker:
#   1) `docker compose down`               — derruba containers (preserva volumes nomeados)
#   2) `docker compose build --no-cache web`— refaz a imagem do zero (inclui o stage Vite do frontend)
#   3) `docker compose up -d --force-recreate --renew-anon-volumes`
#   4) Verificação pós-up: web responde + bundle Vite foi injetado no HTML
#
# --renew-anon-volumes é necessário porque, se algum dia voltar a existir um
# volume anônimo (ex.: `/app/static/dist`), o Compose reaproveita o volume
# antigo e o bundle novo da imagem fica "tampado" pelo bundle velho.
#
# Uso: .\rebuild.ps1

$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot

function Step($msg) {
    Write-Host ""
    Write-Host "==> $msg" -ForegroundColor Cyan
}

function Fail($msg) {
    Write-Host "ERRO: $msg" -ForegroundColor Red
    exit 1
}

# Sanity: .env precisa estar presente — POSTGRES_PASSWORD/REDIS_PASSWORD usam
# `${VAR:?}` no compose e fazem o up falhar com mensagem confusa se ausentes.
if (-not (Test-Path -LiteralPath ".env")) {
    Fail ".env não encontrado em $PSScriptRoot. Copie .env.example e preencha as credenciais antes de rodar."
}

Step "docker compose down"
docker compose down
if ($LASTEXITCODE -ne 0) { Fail "docker compose down falhou (exit=$LASTEXITCODE)" }

# Step "docker compose build --no-cache web"
# docker compose build --no-cache web
Step "docker compose build web"
docker compose build web
if ($LASTEXITCODE -ne 0) { Fail "build falhou (exit=$LASTEXITCODE)" }

Step "docker compose up -d --force-recreate --renew-anon-volumes"
docker compose up -d --force-recreate --renew-anon-volumes
if ($LASTEXITCODE -ne 0) { Fail "up falhou (exit=$LASTEXITCODE)" }

Step "Status dos servicos"
docker compose ps

Step "Verificacao pos-up"
# Espera o web ficar saudável (gunicorn + Flask iniciam em 5-15s).
$deadline = (Get-Date).AddSeconds(60)
$resp = $null
while ((Get-Date) -lt $deadline) {
    try {
        $resp = Invoke-WebRequest -UseBasicParsing -Uri "http://localhost:5000/" -TimeoutSec 3
        if ($resp.StatusCode -lt 500) { break }
    } catch {
        Start-Sleep -Seconds 2
    }
}
if (-not $resp) {
    Fail "web não respondeu em http://localhost:5000/ após 60s. Veja: docker compose logs web"
}
$cssLine = ($resp.Content -split "`n") | Where-Object { $_ -match 'rel="stylesheet"' } | Select-Object -First 1
if (-not $cssLine -or $cssLine -match 'manifest missing') {
    Fail "Bundle Vite não foi injetado no HTML. O /app/static/dist da imagem provavelmente está vazio."
}
Write-Host "OK: bundle injetado -> $($cssLine.Trim())" -ForegroundColor Green

Step "Pronto"
Write-Host "Acesse http://localhost:5000/" -ForegroundColor Green
Write-Host "Logs:  docker compose logs -f web" -ForegroundColor DarkGray
