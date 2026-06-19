# PCAP Network Analyzer

Sistema web em **Flask** para análise forense profunda de capturas de rede (`.pcap` / `.pcapng`), focado em **detecção de ameaças**, **threat intelligence multi-fonte**, **baselining comportamental** e **resposta a incidentes**.

- **50+ detectores** (streaming + pós-processamento) cobrindo reconhecimento, brute-force, lateral movement, C2, exfiltração, exploração web, TLS/JA3/JA4, abuso de DNS, ICS/IoT e túneis modernos.
- Cada alerta é mapeado automaticamente para uma técnica **MITRE ATT&CK** e recebe um score de **confiança (0-100)**.
- **Threat intelligence** contra 16 fontes (IPsum, abuse.ch, CISA KEV, Spamhaus, OTX, MISP, TAXII, AbuseIPDB, etc.).
- **Forense de payload**: file carving HTTP/SMB, hash lookup (VirusTotal/MalwareBazaar), varredura YARA, inspeção de certificados TLS.
- **Autenticação + RBAC** (viewer / analyst / admin), log de auditoria, CSRF, headers de segurança.
- Processamento assíncrono com **Celery + Redis** (filas separadas), persistência em **PostgreSQL** particionado.
- UI estilo SOC: dashboard, kill-chain, grafo de fluxo interativo, visualizador de pacotes, relatórios PDF/HTML.

---

## Sumário

- [O Sistema](#o-sistema)
- [Arquitetura](#arquitetura)
- [Recursos](#recursos)
- [Tipos de Análise / Detecções](#tipos-de-análise--detecções)
  - [Detecções de Segurança](#detecções-de-segurança)
  - [Threat Intelligence](#threat-intelligence)
  - [Análise Comportamental e Correlação](#análise-comportamental-e-correlação)
  - [Forense de Payload](#forense-de-payload)
  - [MITRE ATT&CK](#mitre-attck)
- [Instalação](#instalação)
- [Senhas e Segurança](#senhas-e-segurança)
- [Como Usar](#como-usar)
- [Configurações](#configurações)
- [API REST](#api-rest)
- [Comandos Úteis](#comandos-úteis)
- [Atualizações](#atualizações)
- [Estrutura de Arquivos](#estrutura-de-arquivos)
- [Banco de Dados](#banco-de-dados)
- [Troubleshooting](#troubleshooting)
- [Limitações Conhecidas](#limitações-conhecidas)
- [Licença](#licença)

---

## O Sistema

O PCAP Network Analyzer recebe uma captura de rede, faz o parsing **streaming** (pacote a pacote, sem carregar o arquivo inteiro na memória), executa dezenas de detectores, enriquece o resultado com threat intelligence e geolocalização, e apresenta tudo numa interface web única (SPA).

| Camada | Tecnologia |
|--------|-----------|
| Web / API | Flask 3.0 + Gunicorn (gthread) |
| Autenticação | Flask-Login + Werkzeug (hashing scrypt) + RBAC |
| Parsing de pacotes | Scapy 2.5 (`PcapReader` streaming) |
| Processamento assíncrono | Celery 5.3 + Redis 7 (filas `pcap.fast` / `pcap.slow` + Beat) |
| Persistência | PostgreSQL 15 (tabela `alerts` particionada por mês) |
| Frontend | SPA jQuery + Bootstrap, empacotada com Vite |
| ML / Estatística | scikit-learn (IsolationForest), autocorrelação, entropia |
| Relatórios | ReportLab (PDF), Jinja2 (HTML) |
| Documentação de API | Flasgger / Swagger UI |
| Empacotamento | Docker multi-stage (Node build + Python runtime, usuário não-root) |

---

## Arquitetura

```
                          ┌─────────────┐
                          │   Browser   │  SPA (Vite bundle)
                          └──────┬──────┘
                                 │ HTTPS/HTTP + CSRF
                          ┌──────▼──────┐
                          │  Flask Web  │  Gunicorn · Auth/RBAC · API REST
                          │  (web:5000) │  Audit log · Security headers
                          └──────┬──────┘
                                 │
                 ┌───────────────┼────────────────┐
                 │               │                │
          ┌──────▼──────┐  ┌─────▼─────┐   ┌──────▼───────┐
          │ PostgreSQL  │  │   Redis   │   │   Celery     │
          │  (db:5432)  │  │ (broker)  │   │   workers    │
          └─────────────┘  └─────┬─────┘   └──────┬───────┘
                                 │                │
                 ┌───────────────┴────┐    ┌──────┴─────────────┐
                 │ celery_fast        │    │ celery_slow        │
                 │ parsing+detecção   │    │ geo+threat intel   │
                 │ (queue pcap.fast)  │    │ hash lookup, YARA  │
                 └────────────────────┘    │ (queue pcap.slow)  │
                                           └────────────────────┘
                 ┌────────────────────┐
                 │ celery_beat        │  purga de retenção (03:00 UTC),
                 │ tarefas periódicas │  criação de partições mensais
                 └────────────────────┘
```

**Pipeline de uma análise:**

1. **Upload** → `web` valida o arquivo (extensão, `secure_filename`, realpath dentro de `uploads/`) e enfileira a tarefa.
2. **Fila `pcap.fast`** → parsing streaming, ~50 detectores, baseline comportamental, correlação, gravação no PostgreSQL. *O resultado já fica visível na UI aqui.*
3. **Fila `pcap.slow`** → geolocalização, threat intel de IPs/domínios, lookup de hash de arquivos extraídos, varredura YARA. *Enriquece o scan já salvo.*
4. **Fallback** → sem `CELERY_BROKER_URL` configurada, a análise roda numa thread do próprio `web` (modo single-tenant/dev).

---

## Recursos

### Detecção
- **~50 detectores** divididos em *streaming* (avaliados pacote a pacote durante o parsing) e *post* (avaliados sobre artefatos agregados depois do parsing).
- Cada alerta carrega: severidade (`critical | high | medium | low | info`), confiança (0-100), categoria, IP envolvido, detalhes estruturados, recomendação e técnica MITRE ATT&CK.
- **Supressão por papel de host** — alertas são rebaixados (não removidos) quando o host inferido justifica o comportamento (ex.: NXDOMAIN spike num resolver DNS).
- **Regras definidas pelo usuário** — JSON nativo + importação de regras **Suricata** (`.rules`) e **Zeek** (`.sig`).

### Threat Intelligence
- 16 fontes integradas; padrão **opt-in com no-op silencioso** (sem credencial, o consumidor simplesmente não roda).
- Cache em memória por feed (TTL 24 h) e cache em PostgreSQL por IP (TTL 7 dias).

### Investigação e Resposta
- **Kill-chain timeline** por host (swimlane por tática ATT&CK).
- **Grafo de fluxo interativo** (vis-network) com pivot para abas de IPs/alertas.
- **Host risk score** (0-100) agregando severidade × persistência × reputação × desvio de baseline.
- **Triagem de alertas** (estado: aberto / em análise / falso positivo / confirmado) — marcar falso positivo treina o classificador FP.
- **Regras de supressão** (whitelist) e **assinaturas de FP** aprendidas.
- **Export MITRE ATT&CK Navigator** (layer JSON v4.5), **STIX 2.1 / MISP** de IOCs.
- **PCAP diff** entre dois scans e **BPF replay** (filtra/reexporta pacotes).

### Operação
- Autenticação, RBAC de 3 papéis, log de auditoria de toda operação mutante.
- Notificações de alertas críticos via **Slack / Teams / webhook genérico / Syslog (CEF) / e-mail (SMTP)**.
- Política de **retenção** configurável com purga automática diária.
- Histórico completo com filtro por datas e visão agregada.

### UI e Relatórios
- Dashboard com gráficos (Chart.js), tabelas paginadas (DataTables), dark mode.
- Visualizador de pacotes estilo Wireshark (camadas + hex dump).
- Relatórios **PDF** (ReportLab) e **HTML standalone** com coluna ATT&CK.
- Geolocalização automática (ip-api.com) com bandeiras e tooltip.

---

## Tipos de Análise / Detecções

> Os detectores ficam em `pcap_analyzer/detectors/` (`__init__.py` = streaming, `post.py` = pós-processamento). Comportamental, correlação e host roles ficam em módulos próprios na raiz.

### Detecções de Segurança

#### Reconnaissance / Discovery
| Detecção | Indicadores | ATT&CK |
|----------|-------------|--------|
| Port Scan (vertical) | SYN para muitas portas; **fingerprint de Nmap** (`-sS`, OS-detect) e banda de duração | T1046 |
| Horizontal Port Scan | Mesma porta em muitos hosts | T1046 |
| ICMP Ping Sweep | Echo request para muitos hosts | T1018 |
| ARP Discovery Sweep | Varredura ARP de muitos alvos | T1018 |
| SNMP Walk | Volume alto de queries SNMP | T1602.001 |
| Security Scanner User-Agent | UA de Nmap, Nessus, sqlmap, ZAP, Burp, etc. | T1595.002 |
| HTTP sem User-Agent | Cliente sem UA (atípico de navegador) | T1595 |
| GreyNoise RIOT (opt-in) | Rebaixa scans originados de scanners benignos conhecidos | — |

#### Initial Access / Web Exploitation
| Detecção | Indicadores | ATT&CK |
|----------|-------------|--------|
| Caminhos de exploração | `.env`, `/admin`, `wp-login.php`, `.git`, `phpmyadmin`, etc. | T1190 |
| Métodos HTTP incomuns | TRACE, CONNECT, métodos WebDAV | T1190 |
| Exploit Payloads | Log4Shell, Spring4Shell, ProxyShell, OGNL (Confluence), command injection, SQLi, SSRF a IMDS, webshell RCE | T1190 |
| CVE / CISA KEV | CVEs citados em alertas cruzados com o catálogo CISA KEV (promove para crítico se ransomware) | T1190 |

#### Credential Access
| Detecção | Indicadores | ATT&CK |
|----------|-------------|--------|
| Brute Force | Tentativas em 19 portas de serviço (SSH/FTP/SMB/RDP/MSSQL/MySQL/PostgreSQL/WinRM/VNC/SMTP/POP3/IMAP...) | T1110 |
| Password Spraying | Uma senha contra muitas contas | T1110.003 |
| Cleartext Credentials | Credenciais em texto claro (consciente de STARTTLS) | T1040 |
| Kerberos Abuse | Kerberoasting (RC4), AS-REP roasting, downgrade RC4 | T1558.003/.004 |
| LLMNR/NBT-NS Poisoning | Respostas suspeitas tipo Responder | T1557.001 |
| ARP Spoofing / Gratuitous ARP Flood | Conflitos IP↔MAC, flood de gratuitous ARP | T1557.002 |

#### Lateral Movement
| Detecção | Indicadores | ATT&CK |
|----------|-------------|--------|
| Lateral SMB / RDP / SSH / WinRM | Tráfego entre internos para vários alvos | T1021.x |
| Lateral Kerberos | Tickets Kerberos entre internos | T1558 |
| DCERPC Lateral Pipes | Pipes SMB `svcctl`, `atsvc`, `winreg`, `samr`, `lsarpc`, `netlogon`, `spoolss`... | T1021.002 |
| External SMB Access | Tráfego SMB cruzando a borda | T1021.002 |

#### Command and Control
| Detecção | Indicadores | ATT&CK |
|----------|-------------|--------|
| Beaconing (C2) | Conexões periódicas; multi-sinal: jitter, autocorrelação, âncora NTP, uniformidade de payload | T1071.001 |
| Cobalt Strike (HTTP) | Checksum8 de stager, URIs de perfis malleable, UAs default, cookie `session=` | T1071.001 / S0154 |
| Cobalt Strike DNS Beacon | Prefixos + labels longos de alta entropia em DNS | T1071.004 / S0154 |
| DGA Domain Activity | Score combinado (entropia, log-likelihood de bigramas, dígitos, comprimento) | T1568.002 |
| Fast-Flux DNS | Domínio resolve para muitos IPs com TTL baixo | T1568.001 |
| NXDOMAIN Spike | Picos de NXDOMAIN num cliente (sintoma de DGA) | T1568.002 |
| DNS Tunneling | Subdomínio longo + alta entropia | T1071.004 |
| DoT / DoH | DNS-over-TLS (:853) e DNS-over-HTTPS (SNI / JA3 / IPs de provedores) | T1071.004 |
| TLS suspeito | SNI atípica, ausência de SNI, **ECH** (Encrypted ClientHello), TLS obsoleto (SSLv3/1.0/1.1) | T1071.001 / T1573 |
| JA3 / JA3S malicioso | Fingerprints contra lista interna + SSLBL (abuse.ch) | T1573 |
| Suspicious Port / Protocol | Portas 4444/31337/etc.; protocolos em texto claro (FTP, Telnet) | T1571 / T1071 |

#### Exfiltration
| Detecção | Indicadores | ATT&CK |
|----------|-------------|--------|
| Volume Exfiltration | Saída alta + ratio out/in elevado | T1048 |
| Sustained Exfil Ratio | Vazamento lento e contínuo abaixo do limiar clássico | T1029 |
| DNS Cumulative Exfil | Volume cumulativo alto por zona DNS | T1048.003 |
| ICMP Tunneling | Echo com payload grande | T1095 |
| File-share / Paste service | pastebin, transfer.sh, anonfiles, mega, etc. | T1567.002 |

#### Túneis Modernos, ICS/IoT e Exposição Operacional
| Detecção | Indicadores | ATT&CK |
|----------|-------------|--------|
| Modern Tunnels | DoQ (UDP/853), WireGuard, OpenVPN, túneis IP-layer (GRE, IPIP, L2TP, SIT) | T1572 |
| ICS Protocols | S7Comm, Modbus, MQTT, DNP3, EtherNet/IP, BACnet — **Modbus write de IP externo = crítico** | T0855 |
| Operational Exposure | Handshake real de banco (MSSQL/MySQL/PostgreSQL/Oracle/Mongo/Redis/Elastic/Couch/Memcached) vindo de IP externo | T1190 |

#### Estatística / ML e Comportamental
| Detecção | Indicadores |
|----------|-------------|
| Payload entropy | Entropia alta em portas de texto claro |
| Flow anomaly | IsolationForest sobre features de fluxo L4 |
| Seasonality | Desvio do baseline hora-da-semana |
| First-Seen | IP externo, protocolo, host interno, JA3/JA3S/JA4, SNI, HTTP host nunca vistos antes |
| Volume surge | Bytes enviados/recebidos muito acima da mediana histórica |

#### Fingerprints Modernos
JA3/JA3S e **JA4 / JA4S / JA4H / HASSH / HASSH-Server** são extraídos de handshakes TLS e SSH e rastreados como artefatos *first-seen* — qualquer fingerprint inédito vira alerta correlacionado.

### Threat Intelligence

| Fonte | Tipo | Credencial |
|-------|------|-----------|
| **IPsum** | IPs maliciosos com score | — (grátis) |
| **Tor Exit Nodes** | Lista de saídas Tor | — |
| **Feodo Tracker** (abuse.ch) | C2 de botnets ativos | — |
| **ThreatFox** (abuse.ch) | IOC multi-tipo | — |
| **URLhaus** (abuse.ch) | URLs/hosts maliciosos | — |
| **SSLBL JA3** (abuse.ch) | Fingerprints JA3 de malware | — |
| **CISA KEV** | Vulnerabilidades exploradas (flag ransomware) | — |
| **Spamhaus DROP/EDROP** | Blocos CIDR hostis | — |
| **AbuseIPDB** | Confidence score | API key |
| **AlienVault OTX** | Pulses de IOC | API key (free) |
| **CIRCL Passive DNS/SSL** | Histórico passivo | Basic auth |
| **MISP** | Plataforma de IOC | API key + URL |
| **TAXII 2.1** | Feed STIX | URL + auth |
| **GreyNoise** | Classificação de scanners | API key |
| **VirusTotal / MalwareBazaar** | Reputação de hash de arquivo | API key |
| **ip-api.com** | Geolocalização | — |

Cada IP externo recebe `{reputation_score, is_malicious, abuse_confidence, sources, labels}` agregando todas as fontes. Domínios em alertas DNS/TLS/HTTP são consultados e o resultado anexado em `details.domain_reputation`.

### Análise Comportamental e Correlação

- **Baseline** (`behavioral.py`) — compara o scan atual com a **mediana** dos últimos 60 scans (volume, novos protocolos, novos destinos externos, hosts inéditos, sazonalidade hora-da-semana). Auto-desabilitado com menos de 3 scans históricos.
- **Correlação** (`correlation.py`) — rastreia artefatos *first-seen* entre scans (tabela `artifact_seen`) e aplica regras de kill-chain dentro do mesmo scan (encadeamento de táticas).
- **Asset inventory** (`asset_inventory.py`) — fingerprint passivo estilo p0f dos hosts.
- **Host roles** (`host_roles.py`) — infere o papel do host (resolver DNS, mail server, file server, impressora) e rebaixa alertas que esse papel explica.
- **Host risk** (`host_risk.py`) — score 0-100 por host.

### Forense de Payload

- **File carving** (`file_carving.py`) — extrai arquivos de respostas HTTP e uploads multipart a partir de fluxos TCP remontados; hashes MD5/SHA-1/SHA-256; gravados em `data/artifacts/<sha256>`.
- **Hash lookup** (`hash_lookup.py`) — consulta VirusTotal + MalwareBazaar; hit malicioso gera alerta crítico (T1105).
- **YARA** (`yara_scan.py`) — compila regras de `data/yara_rules/` e varre cada artefato extraído.
- **TLS certificate inspection** (`pcap_analyzer/tls.py`) — extrai CN/SAN/issuer/validade; alerta para self-signed externo, mismatch CN/SAN×SNI, certificado expirado, Let's Encrypt em SNI tipo-DGA, SAN só com IP literal.

### MITRE ATT&CK

Cada alerta é anotado com:

```json
"mitre_attack": {
    "technique_id": "T1110",
    "technique_name": "Brute Force",
    "tactic_id": "TA0006",
    "tactic_name": "Credential Access",
    "url": "https://attack.mitre.org/techniques/T1110/"
}
```

A informação aparece na UI (link clicável + badge da tática), na coluna *ATT&CK* dos relatórios, na **kill-chain timeline** e no **export para o ATT&CK Navigator**. Mapeamento mantido em `mitre_attack.py`.

---

## Instalação

### Requisitos

- **Docker** + **Docker Compose** (recomendado), **ou**
- **Python 3.11+**, **PostgreSQL 15+**, **Redis 7+**, **Node.js 20+** (para o bundle do frontend).

### 1. Configurar o `.env` (obrigatório)

O `docker-compose.yml` **recusa subir** sem as senhas — elas vêm de um arquivo `.env` local (gitignored, nunca embutido na imagem).

```bash
cp .env.example .env
```

Gere segredos fortes e edite o `.env`:

```bash
# Senha do PostgreSQL e do Redis
python -c "import secrets;print(secrets.token_urlsafe(24))"
# Chave de assinatura de sessão do Flask
python -c "import secrets;print(secrets.token_hex(32))"
```

Variáveis obrigatórias do `.env`:

| Variável | Descrição |
|----------|-----------|
| `POSTGRES_PASSWORD` | Senha do banco — **obrigatória** |
| `REDIS_PASSWORD` | Senha do broker Redis — **obrigatória** |
| `FLASK_SECRET_KEY` | Chave de sessão; sem ela as sessões caem a cada restart |

Veja [Senhas e Segurança](#senhas-e-segurança) para as variáveis opcionais.

### 2. Docker (recomendado)

```bash
docker compose up --build -d
```

Sobe 6 serviços:

| Serviço | Função |
|---------|--------|
| `web` | Flask sob Gunicorn em `:5000` |
| `db` | PostgreSQL 15 |
| `redis` | Redis 7 (broker Celery, protegido por senha) |
| `celery_fast` | Worker da fila `pcap.fast` (parsing + detecção) |
| `celery_slow` | Worker da fila `pcap.slow` (geo + threat intel + hash + YARA) |
| `celery_beat` | Tarefas periódicas (purga de retenção, partições) |

Acesse **`http://localhost:5000`**. As credenciais de primeiro acesso são impressas no log do `web` (veja [Senhas](#senhas-e-segurança)).

O bundle do frontend (Vite) é compilado **dentro do Dockerfile** — um estágio `node:20-alpine` roda `npm install && npm run build`. Não é preciso ter Node.js no host.

### 3. Manual (sem Docker)

```bash
python3 -m venv venv
source venv/bin/activate            # Linux/Mac  (.\venv\Scripts\activate no Windows)
pip install -r requirements.txt

npm install && npm run build        # gera static/dist/ a partir de frontend/src/
```

Crie o banco:

```sql
CREATE USER pcap_user WITH PASSWORD 'sua_senha';
CREATE DATABASE pcap_analyzer OWNER pcap_user;
```

Inicie (produção usa Gunicorn; `python app.py` é só o servidor de dev):

```bash
export DATABASE_URL=postgresql://pcap_user:sua_senha@localhost:5432/pcap_analyzer
export FLASK_SECRET_KEY=$(python -c "import secrets;print(secrets.token_hex(32))")
export CELERY_BROKER_URL=redis://:senha@localhost:6379/0      # opcional
export CELERY_RESULT_BACKEND=redis://:senha@localhost:6379/0  # opcional

gunicorn --bind 0.0.0.0:5000 --worker-class gthread --workers 1 --threads 8 app:app
celery -A celery_app.celery worker -Q pcap.fast --concurrency=2 -n fast@%h   # opcional
celery -A celery_app.celery worker -Q pcap.slow --concurrency=4 -n slow@%h   # opcional
celery -A celery_app.celery beat                                            # opcional
```

> `--workers 1` é intencional: o progresso da análise (`analysis_status`) é estado global do processo. Escale com `--threads`, não com `--workers`.

#### Frontend em modo desenvolvimento (HMR)

```bash
# Terminal 1 — API Flask
python app.py
# Terminal 2 — Vite dev server (porta 5173, proxy /api → :5000)
VITE_DEV=1 npm run dev
```

---

## Senhas e Segurança

### Onde ficam as senhas

| Senha | Local | Como definir |
|-------|-------|--------------|
| PostgreSQL | `.env` → `POSTGRES_PASSWORD` | Obrigatória; gere com `secrets.token_urlsafe` |
| Redis | `.env` → `REDIS_PASSWORD` | Obrigatória |
| Chave de sessão Flask | `.env` → `FLASK_SECRET_KEY` | Obrigatória em produção (sem ela, sessões não sobrevivem a restart) |
| Usuário admin da aplicação | Banco (tabela `users`, hash scrypt) | Veja abaixo |
| API keys de threat intel | `data/settings.json` (`api_keys`) ou variáveis de ambiente | Pela aba **Configurações** ou `POST /api/admin/api-keys/<service>` |

O `.env` é **gitignored** e **não** entra na imagem Docker. O `data/settings.json` também é gitignored (acumula segredos em runtime) — o repositório versiona apenas `data/settings.example.json` como template.

### Primeiro acesso (usuário admin)

Na primeira subida com o banco vazio, a aplicação cria o usuário **`admin`**:

- Se `PCAP_DEFAULT_ADMIN_PASSWORD` estiver definida no `.env`, ela é usada.
- Caso contrário, uma **senha aleatória** é gerada e **impressa no log do container `web`** (com `must_change_password=true` — troca obrigatória no primeiro login).

```bash
docker compose logs web | grep -A6 "Bootstrapping default admin"
```

### Trocar / resetar a senha do admin

- **Pela UI**: aba de usuário → trocar senha; admins podem resetar a de qualquer usuário.
- **Pela API**: `POST /api/auth/password` (própria) ou `POST /api/users/<id>/password` (admin).
- **Resetar o banco inteiro**: `python reset_db.py` recria o schema e gera uma nova senha admin aleatória (ou usa `PCAP_DEFAULT_ADMIN_PASSWORD`), com troca obrigatória no primeiro login.

### RBAC — papéis

| Papel | Permissões |
|-------|-----------|
| `viewer` | Somente leitura (endpoints GET, login/logout, ver arquivos extraídos) |
| `analyst` | viewer + uploads, triagem, supressão, webhooks, settings, exports, replays, lookup manual |
| `admin` | analyst + gestão de usuários, API keys, purga de retenção, download de arquivos extraídos |

### Endurecimento de segurança aplicado

- **CSRF** — token por sessão, exigido via header `X-CSRF-Token` em todo POST/PUT/PATCH/DELETE.
- **Headers** — CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, HSTS (quando sob HTTPS).
- **Brute-force de login** — limitador deslizante em memória (10 falhas / 15 min / IP → HTTP 429).
- **Sessões** — `HttpOnly`, `SameSite=Lax`, expiração deslizante (`SESSION_LIFETIME_HOURS`, padrão 12 h).
- **SSRF** — webhooks bloqueiam IPs privados/loopback por padrão.
- **Container** — roda como usuário não-root (`appuser`, uid 1000); sem bind-mount do código-fonte.
- **Erros** — exceções não retornam stack trace ao cliente (vão só para o log do servidor).

> **Importante:** em produção, sirva sempre atrás de um proxy reverso com TLS e defina `SESSION_COOKIE_SECURE=1` e `TRUSTED_PROXY_COUNT` no `.env`. Sem TLS, **não exponha à internet**.

### Variáveis de ambiente

| Variável | Descrição | Padrão |
|----------|-----------|--------|
| `DATABASE_URL` | URL do PostgreSQL | — |
| `CELERY_BROKER_URL` / `CELERY_RESULT_BACKEND` | Redis; vazio = fallback para threading | desabilitado |
| `FLASK_SECRET_KEY` | Chave de assinatura de sessão | gerada por processo (avisa) |
| `PCAP_DEFAULT_ADMIN_PASSWORD` | Senha inicial do admin | aleatória (impressa no log) |
| `SESSION_COOKIE_SECURE` | `1` quando servido sob HTTPS | off |
| `SESSION_LIFETIME_HOURS` | Timeout de inatividade da sessão | `12` |
| `TRUSTED_PROXY_COUNT` | Nº de proxies reversos confiáveis (habilita `ProxyFix`) | `0` |
| `MAX_UPLOAD_BYTES` | Tamanho máximo de upload | `10 GiB` |
| `DISABLE_SWAGGER` | `1` desabilita a UI Swagger em `/apidocs` | off |
| `PCAP_ALLOW_PRIVATE_WEBHOOKS` | `1` permite webhooks para IPs privados | off |
| `ABUSEIPDB_API_KEY` | API key do AbuseIPDB | desabilitado |
| `FLASK_DEBUG` | `1` liga o debugger (**nunca em produção**) | off |
| `UPLOAD_FOLDER` / `SETTINGS_FILE` | Caminhos de upload / settings | `data/uploads` · `data/settings.json` |

---

## Como Usar

1. **Login** com as credenciais (admin no primeiro acesso — troque a senha).
2. **Upload** — arraste ou selecione `.pcap`/`.pcapng` e clique *Analyze*.
3. **Acompanhe o progresso** — barra em tempo real (parsing → detecção → comportamental → save → enriquecimento).
4. **Explore as abas:**
   - **Visão Geral** — métricas, gráficos, alertas recentes, botões PDF/HTML.
   - **IPs e Tráfego** — nome, grupo, geo, reputação, **risk score**, stats.
   - **Protocolos** — stats com drill-down de IPs.
   - **Alertas** — filtro por severidade, ATT&CK clicável, triagem.
   - **Kill-Chain** — swimlane por host × tática; botão de export para o Navigator.
   - **Graph** — grafo de fluxo interativo; clique num nó para pivotar.
   - **Pacotes** — visualizador estilo Wireshark com filtros, paginação, camadas e hex dump.
   - **Configurações** — thresholds, ranges confiáveis, API keys, regras, webhooks, usuários, retenção.
5. **Histórico** — filtro por data; *Ver Todos (Agregado)* respeita o filtro.
6. **Dark mode** — toggle no navbar (persistido em localStorage).

---

## Configurações

Arquivo: `data/settings.json` (semeado de `data/settings.example.json` na primeira execução). Editável pela aba **Configurações** ou via `GET/POST /api/settings` — segredos são redigidos no GET e mesclados de volta no POST.

### Principais grupos

- **`trusted_ranges`** — CIDRs internos (RFC1918 por padrão) usados para classificar tráfego interno × externo.
- **`thresholds`** — ~45 limiares de detecção (port scan, DGA, fast-flux, exfil, beaconing, entropia, flow anomaly, first-seen, `max_packets`, etc.). Veja `data/settings.example.json` para a lista completa com os padrões.
- **`carving`** — `enabled`, `max_file_size`, `min_file_size` para o file carving.
- **`api_keys`** — chaves de threat intel (AbuseIPDB, OTX, GreyNoise, VirusTotal, MalwareBazaar, MISP, TAXII, CIRCL...).
- **`retention_days`** — janela de retenção (padrão 90); a purga roda diariamente às 03:00 UTC.
- **`smtp`** — credenciais para o digest de e-mail (a senha é redigida na API).

### Classificação de Risco de Protocolos

| Nível | Protocolos |
|-------|-----------|
| Baixo (verde) | DNS, HTTPS, TLS, SSH, ICMP, NTP, DHCP |
| Médio (amarelo) | TCP, UDP, HTTP, SMTP, IPv6 |
| Alto (vermelho) | FTP, Telnet, ARP, SMB, SMBv1, SNMP |

---

## API REST

Documentação interativa em **`/apidocs`** (Swagger UI). Todos os endpoints exigem autenticação; mutações exigem o header `X-CSRF-Token`. O papel mínimo está indicado entre parênteses.

### Autenticação — `/api/auth`
| Método | Endpoint | Descrição |
|--------|----------|-----------|
| POST | `/login` | Login (username + password) |
| POST | `/logout` | Logout |
| GET | `/me` | Usuário atual + CSRF token |
| GET | `/csrf-token` | Mintar/obter o CSRF token |
| POST | `/password` | Trocar a própria senha |

### Scans e Resultados
| Método | Endpoint | Descrição |
|--------|----------|-----------|
| POST | `/api/upload` *(analyst)* | Upload de PCAP/PCAPNG |
| GET | `/api/status` · `/api/status/stream` | Status da análise (polling / SSE) |
| GET | `/api/results` | Resultados (`scan_id`, `view=aggregate`, datas) |
| GET | `/api/scans` | Histórico (filtro por datas) |
| DELETE | `/api/scans/<id>` · `/api/scans/batch` *(analyst)* | Excluir scan(s) |
| POST | `/api/clear` *(analyst)* | Limpar cache de análise |
| GET | `/api/packets/<scan_id>[/<num>]` | Pacotes paginados / detalhe de um pacote |
| GET | `/api/replay/<scan_id>` *(analyst)* | Replay/reexport com filtro BPF |
| GET | `/api/diff` | Diff entre dois scans |
| GET | `/api/report/<id>` | Relatório (`format=pdf\|html`) |
| GET | `/api/scans/<id>/export` *(analyst)* | Export STIX 2.1 / MISP |
| GET | `/api/scans/<id>/killchain` | Kill-chain por host |
| GET | `/api/scans/<id>/graph` | Grafo de fluxo |
| GET | `/api/scans/<id>/mitre-layer` | Layer JSON do ATT&CK Navigator |
| GET | `/api/scans/<id>/carved-files` *(viewer)* | Arquivos extraídos |
| GET | `/api/carved-files/<sha256>/download` *(admin)* | Baixar arquivo extraído |

### Alertas e Resposta
| Método | Endpoint | Descrição |
|--------|----------|-----------|
| GET | `/api/alerts` | Alertas de um scan com estado de triagem |
| POST | `/api/alerts/<id>/triage` *(analyst)* | Atualizar triagem (treina o classificador FP) |
| GET / POST / DELETE | `/api/suppression-rules[...]` | CRUD de regras de supressão |
| GET / DELETE | `/api/fp-signatures[...]` | Assinaturas de FP aprendidas |
| GET / POST / DELETE | `/api/webhooks[...]` · `/test` | CRUD de webhooks + teste de conectividade |

### Regras de Detecção — `/api/user-rules`
| Método | Endpoint | Descrição |
|--------|----------|-----------|
| GET | `/api/user-rules` *(analyst)* | Listar regras do usuário |
| PUT / DELETE | `/api/user-rules/<filename>` *(admin)* | Editar / excluir arquivo de regras |
| POST | `/api/user-rules/import` *(admin)* | Importar regras Suricata/Zeek |

### Administração e Configuração
| Método | Endpoint | Descrição |
|--------|----------|-----------|
| GET / POST | `/api/admin/api-keys[/<service>]` *(admin)* | Listar / salvar API keys |
| POST | `/api/admin/lookup` *(analyst)* | Lookup manual de IP/domínio |
| POST | `/api/admin/purge` *(admin)* | Purgar scans/partições por retenção |
| GET | `/api/admin/partitions` *(admin)* | Listar partições de alertas |
| GET | `/api/audit-log` *(analyst)* | Log de auditoria |
| GET / POST | `/api/settings` | Carregar/salvar configurações |
| GET / POST / DELETE | `/api/ip-names[...]` · `/export` · `/import` | CRUD de nomes de IP |
| GET | `/api/ip-evolution/<ip>` | Evolução do IP entre scans |
| GET | `/api/device-types` | Tipos de dispositivo válidos |
| POST / DELETE | `/api/trusted-range[...]` *(analyst)* | CRUD de ranges confiáveis |

### Usuários — `/api/users` *(admin)*
| Método | Endpoint | Descrição |
|--------|----------|-----------|
| GET / POST | `/api/users` | Listar / criar usuários |
| DELETE | `/api/users/<id>` | Excluir usuário |
| POST | `/api/users/<id>/role` · `/enabled` · `/password` | Alterar papel / habilitar / resetar senha |

---

## Comandos Úteis

### Docker — operação

```bash
docker compose up --build -d            # subir (rebuild)
docker compose ps                       # status dos serviços
docker compose logs -f web              # logs do app
docker compose logs -f celery_fast      # logs do worker de análise
docker compose down                     # parar (mantém dados)
docker compose down -v                  # parar + APAGAR volumes (reset total)
docker compose restart celery_slow      # reiniciar um serviço
```

### Frontend — após mudar `frontend/src/`

```bash
docker compose down
docker compose build web
docker compose up -d --force-recreate --renew-anon-volumes
# Verificar: deve retornar um <link> para /static/dist/assets/main-*.css
curl -s http://localhost:5000/ | grep stylesheet
```

> `--renew-anon-volumes` é necessário: sem ele o Compose reaproveita o bundle antigo do volume anônimo.

### Senhas e usuários

```bash
# Ver a senha inicial do admin
docker compose logs web | grep -A6 "Bootstrapping default admin"

# Resetar o banco e gerar nova senha admin
docker compose exec web python reset_db.py

# Resetar a senha do admin manualmente
docker compose exec -T web python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('NOVA_SENHA'))"
docker compose exec db psql -U pcap_user -d pcap_analyzer -c \
  "UPDATE users SET password_hash='<hash>', must_change_password=false WHERE username='admin';"
```

### Banco de dados

```bash
docker compose exec db psql -U pcap_user -d pcap_analyzer        # shell SQL
docker compose exec db pg_dump -U pcap_user pcap_analyzer > backup.sql   # backup
```

### Diagnóstico

```bash
docker compose exec web python -m py_compile app.py             # checar sintaxe
docker compose config -q                                        # validar compose
docker compose run --rm --user root --entrypoint "" web \
  chown -R 1000:1000 /app/data/uploads                          # corrigir dono do volume
```

---

## Atualizações

### O que precisa ser atualizado, e quando

| Item | Quando atualizar | Como |
|------|------------------|------|
| **Código da aplicação** | Após `git pull` ou editar `.py` | `docker compose up --build -d` (rebuild da imagem) |
| **Frontend (JS/CSS)** | Após editar `frontend/src/` | `docker compose build web` + `up -d --force-recreate --renew-anon-volumes` |
| **Dependências Python** | Após editar `requirements.txt` | `docker compose build` (camada `pip install` é refeita) |
| **Schema do banco** | Após mudança em `database.py` | Tabelas novas são criadas no import; mudanças destrutivas exigem `reset_db.py` ou migração manual |
| **Feeds de threat intel** | Automático | Cache em memória expira em 24 h; para forçar, reinicie os workers |
| **Regras YARA** | Ao adicionar `.yar` em `data/yara_rules/` | Recompiladas automaticamente (cache por mtime) |
| **Regras Suricata/Zeek** | Ao adicionar em `data/rules/` ou via UI | Carregadas automaticamente; `*.rules`/`*.sig` são reconhecidos |
| **Configurações** | A qualquer momento | Aba **Configurações** ou `POST /api/settings` (sem reiniciar) |
| **Imagens base (Postgres/Redis/Python/Node)** | Periodicamente, por segurança | `docker compose pull && docker compose up --build -d` |

### Procedimento padrão de atualização

```bash
git pull                                # trazer a nova versão
docker compose down                     # parar (volumes preservados)
docker compose build                    # reconstruir as imagens
docker compose up -d --force-recreate --renew-anon-volumes
docker compose logs -f web              # acompanhar o boot
```

Os volumes `postgres_data`, `app_data` e `uploads_data` **sobrevivem** ao `down`/`up` — scans, configurações, usuários e PCAPs são preservados. Use `down -v` **somente** para um reset completo.

### Tarefas periódicas automáticas

O serviço `celery_beat` executa sozinho:

- **Purga de retenção** — diariamente às 03:00 UTC, apaga scans e partições além de `retention_days`.
- **Partições de alertas** — cria a partição mensal da tabela `alerts` no 1º dia de cada mês.

### Migração após o endurecimento de segurança

O container passou a rodar como usuário não-root (uid 1000). Se você tinha um volume `uploads_data` antigo (criado quando o container rodava como root), ajuste o dono uma vez:

```bash
docker compose run --rm --user root --entrypoint "" web chown -R 1000:1000 /app/data/uploads
```

---

## Estrutura de Arquivos

```
pcap_analyzer/
├── Dockerfile / docker-compose.yml / docker-entrypoint.sh
├── .env.example                 # template de variáveis de ambiente
├── app.py                       # wiring do Flask (auth, audit, swagger, blueprints)
├── celery_app.py                # Celery: filas pcap.fast / pcap.slow + Beat
├── database.py                  # PostgreSQL (schema, partições, retenção)
├── reset_db.py                  # recria o schema + gera senha admin
├── auth.py                      # Flask-Login, RBAC, CSRF, bootstrap de admin
├── report_generator.py          # relatórios PDF (ReportLab) + HTML
├── threat_intel.py              # 16 fontes de threat intelligence
├── mitre_attack.py              # mapeamento alerta → técnica ATT&CK
├── behavioral.py                # baseline comportamental
├── correlation.py               # artefatos first-seen + kill-chain intra-scan
├── asset_inventory.py           # fingerprint passivo de hosts
├── host_roles.py                # inferência de papel + supressão por papel
├── host_risk.py                 # host risk score 0-100
├── flow_anomaly.py              # IsolationForest sobre fluxos
├── file_carving.py              # extração de arquivos de fluxos HTTP/SMB
├── hash_lookup.py               # VirusTotal + MalwareBazaar
├── yara_scan.py                 # varredura YARA dos artefatos
├── notifications.py             # Slack/Teams/webhook/Syslog/SMTP
├── stix_export.py               # export STIX 2.1 / MISP
├── suricata_import.py           # importador de regras Suricata/Zeek
├── user_rules.py                # regras de detecção definidas pelo usuário
├── pcap_analyzer/               # motor de análise (pacote)
│   ├── _core.py                 # orquestrador (parsing streaming + pipeline)
│   ├── constants.py             # portas, fingerprints, IOCs estáticos
│   ├── tls.py / ssh.py          # parsers TLS (JA3/JA4) e SSH (HASSH)
│   ├── pkt_view.py              # camadas + hex dump para o visualizador
│   ├── aggregators/             # agregadores de stats (IP, protocolo, TLS, SSH, HTTP)
│   └── detectors/
│       ├── __init__.py          # detectores streaming
│       └── post.py              # detectores de pós-processamento
├── routes/                      # blueprints da API REST
│   ├── auth.py users.py scans.py alerts.py rules.py
│   ├── admin.py config.py ui.py vite.py
│   └── common.py                # helpers e estado compartilhado
├── data/
│   ├── settings.json            # configurações (gitignored)
│   ├── settings.example.json    # template versionado
│   ├── uploads/                 # PCAPs enviados
│   ├── artifacts/               # arquivos extraídos (carving)
│   ├── rules/                   # regras Suricata/Zeek
│   └── yara_rules/              # regras YARA
├── templates/index.html         # shell da SPA
├── frontend/src/                # main.js, app.js, jquery-global.js, style.css
├── static/dist/                 # bundle gerado pelo Vite (gitignored)
├── package.json / vite.config.js
└── requirements.txt
```

---

## Banco de Dados

PostgreSQL 15. A tabela `alerts` é **particionada por mês** (`PARTITION BY RANGE`), com `alerts_default` para overflow.

| Tabela | Conteúdo |
|--------|----------|
| `scans` | Metadados + JSON completo do resultado |
| `ip_stats` / `protocol_stats` / `protocol_ip_stats` | Stats por IP / protocolo / protocolo×IP por scan |
| `alerts` *(particionada)* | Alertas detectados (+ partições mensais) |
| `users` | Usuários, hashes de senha, papéis |
| `audit_log` | Trilha de auditoria de operações mutantes |
| `ip_names` | Nomes/descrições/tipo de dispositivo personalizados |
| `ip_geolocation` / `ip_reputation` | Cache de geo / reputação (TTL 7 d) |
| `suppression_rules` / `fp_signatures` | Regras de supressão + assinaturas de FP aprendidas |
| `webhooks` | Webhooks de notificação configurados |
| `artifact_seen` | Artefatos first-seen (JA3/JA4/SNI/HTTP host/MAC...) |
| `assets` | Inventário passivo de hosts |
| `carved_files` | Arquivos extraídos + hashes + veredito |

Tabelas filhas usam `ON DELETE CASCADE`.

---

## Troubleshooting

### `docker compose up` falha logo no início
Quase sempre o `.env` não existe ou está incompleto. As variáveis `POSTGRES_PASSWORD`, `REDIS_PASSWORD` (e idealmente `FLASK_SECRET_KEY`) são obrigatórias. `cp .env.example .env` e preencha.

### A página carrega sem estilo (HTML cru)
Bundle do Vite ausente/desatualizado. Reconstrua:
```bash
docker compose down
docker compose build web
docker compose up -d --force-recreate --renew-anon-volumes
```

### Não consigo logar / não sei a senha do admin
```bash
docker compose logs web | grep -A6 "Bootstrapping default admin"
```
Se o log já rolou, resete a senha (veja [Comandos Úteis](#comandos-úteis)).

### Uploads falham com erro de permissão
O volume `uploads_data` é de um container antigo que rodava como root:
```bash
docker compose run --rm --user root --entrypoint "" web chown -R 1000:1000 /app/data/uploads
```

### Celery não processa tarefas
```bash
docker compose logs redis celery_fast celery_slow
```
Confira se `REDIS_PASSWORD` é a mesma no `.env` e nas URLs do broker.

### Feeds de threat intel vazias
Baixadas no momento do enriquecimento, com fallback gracioso (se uma feed falha, as demais seguem). Cache em memória é por processo — reinicie os workers para forçar reload. Fontes opcionais (OTX/MISP/TAXII/GreyNoise/VT) só rodam se a credencial estiver configurada.

### Porta 5000 em uso
Edite o mapeamento em `docker-compose.yml`: `ports: - "8080:5000"`.

### Resetar o banco
```bash
docker compose down -v && docker compose up --build -d
```

---

## Limitações Conhecidas

- O parsing é **streaming** (`PcapReader`), mas detectores agregam estado em memória — capturas extremas ainda podem pressionar a RAM. O worker `celery_fast` tem `mem_limit` de 6 GB para falhar de forma controlada.
- `max_packets` (padrão 5.000.000) limita o nº de pacotes processados por scan.
- Geolocalização limitada a **45 req/min** (ip-api.com gratuita); AbuseIPDB free: **1.000 consultas/dia**.
- Feeds externas dependem de conectividade.
- A UI ainda não tem aba dedicada para os arquivos extraídos (carving) — backend completo, exposto via API.
- Sirva sempre atrás de um proxy com TLS; sem isso, não exponha à internet.

---

## Licença

Fornecido "como está", sem garantias.

---

**Versão:** 5.0 · **Atualizado em:** 2026-05-20
