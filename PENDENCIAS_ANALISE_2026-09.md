# Revisão de regras de alerta — setembro/2026

Objetivo: corrigir bugs, reduzir falsos positivos sem deixar de alertar o que é
problema de verdade. Princípio seguido: **rebaixar/anotar em vez de suprimir**.
Só são descartados casos em que o tráfego comprovadamente não pode ser ataque.
Exemplo: consulta DNS a uma zona que só o fornecedor responde.

Estado: **264 testes passando**. A e B concluídos; resta C. Nada foi commitado ainda.

- Os testes rodam via Docker, com um Postgres temporário. Veja a seção
  "Como rodar os testes" no fim deste arquivo.
- Para entrar em produção é preciso `docker compose build`, porque o código é
  copiado para dentro da imagem.

---

## FEITO nesta sessão

### Bugs corrigidos
- **Validade de certificado TLS usava a data de hoje.** Agora usa o timestamp
  do pacote. Quando o timestamp não é plausível (< 2000), cai para o relógio
  atual. Antes, PCAPs antigos geravam "certificado expirado" falso. O teste do
  fixture, que quebraria em 2026-08-31, foi refeito com carimbo de tempo fixo.
- **`_is_local_ip`** passou a tratar como não-externos: multicast, link-local,
  loopback, reservados e CGNAT 100.64/10.
  - Antes, SSDP/mDNS viravam "exfiltração lenta" com razão saída/entrada
    infinita.
  - Endereços multicast também iam para consulta de threat-intel.
- **Porta suspeita em porta efêmera** (4444, 65000, 1080...). O detector agora
  identifica quem realmente escuta a porta, pelo SYN ou SYN-ACK. Um cliente
  HTTPS que sorteava a porta de origem 65000 virava "backdoor crítico".
- **STARTTLS mascarava credenciais em claro.** O anúncio `250-STARTTLS` do
  servidor desligava o detector. Agora só conta o comando STARTTLS/STLS/AUTH TLS
  enviado pelo cliente.
- **Brute force com complexidade O(n²).** Clientes com milhares de conexões
  podiam travar a análise. Trocado por uma janela com dois ponteiros.
- **Bytes TCP zerados em SMB.** O scapy disseca SMB2 e o `Raw` some.
  - O `pkt_view` ganhou `plen`, o tamanho do payload calculado pelos
    cabeçalhos.
  - `TcpFlowTracker` e brute force passaram a usar esse campo.
- **JA4S embutido "Cobalt Strike" era genérico.** O hash `a56c5b993250` é
  sha256("002b,0033") e corresponde a boa parte de todos os servidores TLS 1.3.
  Foi removido.
- **JA4 "Sliver" colidia com o Firefox** nas partes a/b. Removido.
- **ARP host discovery e ping sweep** contavam requisições em vez de alvos
  distintos na janela. Corrigido.

### Regras recalibradas (FP ↓)
- **Port scan:** a avaliação agora é por par (origem, alvo). Cliente P2P, VoIP
  ou NAT falando com muitos peers não vira mais scan.
- **ARP spoofing:**
  - Vira `critical` só com evidência: flip-flop, reanúncio agressivo
    (≥5 em 60 s) ou o MAC novo continuar respondendo por outro IP.
  - Uma troca única gera um novo alerta, `ARP IP-to-MAC Change`: `medium`, ou
    `high` se o IP parecer gateway.
  - O flood de ARP gratuito agora é contado em janela.
- **DNS tunneling:**
  - Agregado por (origem, zona). A severidade cresce com o nº de nomes
    distintos: 1 → medium, 3 → high, 10 → critical.
  - Passa a enxergar payload dividido em vários labels.
  - Ignora zonas de reputação de AV/DNSBL.
- **DNS cumulative exfil:**
  - Ignora zonas de provedores e de reputação.
  - A severidade depende da fração de subdomínios com cara de payload
    codificado. Muitos hostnames legíveis ficam em `low`.
- **CS DNS beacon:** o label codificado precisa ficar abaixo da zona
  registrável e ter dígitos ou score DGA. Zonas de provedores são ignoradas.
- **DGA:** 1 domínio → medium, 2–4 → high, ≥5 → critical. Punycode (`xn--`) é
  ignorado.
- **Fast-flux:**
  - CDNs conhecidas são ignoradas.
  - Considera a diversidade de redes /16 dos IPs: IPs concentrados → `low`.
- **NXDOMAIN:**
  - Conta nomes distintos.
  - Ignora PTR, zonas locais e nomes de um só label.
  - Nomes legíveis → medium; nomes algorítmicos em volume → critical.
- **TLD suspeito:** 1–2 domínios → low, 3–4 → medium, ≥5 → high.
- **DoT:** para resolver público conhecido → `low`.
- **Beaconing (SYN):**
  - Menos de 10 conexões limita a severidade a medium; menos de 20, a high.
    Phase-lock com tamanho uniforme ainda libera critical.
  - Destino de plataforma conhecida (via SNI, Host ou DNS) desce 1 nível.
    Isso também vale para o beaconing dentro de uma conexão.
- **Brute force:**
  - Conexões sem nenhum dado são retry, não login: `low` se a origem é
    interna, `medium` se externa.
  - Volume grande ou variável em origem interna indica pool de aplicação:
    `low`.
  - Origem externa mantém a severidade original.
- **Password spraying:** em origem interna, sessões estabelecidas com muito
  volume indicam gerência/backup → medium; sem nenhum dado → medium. Origem
  externa mantém a severidade original.
- **Movimento lateral interno:** exclui servidores compartilhados, ou seja,
  alvos usados por ≥3 outros clientes (DCs, servidores de arquivo e de
  impressão).
- **SMB externo:**
  - Severidade conforme o estado da conexão.
  - Entrada: estabelecida → critical, SYN-ACK → high, sem resposta → medium.
  - Saída não estabelecida → medium.
- **Ping sweep:** padrão de monitoramento (≥4 pings por alvo, > 5 min) →
  `low`.
- **SNMP walk:** polling recorrente (≥3 rajadas) → `low`; origem externa →
  critical.
- **LLMNR/NBT-NS:** se o host só responde o próprio nome (≤2 nomes) → `low`.
  O `pkt_view` passou a extrair o nome respondido.
- **Túnel ICMP:** payload de preenchimento padrão de `ping` → `low`.
- **Entropia em porta cleartext:** só o sentido cliente→servidor. Se qualquer
  segmento abre com um verbo do protocolo, o fluxo é tratado como legítimo.
- **DB exposto:**
  - Ignora porta efêmera quando o outro lado é um serviço conhecido.
  - Severidade: RST ou silêncio → low; SYN-ACK → medium; handshake do banco →
    high.
- **Pipes DCERPC:**
  - Classificados em níveis: exec (svcctl, atsvc) → high; admin (winreg,
    eventlog) → medium; rotina (lsarpc, samr, netlogon, srvsvc, wkssvc,
    spoolss) → low.
  - Agravantes: origem externa → critical; exec em ≥3 hosts → critical;
    ≥5 hosts → high.
- **DCERPC bind:**
  - MS-DRSR entre dois DCs (hosts que respondem Kerberos) → low (replicação
    normal).
  - MS-RPRN/PAR para servidor de impressão com ≥3 clientes → low.
  - Origem externa → critical.
- **WireGuard na porta padrão:** `low`.
- **IP com vários MACs:**
  - MACs de roteador (MAC de origem de ≥4 IPs) não contam → `low`.
  - Dois MACs de dispositivo → medium (antes high).
  - IP externo → low.

### Infra nova
- `DnsResolutionAggregator`, com resolução IP → nomes a partir das respostas
  DNS. `_hostname_index` agora inclui esses nomes, então o rebaixamento de
  "destino sancionado" funciona também para QUIC/SMB. Existem agora 15
  agregadores.
- Constantes em `constants.py`: `DNS_REPUTATION_LOOKUP_ZONES`,
  `DNS_PROVIDER_OWNED_ZONES`, `KNOWN_BENIGN_SERVICE_SUFFIXES` e
  `hostname_suffix_match()`.
- Helpers em `detectors/__init__.py`: `_apply_known_service_downgrade()` e
  `_cap_severity()`.

---

## STATUS DO PLANO

### A. Pós-detectores — FEITO (sessão 2026-09-23)
- **OldTlsVersion:** o servidor confirmou → TLS 1.0/1.1 medium, SSLv3 high.
  Só o cliente ofereceu → low. Novo campo `server_confirmed`.
- **SuspiciousSni:** DGA ou ≥2 motivos → high. Só literal de IP ou SNI longo
  → medium. Só TLD → low. Sem SNI para destino externo → low.
- **TlsCertificate:** autoassinado externo → medium. Divergência SNI/CN na
  mesma zona registrável → medium; em zonas diferentes continua high. Novo
  campo `same_registrable_zone`.
- **KnownBadJa3:** JA3 + JA3S ruins no mesmo par → critical. JA3 sozinho →
  high. Destino de plataforma conhecida → low. Novo campo
  `ja3s_corroborated`.
- **ScannerUserAgent:** classificação por tipo de ferramenta.
  - Exploração ou scanner de vulnerabilidade → high.
  - Reconhecimento (nmap, zgrab, masscan, whatweb) vindo de fora → medium;
    de origem interna → high.
  - Crawler (mj12bot) → low.
- **ExploitPaths:**
  - `/config.json` e `/config.yaml` só casam na raiz.
  - Nomes de arquivo exigem limite de caminho (`/web.configuration` não casa;
    `wp-config.php.bak` casa).
  - Padrões medium de interno → externo → low.
- **HttpInjection e ExploitPayload:**
  - XSS só no path e nos headers.
  - Tráfego de saída desce 1 nível, exceto critical.
  - **Regex do ProxyShell corrigido:** exige `autodiscover.json?…@` ou
    autodiscover dentro de `Email=`.
  - **IMDS:** acesso direto a 169.254.169.254 ou metadata.google.internal
    não vira SSRF.
- **FileShareUpload:** `discord.com` e `firefox.com` foram removidos da
  lista. Sem POST/PUT → low.
- **ECH** → low. **DoH:** por SNI → low; `ip_no_sni` → medium; por JA3
  continua high.
- **QUIC para destino novo:** aplica `_apply_known_service_downgrade`
  (medium → low para plataforma conhecida).

### B. Testes novos — FEITO
- Criado `tests/test_fp_recalibration_streaming.py` com 38 testes. Cobre
  todos os itens da antiga lista B, sempre em pares benigno/malicioso.
- Os testes HTTP, TLS e JA3 existentes foram ajustados e ampliados:
  ProxyShell, IMDS, XSS no body, SPA `config.json` e file-share.
- **Bug achado pelos testes:** `_is_local_ip` não reconhecia CGNAT. Usava
  `getattr(ip, 'is_shared')`, atributo que não existe. Corrigido com
  `_CGNAT_NET` em `_core.py`.
- Total: **264 testes passando**.


### C. Outros
- `teste.txt` e `diagnose_suppression.py` estão soltos, fora do git. Decidir
  se versiona ou apaga.
- Há muitas mudanças de sessões anteriores ainda não commitadas (UI PT-BR,
  supressão, TOTP). Commitar em blocos separados.
- Rever a análise do lado web (routes, database). Nesta sessão o foco foi 100%
  nas regras de detecção.
- Depois de tudo: `docker compose build` e reprocessar um PCAP real para
  comparar a contagem de alertas por severidade, antes e depois.

---

## Como rodar os testes (Windows / Git Bash)
O host não tem scapy nem psycopg2. Os testes rodam na imagem `pcap_analyzer-web`
com pytest adicionado, mais um Postgres descartável:

```sh
# imagem de teste (uma vez)
printf 'FROM pcap_analyzer-web:latest\nRUN pip install -q pytest\n' | docker build -q -t pcap_analyzer-test -
docker network create pcaptest
docker run -d --rm --name pcaptest-db --network pcaptest \
  -e POSTGRES_USER=pcap_user -e POSTGRES_PASSWORD=pcap_pass -e POSTGRES_DB=pcap_analyzer postgres:15-alpine
# rodar
MSYS_NO_PATHCONV=1 docker run --rm --network pcaptest --entrypoint sh \
  -e DATABASE_URL=postgresql://pcap_user:pcap_pass@pcaptest-db:5432/pcap_analyzer \
  -v "$(pwd -W):/src:ro" pcap_analyzer-test \
  -c "cp -r /src /tmp/w && cd /tmp/w && python -m pytest -p no:cacheprovider -q"
```
