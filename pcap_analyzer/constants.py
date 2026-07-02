"""
Detection-related constants used by PCAPAnalyzer and its detectors.

These were previously class attributes on PCAPAnalyzer. They are kept here as
module-level constants so individual detectors can import them without pulling
in the whole analyzer. The PCAPAnalyzer class still exposes them as attributes
(via re-assignment in _core.py) so existing `self.SUSPICIOUS_PORTS`-style code
keeps working.
"""

# Portas suspeitas conhecidas
SUSPICIOUS_PORTS = {
    4444: ("Metasploit Default", "critical"),
    666: ("Doom Backdoor", "critical"),
    1337: ("Leet/Hacker Culture", "high"),
    6666: ("IRC Backdoor", "critical"),
    6667: ("IRC (pode ser C2)", "medium"),
    27374: ("SubSeven Trojan", "critical"),
    31337: ("Back Orifice", "critical"),
    65000: ("Várias Backdoors", "critical"),
    5555: ("Android ADB", "high"),
    9001: ("Tor Default", "medium"),
    1080: ("SOCKS Proxy", "medium"),
}

# Portas SMB
SMB_PORTS = {445, 139}

# Classificação de risco por protocolo
PROTOCOL_RISK = {
    # Baixo risco
    'DNS': ('low', None),
    'HTTPS': ('low', None),
    'TLS': ('low', None),
    'SSH': ('low', None),
    'ICMP': ('low', None),
    'NTP': ('low', None),
    'DHCP': ('low', None),

    # Médio risco
    'TCP': ('medium', None),
    'UDP': ('medium', None),
    'HTTP': ('medium', 'Unencrypted traffic - data can be intercepted'),
    'SMTP': ('medium', 'Verify TLS/STARTTLS usage'),
    'IPv6': ('medium', None),

    # Alto risco
    'FTP': ('high', 'Insecure protocol - credentials in plain text'),
    'Telnet': ('high', 'Extremely insecure protocol - avoid use'),
    'ARP': ('high', 'Monitor for spoofing attacks'),
    'SMB': ('high', 'Verify proper authentication and encryption'),
    'SMBv1': ('high', 'Obsolete version with known vulnerabilities'),
    'SNMP': ('high', 'Verify if using v3 with authentication'),
}

# TLDs frequentemente abusados (registro barato/gratuito ou histórico de abuso)
SUSPICIOUS_TLDS = {
    'top', 'xyz', 'tk', 'ml', 'ga', 'cf', 'pw', 'cc', 'club', 'loan',
    'work', 'win', 'date', 'racing', 'review', 'country', 'kim',
    'science', 'gq', 'men', 'bid', 'trade', 'party', 'stream',
    'download', 'mom', 'icu', 'cyou', 'monster', 'rest', 'quest',
    'cam', 'fit', 'buzz', 'sbs', 'lol'
}

# Resolvers DNS públicos conhecidos (uso direto pode bypassar DNS corporativo)
KNOWN_PUBLIC_DNS_RESOLVERS = {
    '1.1.1.1', '1.0.0.1', '1.1.1.2', '1.0.0.2',
    '8.8.8.8', '8.8.4.4',
    '9.9.9.9', '149.112.112.112',
    '208.67.222.222', '208.67.220.220',
    '94.140.14.14', '94.140.15.15',
    '76.76.19.19', '76.76.2.0',
    '64.6.64.6', '64.6.65.6',
    '4.2.2.1', '4.2.2.2',
}

# DoH (DNS-over-HTTPS, RFC 8484) — endpoints conhecidos.
# Casamos por SNI exato ou sufixo (.host). RFC 8484 reserva o template
# /dns-query, então também olhamos o path em HTTP cleartext (raro mas possível
# em DoH com proxy local). DoH é importante porque cega praticamente todas as
# detecções DNS (DGA/NXDOMAIN/TLD suspeitos) — o trade-off é privacidade vs.
# visibilidade defensiva.
DOH_HOSTS = {
    # Cloudflare
    'cloudflare-dns.com', 'mozilla.cloudflare-dns.com',
    'security.cloudflare-dns.com', 'family.cloudflare-dns.com',
    'one.one.one.one',
    # Google
    'dns.google', 'dns.google.com',
    # Quad9
    'dns.quad9.net', 'dns10.quad9.net', 'dns11.quad9.net',
    'dns12.quad9.net', 'dns9.quad9.net',
    # OpenDNS / Cisco
    'doh.opendns.com', 'doh.familyshield.opendns.com',
    # CleanBrowsing
    'doh.cleanbrowsing.org',
    # NextDNS
    'dns.nextdns.io',
    # AdGuard
    'dns.adguard.com', 'dns-family.adguard.com', 'dns-unfiltered.adguard.com',
    'dns.adguard-dns.com',
    # ControlD
    'dns.controld.com', 'freedns.controld.com',
    # Mullvad / DNS0
    'doh.mullvad.net', 'dns.mullvad.net', 'doh.dns0.eu', 'zero.dns0.eu',
    # LibreDNS / Switch / outros provedores comuns
    'doh.libredns.gr', 'dns.switch.ch', 'dns.digitale-gesellschaft.ch',
    'doh.pub', 'doh.360.cn', 'dns.alidns.com',
}

# IPs de servidores DoH conhecidos — usados quando o cliente envia ClientHello
# sem SNI (raro em browsers, comum em malware/proxy DoH custom). Mantém-se
# pequeno e focado: apenas IPs cuja assinatura primária é DoH/DoT, não IPs
# anycast genéricos do provedor (ex.: web/CDN da Cloudflare também responde
# em 1.1.1.1 mas está coberto por hostname).
DOH_PROVIDER_IPS = {
    # Cloudflare resolvers
    '1.1.1.1', '1.0.0.1', '1.1.1.2', '1.0.0.2', '1.1.1.3', '1.0.0.3',
    # Google Public DNS
    '8.8.8.8', '8.8.4.4',
    # Quad9
    '9.9.9.9', '9.9.9.10', '9.9.9.11', '149.112.112.112',
    '149.112.112.10', '149.112.112.11',
    # OpenDNS
    '208.67.222.222', '208.67.220.220', '208.67.222.123', '208.67.220.123',
    # AdGuard
    '94.140.14.14', '94.140.15.15', '94.140.14.140', '94.140.14.141',
    # NextDNS anycast
    '45.90.28.0', '45.90.30.0',
}

# JA3 conhecidos de clientes DoH (assinatura do TLS ClientHello). Vazio por
# default — JA3s de browsers mudam a cada versão e shippar IOCs de terceiros
# como verdade absoluta gera falso positivo. Extensível pelo operador via
# settings['known_doh_ja3'] = {'<md5>': '<label>'}. O caminho principal de
# detecção é SNI + IP do provedor.
KNOWN_DOH_JA3 = {}

# ---------------------------------------------------------------------------
# Cobalt Strike — malleable C2 default-profile signatures.
#
# O Team Server gera dois URIs especiais via checksum8: a soma dos caracteres
# do path (após o "/") módulo 256 deve dar 92 (0x5C, stager x86) ou 93 (0x5D,
# stager x64). Esses URIs são gerados aleatoriamente no boot do Team Server,
# então não dá para alertar pela string em si — só pelo checksum. Operadores
# podem sobrescrever em malleable profiles (set uri_x86/uri_x64), mas a
# maioria dos pentests/red-teams roda no default.
#
# Além do stager, perfis maleáveis "default", "amazon", "gmail", "jquery",
# "havex", "trick", "webbug" e variações vazadas usam URIs e cabeçalhos bem
# documentados. Detectar quaisquer deles em combinação com JA3 conhecido
# (já coberto por KNOWN_MALICIOUS_JA3) ou com beaconing co-localizado dá
# alta confiança.
#
# Referências: Cobalt Strike documentation (Malleable C2),
# Tek Defense/Sophos/Trend Micro writeups, MITRE ATT&CK S0154.
# ---------------------------------------------------------------------------

# Checksum-8 alvos do Team Server default. Histórico:
#   92 = stager x86 beacon
#   93 = stager x64 beacon
COBALT_STRIKE_CHECKSUMS = {92: 'x86 stager', 93: 'x64 stager'}

# URIs literais que aparecem em malleable profiles públicos/vazados. Marcador
# de baixa confiança individual (jquery URIs são triviais) mas combinado com
# outros sinais (UA, JA3, beaconing) eleva o alerta.
COBALT_STRIKE_DEFAULT_URIS = {
    '/ca', '/dpixel', '/__utm.gif', '/pixel.gif', '/ptj',
    '/submit.php', '/load', '/news.php', '/fwlink',
    '/ie9compatviewlist.xml',
    '/jquery-3.3.1.min.js', '/jquery-3.3.2.min.js',
    '/jquery-3.3.1.slim.min.js',
    # OCSP-like decoys
    '/cm', '/cx', '/activity',
    # Amazon profile
    '/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books',
    '/n/?ie=utf8&node=283155',
    # Gmail profile
    '/mail/u/0/',
}

# User-Agents default que aparecem em profiles vazados. Substring match —
# strings completas mudam por profile, mas estes tokens são marcadores.
COBALT_STRIKE_USER_AGENTS = (
    # Default IE 8/9 string que muitos profiles ainda usam
    'mozilla/4.0 (compatible; msie 8.0; windows nt 6.1; trident/4.0',
    'mozilla/5.0 (compatible; msie 9.0; windows nt 6.0; trident/4.0)',
    # Default profile do CS 3.x/4.x
    'mozilla/5.0 (windows nt 6.1; wow64; trident/7.0; rv:11.0) like gecko',
    # Profile "havex"
    'mozilla/4.0 (compatible; msie 6.0; windows nt 5.1; sv1; havij)',
)

# Cabeçalhos servidor → cliente. NanoHTTPD é o servidor HTTP embarcado do
# Team Server pre-4.0. Cookies/Headers extras aparecem em profiles default.
COBALT_STRIKE_SERVER_HEADERS = (
    'nanohttpd',  # Server: NanoHTTPD
)

# Substrings em cookies/cabeçalhos que aparecem em profiles default.
# JSESSIONID isolado é genérico (Tomcat/Java) — só conta se combinado com
# outro sinal. SESSID em GET com base64 longo é mais específico.
COBALT_STRIKE_COOKIE_HINTS = (
    'session=',  # default profile injects base64 metadata in Cookie: session=...
)

# Bigramas mais comuns em inglês (pontuação heurística para DGA)
ENGLISH_COMMON_BIGRAMS = {
    'th', 'he', 'in', 'er', 'an', 're', 'on', 'at', 'en', 'nd',
    'ti', 'es', 'or', 'te', 'of', 'ed', 'is', 'it', 'al', 'ar',
    'st', 'to', 'nt', 'ng', 'se', 'ha', 'as', 'ou', 'io', 'le',
    've', 'co', 'me', 'de', 'hi', 'ri', 'ro', 'ic', 'ne', 'ea',
    'ra', 'ce', 'li', 'ch', 'll', 'be', 'ma', 'si', 'om', 'ur',
    'ca', 'el', 'ta', 'la', 'na', 'ol', 'pe', 'us', 'do', 'ec',
    'ot', 'ut', 'sh', 'tr', 'wh', 'ad', 'ai', 'am', 'ay', 'ee',
    'fo', 'so', 'ts', 'wa', 'ge', 'po', 'ie', 'ns', 'rt', 'ly',
}

VOWELS = set('aeiou')

# English letter-bigram frequencies (normalized; sum ≈ 1.0). Source: Norvig's
# Mayzner-derived count over the Google n-gram corpus, top ~150 bigrams.
# Used by the DGA scorer to compute per-bigram average log-likelihood:
# random/algorithmic strings draw from the long tail of unlikely pairs and
# end up with much lower avg log-likelihood than real domain labels.
# Bigrams not in this table are treated as a smoothed epsilon (≈ 1e-5) so
# the log doesn't blow up on rare-but-real pairs (vowel-vowel, qX, jX, …).
ENGLISH_BIGRAM_FREQ = {
    'th': 0.0356, 'he': 0.0307, 'in': 0.0243, 'er': 0.0205, 'an': 0.0199,
    're': 0.0185, 'on': 0.0176, 'at': 0.0149, 'en': 0.0145, 'nd': 0.0135,
    'ti': 0.0134, 'es': 0.0134, 'or': 0.0128, 'te': 0.0120, 'of': 0.0117,
    'ed': 0.0117, 'is': 0.0113, 'it': 0.0112, 'al': 0.0109, 'ar': 0.0107,
    'st': 0.0105, 'to': 0.0105, 'nt': 0.0104, 'ng': 0.0095, 'se': 0.0093,
    'ha': 0.0093, 'as': 0.0087, 'ou': 0.0087, 'io': 0.0083, 'le': 0.0083,
    've': 0.0083, 'co': 0.0079, 'me': 0.0079, 'de': 0.0076, 'hi': 0.0076,
    'ri': 0.0073, 'ro': 0.0073, 'ic': 0.0070, 'ne': 0.0069, 'ea': 0.0069,
    'ra': 0.0069, 'ce': 0.0065, 'li': 0.0062, 'ch': 0.0060, 'll': 0.0058,
    'be': 0.0058, 'ma': 0.0057, 'si': 0.0055, 'om': 0.0055, 'ur': 0.0054,
    'ca': 0.0052, 'el': 0.0051, 'ta': 0.0051, 'la': 0.0050, 'na': 0.0049,
    'ol': 0.0048, 'pe': 0.0046, 'us': 0.0046, 'do': 0.0044, 'ec': 0.0043,
    'ot': 0.0043, 'ut': 0.0042, 'sh': 0.0041, 'tr': 0.0041, 'wh': 0.0040,
    'ad': 0.0038, 'ai': 0.0038, 'am': 0.0038, 'ay': 0.0038, 'ee': 0.0037,
    'fo': 0.0037, 'so': 0.0037, 'ts': 0.0036, 'wa': 0.0035, 'ge': 0.0035,
    'po': 0.0034, 'ie': 0.0034, 'ns': 0.0033, 'rt': 0.0033, 'ly': 0.0033,
    'id': 0.0032, 'no': 0.0030, 'mo': 0.0029, 'pl': 0.0028, 'lo': 0.0028,
    'ke': 0.0028, 'pr': 0.0028, 'su': 0.0027, 'os': 0.0027, 'ho': 0.0027,
    'pa': 0.0027, 'em': 0.0026, 'ev': 0.0026, 'ac': 0.0026, 'mi': 0.0026,
    'ny': 0.0025, 'ir': 0.0025, 'wi': 0.0025, 'sa': 0.0024, 'gh': 0.0024,
    'wo': 0.0023, 'ul': 0.0023, 'pi': 0.0023, 'rm': 0.0023, 'ge': 0.0023,
    'fi': 0.0022, 'ow': 0.0022, 'ig': 0.0022, 'br': 0.0021, 'fe': 0.0021,
    'av': 0.0020, 'mp': 0.0020, 'um': 0.0020, 'ld': 0.0020, 'sp': 0.0020,
    'gr': 0.0020, 'ap': 0.0020, 'ci': 0.0019, 'ts': 0.0019, 'rs': 0.0019,
    'ag': 0.0019, 'ab': 0.0018, 'eo': 0.0017, 'op': 0.0017, 'eb': 0.0016,
    'da': 0.0016, 'oo': 0.0015, 'pp': 0.0015, 'ff': 0.0015, 'rd': 0.0015,
    'bi': 0.0014, 'cl': 0.0014, 'bl': 0.0014, 'ig': 0.0014, 'iv': 0.0014,
    'fr': 0.0013, 'ck': 0.0013, 'au': 0.0013, 'ph': 0.0013, 'gi': 0.0012,
    'pt': 0.0012, 'rn': 0.0012, 'lu': 0.0011, 'rl': 0.0011, 'fa': 0.0011,
    'di': 0.0011, 'va': 0.0011, 'ka': 0.0010, 'sl': 0.0010, 'qu': 0.0010,
    'sm': 0.0010, 'wr': 0.0009, 'gu': 0.0009, 'ke': 0.0009, 'ix': 0.0008,
    'tw': 0.0008, 'cr': 0.0008, 'bo': 0.0008, 'mb': 0.0008, 'eu': 0.0007,
    'oc': 0.0007, 'ub': 0.0007, 'yt': 0.0007, 'sk': 0.0007, 'ye': 0.0007,
    'go': 0.0006, 'sw': 0.0006, 'eg': 0.0005, 'rk': 0.0005, 'hr': 0.0005,
    'oa': 0.0005, 'iz': 0.0005, 'ws': 0.0005,
}
# Smoothing weight for bigrams absent from the table — gives them a non-zero
# probability so log() does not diverge, while still scoring them as much
# less likely than common pairs. 1e-5 ≈ log10 of -5.
ENGLISH_BIGRAM_EPSILON = 1e-5

# Versões TLS/SSL conhecidas
TLS_VERSIONS = {
    0x0300: 'SSLv3',
    0x0301: 'TLS 1.0',
    0x0302: 'TLS 1.1',
    0x0303: 'TLS 1.2',
    0x0304: 'TLS 1.3',
}
OLD_TLS_VERSIONS = {0x0300, 0x0301, 0x0302}

# GREASE values (RFC 8701) — devem ser removidos do JA3
JA3_GREASE = frozenset({
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
})

# Subset inicial de JA3 maliciosos conhecidos (extensível via settings)
# Fontes: abuse.ch SSLBL, pesquisas públicas. Tunable.
KNOWN_MALICIOUS_JA3 = {
    'e7d705a3286e19ea42f587b344ee6865': 'Cobalt Strike (variant)',
    '72a589da586844d7f0818ce684948eea': 'TrickBot',
    '6734f37431670b3ab4292b8f60f29984': 'Tor',
    'b386946a5a44d1ddcc843bc75336dfce': 'Cobalt Strike',
    'a0e9f5d64349fb13191bc781f81f42e1': 'Cobalt Strike Beacon',
    'bd9637ecdcf5ad3354e802d2bb16ae0a': 'Sliver C2',
    '37f463bf4616ecd445d4a1937da06e19': 'Trickbot',
    '06d6817cd2cf90c61b4329a4cd3a01a4': 'Dridex',
}

# Métodos HTTP válidos (para parser)
HTTP_METHODS = (
    b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ', b'OPTIONS ',
    b'PATCH ', b'TRACE ', b'CONNECT ', b'PROPFIND ', b'PROPPATCH ',
    b'MKCOL ', b'COPY ', b'MOVE ', b'LOCK ', b'UNLOCK ',
)

# Substrings de User-Agent indicando scanners/ferramentas ofensivas
SCANNER_USER_AGENTS = (
    'sqlmap', 'nikto', 'nmap', 'masscan', 'gobuster', 'dirb', 'dirbuster',
    'wpscan', 'hydra', 'metasploit', 'nessus', 'acunetix',
    'arachni', 'havij', 'whatweb', 'wfuzz', 'feroxbuster', 'sqlninja',
    'zgrab', 'mj12bot', 'xspider', 'paros', 'w3af', 'nuclei',
)

# Caminhos altamente sensíveis (acesso = RCE/leak imediato)
EXPLOIT_PATHS_HIGH = (
    '/.env', '/.git/', '/.svn/', '/.aws/', '/.ssh/', '/.bash_history',
    '/shell.php', '/shell.jsp', '/cmd.jsp', '/c99.php', '/r57.php',
    '/wso.php', '/x.php',
    '/actuator/env', '/actuator/heapdump', '/actuator/jolokia',
    '/vendor/phpunit/phpunit/src/util/php/eval-stdin.php',
    '/wp-config.php', '/web.config', '/config.json', '/config.yaml',
    '/hnap1/', '/boaform/', '/setup.cgi', '/goform/',
    '/cgi-bin/.%2e/', '/cgi-bin/luci',
)

# Caminhos de reconnaissance / paineis administrativos
EXPLOIT_PATHS_MEDIUM = (
    '/wp-login.php', '/wp-admin/', '/phpmyadmin', '/administrator/',
    '/manager/html', '/console/', '/jenkins', '/api-docs', '/swagger',
    '/cgi-bin/', '/.htaccess', '/server-status', '/server-info',
    '/.ds_store', '/api/v1/console', '/solr/admin', '/struts2',
)

# Serviços de file-share / paste comumente usados para exfiltração
FILE_SHARE_HOSTS = (
    'pastebin.com', 'paste.ee', 'hastebin.com', 'rentry.co', 'pastes.io',
    'controlc.com', 'tempfiles.ninja', 'ix.io', 'dpaste.com',
    'transfer.sh', 'file.io', 'anonfiles.com', 'gofile.io',
    'mega.nz', 'mega.io', 'mediafire.com', 'wetransfer.com', 'we.tl',
    'bashupload.com', 'sendspace.com', 'zippyshare.com', 'krakenfiles.com',
    'cdn.discordapp.com', 'discord.com',
    'send.tresorit.com', 'firefox.com', 'send.firefox.com',
)

# Portas associadas a movimentação lateral em redes Windows/Linux
LATERAL_PORTS = {
    445: 'SMB', 139: 'NetBIOS-SSN',
    3389: 'RDP',
    5985: 'WinRM-HTTP', 5986: 'WinRM-HTTPS',
    22: 'SSH',
    135: 'RPC-Endpoint-Mapper',
    88: 'Kerberos',
}

# Padrões de injeção (matched case-insensitive contra URL+headers+body)
# (substring, severidade, rótulo)
INJECTION_PATTERNS = (
    ('${jndi:',          'critical', 'Log4Shell (CVE-2021-44228)'),
    ('${lower:',         'high',     'Log4Shell evasion variant'),
    ('union select',     'high',     'SQL Injection (UNION SELECT)'),
    ('union%20select',   'high',     'SQL Injection (URL-encoded)'),
    ("' or 1=1",         'high',     'SQL Injection (tautology)'),
    ("' or '1'='1",      'high',     'SQL Injection (tautology)'),
    ('xp_cmdshell',      'critical', 'SQL Injection (xp_cmdshell)'),
    ('sleep(',           'medium',   'SQL Injection (time-based)'),
    ('benchmark(',       'medium',   'SQL Injection (time-based)'),
    ('../../../',        'high',     'Path Traversal'),
    ('..%2f..%2f',       'high',     'Path Traversal (URL-encoded)'),
    ('..%252f',          'high',     'Path Traversal (double-encoded)'),
    ('/etc/passwd',      'high',     'LFI / Path Traversal'),
    ('/etc/shadow',      'critical', 'LFI targeting credentials'),
    ('<script>',         'high',     'XSS'),
    ('javascript:',      'medium',   'XSS'),
    ('onerror=',         'medium',   'XSS'),
    ('|nc -e',           'critical', 'Command Injection (reverse shell)'),
    (';cat ',            'high',     'Command Injection'),
    ('$(whoami)',        'high',     'Command Injection'),
    ('cmd=cat',          'high',     'Command Injection'),
    ('php://filter',     'high',     'PHP Wrapper / LFI'),
    ('php://input',      'high',     'PHP Wrapper / RCE'),
)

# ---------------------------------------------------------------------------
# Onda 5 — A.5 / A.6 / A.7: cobertura ampliada
# ---------------------------------------------------------------------------

# A.5 — Tunneling moderno

# TLS ClientHello extension type 0xfe0d = encrypted_client_hello (RFC 9180-based
# ECH draft). Quando presente, o ClientHello externo (outer) costuma ter SNI
# em branco ou SNI público "neutro" e o real fica encriptado — sinal moderno
# de cegueira deliberada para o defensor.
TLS_EXT_ECH = 0xfe0d

# DNS-over-QUIC (RFC 9250) — porta UDP 853. Tráfego é QUIC válido, mas se vai
# para resolver externo é DNS cego no perímetro.
DOQ_PORT = 853

# WireGuard handshake init: 148 bytes UDP, primeiro byte = 0x01 (message_type),
# bytes 1-3 zerados (reserved). Porta default = 51820 (mas frequentemente
# tunelado em portas arbitrárias para evasão). Mensagem é IMPL específica do
# WG: total length = 148, e o tipo nos primeiros 4 bytes é 0x01000000 (LE).
WIREGUARD_HANDSHAKE_INIT_LEN = 148
WIREGUARD_DEFAULT_PORT = 51820
WIREGUARD_PORTS_BENIGN = {51820}  # qualquer outra porta com WG init = não-padrão

# OpenVPN UDP: opcodes (high 5 bits do primeiro byte). 0x38 = P_CONTROL_HARD_RESET_CLIENT_V2.
# Porta default 1194. Sinalização não-padrão se sair desta porta.
OPENVPN_RESET_OPCODES = {0x38, 0x40, 0x70}  # client_v2 init, server_v2 init, key
OPENVPN_DEFAULT_PORT = 1194
OPENVPN_PORTS_BENIGN = {1194}

# IP-layer encapsulation protocol numbers (RFC 791). Alertar quando o destino
# é externo — uso legítimo (IPv6 transition, MPLS-over-GRE) existe mas é raro
# em redes corporativas modernas e quase sempre vale revisar.
IP_PROTO_TUNNELS = {
    4: 'IPIP',      # IP-in-IP
    41: 'IPv6/SIT', # 6in4 / SIT
    47: 'GRE',
    97: 'EtherIP',
    115: 'L2TP',
}

# A.6 — OT / ICS / IoT
# Presença de qualquer um destes protocolos numa rede corporativa "normal" é
# por si só notável; vindos do exterior, sempre criticamente.
ICS_PORTS = {
    102:   ('S7Comm',       'Siemens S7 (ISO-TSAP)'),
    502:   ('Modbus/TCP',   'Modbus TCP'),
    1883:  ('MQTT',         'MQTT (plaintext)'),
    8883:  ('MQTT-TLS',     'MQTT over TLS'),
    20000: ('DNP3',         'Distributed Network Protocol 3'),
    44818: ('EtherNet/IP',  'EtherNet/IP (Allen-Bradley / Rockwell)'),
    47808: ('BACnet',       'BACnet/IP (building automation)'),
}

# Modbus function codes que escrevem no dispositivo. Vindo de IP externo =
# crítico (controle remoto de PLC/RTU). Lista RFC-equivalente do livro.
MODBUS_WRITE_FUNCTION_CODES = {
    5:  'Write Single Coil',
    6:  'Write Single Register',
    15: 'Write Multiple Coils',
    16: 'Write Multiple Registers',
    22: 'Mask Write Register',
    23: 'Read/Write Multiple Registers',
}
MODBUS_READ_FUNCTION_CODES = {1, 2, 3, 4, 7, 11, 12, 17, 20, 24}

# A.7 — Operacional: superfície de DB exposta + DCERPC named pipes laterais

# Portas e assinaturas de handshake. Detectar a presença do handshake real
# (não só "porta aberta") evita FP de scans inocentes vs. autenticação genuína.
EXPOSED_DB_PORTS = {
    1433: ('MSSQL', 'Microsoft SQL Server (TDS)'),
    1434: ('MSSQL-UDP', 'Microsoft SQL Browser'),
    3306: ('MySQL', 'MySQL / MariaDB'),
    5432: ('PostgreSQL', 'PostgreSQL'),
    1521: ('Oracle', 'Oracle TNS'),
    27017: ('MongoDB', 'MongoDB Wire'),
    6379: ('Redis', 'Redis (often unauth)'),
    9200: ('Elasticsearch', 'Elasticsearch HTTP'),
    5984: ('CouchDB', 'CouchDB HTTP'),
    11211: ('Memcached', 'Memcached (no auth)'),
}

# DCERPC named-pipes clássicos de movimentação lateral. Detectados em
# SMB Tree-Connect / Create requests. Strings em ASCII com prefixo \PIPE\.
# Bytes: SMB1/SMB2 envia em UTF-16LE no Tree/Create — vamos checar ambas.
DCERPC_LATERAL_PIPES = {
    'svcctl':   'Service Control Manager (PsExec, SCM RCE)',
    'atsvc':    'Task Scheduler (schtasks, AT)',
    'winreg':   'Remote Registry',
    'samr':     'SAM Database (user/group enumeration)',
    'lsarpc':   'LSA RPC (policy, secrets)',
    'netlogon': 'NetLogon (Zerologon vector)',
    'wkssvc':   'Workstation Service',
    'srvsvc':   'Server Service (share enumeration)',
    'spoolss':  'Print Spooler (PrintNightmare, hijack)',
    'eventlog': 'Remote Event Log',
}

# DCERPC abstract-syntax (interface) UUIDs notórios por abuso. Detectados em
# bind/alter-context sobre ncacn_ip_tcp (TCP/135 + portas dinâmicas). O simples
# bind a estas interfaces já é acionável (coerção de auth, DCSync, exec remoto)
# — diferente do fan-out na 135, que só pega varredura ampla. UUID em minúsculo.
# (label, severity, technique_id, technique_name, tactic_id, tactic_name)
DCERPC_DANGEROUS_INTERFACES = {
    '12345678-1234-abcd-ef00-0123456789ab': (
        'MS-RPRN (Print Spooler — PrinterBug / PrintNightmare)', 'high',
        'T1187', 'Forced Authentication', 'TA0006', 'Credential Access'),
    '76f03f96-cdfd-44fc-a22c-64950a001209': (
        'MS-PAR (Print Async — PrinterBug variant)', 'high',
        'T1187', 'Forced Authentication', 'TA0006', 'Credential Access'),
    'c681d488-d850-11d0-8c52-00c04fd90f7e': (
        'MS-EFSR (EFS RPC — PetitPotam coercion)', 'high',
        'T1187', 'Forced Authentication', 'TA0006', 'Credential Access'),
    'df1941c5-fe89-4e79-bf10-463657acf44d': (
        'MS-EFSR (EFS lsarpc — PetitPotam coercion)', 'high',
        'T1187', 'Forced Authentication', 'TA0006', 'Credential Access'),
    'e3514235-4b06-11d1-ab04-00c04fc2dcd2': (
        'MS-DRSR (DRSUAPI — DCSync replication)', 'critical',
        'T1003.006', 'OS Credential Dumping: DCSync',
        'TA0006', 'Credential Access'),
    '367abb81-9844-35f1-ad32-98f038001003': (
        'MS-SCMR (svcctl — remote service execution)', 'high',
        'T1569.002', 'System Services: Service Execution',
        'TA0002', 'Execution'),
    '86d35949-83c9-4044-b424-db363231fd0c': (
        'MS-TSCH (Task Scheduler — remote task)', 'high',
        'T1053.005', 'Scheduled Task/Job: Scheduled Task',
        'TA0002', 'Execution'),
    '338cd001-2244-31f1-aaaa-900038001003': (
        'MS-RRP (Remote Registry)', 'medium',
        'T1112', 'Modify Registry', 'TA0005', 'Defense Evasion'),
    '12345778-1234-abcd-ef00-0123456789ac': (
        'MS-SAMR (SAM — account enumeration)', 'medium',
        'T1087.002', 'Account Discovery: Domain Account',
        'TA0007', 'Discovery'),
    '99fcfec4-5260-101b-bbcb-00aa0021347a': (
        'IOXIDResolver (DCOM IObjectExporter — coercion/lateral)', 'medium',
        'T1021.003', 'Remote Services: Distributed Component Object Model',
        'TA0008', 'Lateral Movement'),
}

# ---------------------------------------------------------------------------
# Onda 6 — B.4 / B.6 / B.7: acurácia
# ---------------------------------------------------------------------------

# B.4 — NMAP TCP SYN fingerprint.
# Default `nmap -sS` (SYN scan) emits SYN probes with window=1024 and a very
# minimal TCP options stack: MSS=1460, NOP, NOP, SACK_PERM (no Timestamp,
# no WScale). Real OS TCP stacks (Linux, Windows, macOS, iOS, Android) always
# include either Timestamp or WScale in their SYN options. Combined with the
# 1024-byte window, the absence of these two options is a strong nmap signal.
# OS-detection probes (`-O`) use other distinctive windows (1, 63, 4, 4, 16,
# 512, 3) — we list them for the fast-scan FP path.
NMAP_DEFAULT_WINDOWS = {1024}
NMAP_OS_DETECT_WINDOWS = {1, 63, 4, 16, 512, 3, 31337}
# Required option names (in any order) for the SYN probe to look nmap-like.
# Real stacks add at least one of: Timestamp ('Timestamp'), Wscale ('WScale').
NMAP_REQUIRED_OPTS = {'MSS', 'SAckOK'}
NMAP_DISQUALIFYING_OPTS = {'Timestamp', 'WScale'}

# Slow-scan duration bands. Used to label PortScanDetector output so analysts
# see "ultra-slow scan over 6 hours" instead of just "slow scan".
SCAN_DURATION_BAND_ULTRA_SLOW_SEC = 3600   # > 1h
SCAN_DURATION_BAND_SLOW_SEC = 300          # 5 min..1h

# B.6 — JA3S known-bad. Server-side fingerprint counterpart to
# KNOWN_MALICIOUS_JA3. Built-in entries are minimal because JA3S is much less
# stable than JA3 (server stacks change quickly) — operators extend via
# settings['known_malicious_ja3s'] = {'<md5>': '<label>'}.
KNOWN_MALICIOUS_JA3S = {
    # SSLBL has historically tracked these for Sliver / Cobalt-Strike-like
    # JARM-collided servers. Tunable.
    'ec74a5c51106f0419184d0dd08fb05bc': 'Cobalt Strike (default profile)',
    '15af977ce25de452b96affa2addb1036': 'Sliver C2 (legacy)',
}

# B.6 — ALPN vs port consistency.
# When TLS advertises HTTP/2 or HTTP/3 via ALPN on a port that's clearly not
# a web port, it is highly anomalous: legitimate services on 25/465/587/993
# do not negotiate h2; legitimate DoT/DoQ uses dot/doq ALPN, not h2/h3.
# Empty set = "no port restriction" (use sane defaults below).
ALPN_HTTP_TOKENS = {'h2', 'h3', 'http/1.1'}
ALPN_WEB_OK_PORTS = {80, 443, 8080, 8443, 4443, 8000, 8888, 3000, 5000, 9000}
# ALPN tokens whose port should clearly NOT be a normal web port. Pairs that
# look "wrong" trigger the inconsistency alert.
ALPN_INCONSISTENCY_PORTS = {
    25, 110, 143, 465, 587, 993, 995,   # mail
    53, 853,                              # DNS / DoT / DoQ
    22, 23, 21,                           # admin / file transfer
    1883, 8883,                           # MQTT
    3306, 5432, 1433, 1521, 27017, 6379,  # databases
}

# B.7 — Cobalt Strike DNS Beacon signatures.
# DNS Beacons exfiltrate via TXT/A/AAAA replies and inbound queries using
# distinctive subdomain prefixes: "post.<random>.<domain>", "api.<random>",
# "cs.<random>". Long base32-ish random labels under one of these prefixes
# is a strong CS DNS C2 signal.
COBALT_STRIKE_DNS_PREFIXES = ('post.', 'api.', 'cs.', 'www.', 'cdn.')
# Min subdomain label length to consider — guards against benign api.svc.
COBALT_STRIKE_DNS_LABEL_MIN_LEN = 20

# B.4 — GreyNoise RIOT classifications that we treat as "known benign".
# Used to downgrade scan alerts to informational when the source IP is a
# documented benign internet scanner (Shodan, Censys, etc).
GREYNOISE_BENIGN_CLASSIFICATIONS = {'benign'}

# Lightweight public-suffix handling for base-zone extraction.
# The DNS exfil/C2 detectors group queries by "registrable zone"; taking the
# last 2 labels breaks under compound ccTLD suffixes (x.evil.co.uk would
# aggregate under "co.uk", mixing unrelated domains and hiding the real
# attacker zone). A full Public Suffix List is a heavyweight dependency for
# an offline analyzer, so we ship a curated set of the common second-level
# public suffixes plus a generic rule in base_zone() below.
SECOND_LEVEL_PUBLIC_SUFFIXES = {
    # United Kingdom
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'net.uk', 'sch.uk', 'me.uk',
    'ltd.uk', 'plc.uk', 'nhs.uk',
    # Brazil
    'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br', 'mil.br', 'art.br',
    'adv.br', 'ind.br', 'inf.br', 'srv.br', 'eng.br', 'blog.br', 'eco.br',
    'emp.br', 'far.br', 'med.br', 'tv.br', 'etc.br', 'jus.br', 'leg.br',
    'mp.br', 'def.br',
    # Australia / New Zealand
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'asn.au', 'id.au',
    'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz',
    # Japan / Korea / China / Taiwan / Hong Kong / Singapore / India
    'co.jp', 'ne.jp', 'or.jp', 'go.jp', 'ac.jp', 'ad.jp', 'ed.jp', 'gr.jp',
    'co.kr', 'ne.kr', 'or.kr', 'go.kr', 'ac.kr', 're.kr', 'pe.kr',
    'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn',
    'com.tw', 'net.tw', 'org.tw', 'gov.tw', 'edu.tw', 'idv.tw',
    'com.hk', 'net.hk', 'org.hk', 'gov.hk', 'edu.hk', 'idv.hk',
    'com.sg', 'net.sg', 'org.sg', 'gov.sg', 'edu.sg', 'per.sg',
    'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in', 'res.in', 'firm.in',
    'gen.in', 'ind.in', 'nic.in', 'ernet.in',
    # Latin America
    'com.mx', 'net.mx', 'org.mx', 'gob.mx', 'edu.mx',
    'com.ar', 'net.ar', 'org.ar', 'gob.ar', 'edu.ar', 'int.ar', 'mil.ar',
    'com.co', 'net.co', 'org.co', 'gov.co', 'edu.co', 'mil.co', 'nom.co',
    'com.pe', 'net.pe', 'org.pe', 'gob.pe', 'edu.pe', 'nom.pe',
    'com.ve', 'net.ve', 'org.ve', 'gob.ve', 'edu.ve',
    'com.uy', 'net.uy', 'org.uy', 'gub.uy', 'edu.uy',
    'com.ec', 'net.ec', 'org.ec', 'gob.ec', 'edu.ec',
    'com.bo', 'net.bo', 'org.bo', 'gob.bo', 'edu.bo',
    'com.py', 'net.py', 'org.py', 'gov.py', 'edu.py',
    'com.do', 'com.gt', 'com.sv', 'com.ni', 'com.hn', 'com.pa', 'com.pr',
    # Europe (compound-suffix countries)
    'com.tr', 'net.tr', 'org.tr', 'gov.tr', 'edu.tr', 'gen.tr', 'web.tr',
    'com.pl', 'net.pl', 'org.pl', 'gov.pl', 'edu.pl', 'waw.pl',
    'com.pt', 'net.pt', 'org.pt', 'gov.pt', 'edu.pt', 'int.pt',
    'com.es', 'nom.es', 'org.es', 'gob.es', 'edu.es',
    'com.gr', 'net.gr', 'org.gr', 'gov.gr', 'edu.gr',
    'com.ro', 'org.ro', 'nt.ro',
    'com.ua', 'net.ua', 'org.ua', 'gov.ua', 'edu.ua', 'in.ua', 'kiev.ua',
    'com.ru', 'net.ru', 'org.ru', 'msk.ru', 'spb.ru',
    # Africa / Middle East
    'co.za', 'net.za', 'org.za', 'gov.za', 'ac.za', 'web.za',
    'com.ng', 'net.ng', 'org.ng', 'gov.ng', 'edu.ng',
    'com.eg', 'net.eg', 'org.eg', 'gov.eg', 'edu.eg',
    'co.il', 'net.il', 'org.il', 'gov.il', 'ac.il', 'muni.il',
    'com.sa', 'net.sa', 'org.sa', 'gov.sa', 'edu.sa', 'med.sa',
    'co.ke', 'or.ke', 'ne.ke', 'go.ke', 'ac.ke',
    'co.ma', 'net.ma', 'org.ma', 'gov.ma', 'ac.ma',
    'com.ae', 'net.ae', 'org.ae', 'gov.ae', 'ac.ae',
}
# Generic fallback rule: <short-functional-label>.<2-letter-ccTLD> is almost
# always a public suffix even when missing from the curated set above
# (e.g. gov.xx, edu.xx for a ccTLD we didn't enumerate).
_GENERIC_SLD_LABELS = frozenset({
    'com', 'net', 'org', 'gov', 'gob', 'gub', 'edu', 'mil',
    'ac', 'co', 'or', 'ne', 'go', 'sch',
})


def base_zone(parts):
    """Return the registrable base zone for a lowercased DNS label list.

    ['x', 'evil', 'co', 'uk']  -> 'evil.co.uk'
    ['x', 'evil', 'com']       -> 'evil.com'
    ['evil', 'com']            -> 'evil.com'
    """
    if len(parts) < 2:
        return '.'.join(parts)
    suffix2 = parts[-2] + '.' + parts[-1]
    is_compound = (
        suffix2 in SECOND_LEVEL_PUBLIC_SUFFIXES
        or (len(parts[-1]) == 2 and parts[-2] in _GENERIC_SLD_LABELS)
    )
    if is_compound and len(parts) >= 3:
        return '.'.join(parts[-3:])
    return suffix2

# --- Sanctioned bulk-transfer destinations (exfil false-positive guard) -----
# Volume/ratio exfil detectors fire on any large local->external upload. Cloud
# backup, OS/software updates, telemetry and video/conferencing legitimately
# move large volumes outbound and dominate real-world false positives. When an
# exfil alert's destination resolves (via TLS SNI or HTTP Host observed in the
# same capture) to one of these suffixes, the detector DOWNGRADES severity and
# annotates the alert — it does NOT suppress it, because attackers do abuse
# cloud services for exfil (so the analyst still sees it, de-prioritized).
#
# Deliberately EXCLUDES file-share / paste services (dropbox, mega, wetransfer,
# pastebin, ...) — those are the exfil channel of concern and are handled by
# FileShareUploadDetector; downgrading them here would hide the very thing we
# want surfaced.
SANCTIONED_BULK_DESTINATIONS = (
    # OS / software updates
    'windowsupdate.com', 'update.microsoft.com', 'delivery.mp.microsoft.com',
    'dl.delivery.mp.microsoft.com', 'swcdn.apple.com', 'swscan.apple.com',
    'mesu.apple.com', 'osxapps.itunes.apple.com', 'appldnld.apple.com',
    'archive.ubuntu.com', 'security.ubuntu.com', 'deb.debian.org',
    'download.windowsupdate.com', 'ftp.mozilla.org', 'download.mozilla.org',
    'dl.google.com', 'redirector.gvt1.com', 'update.googleapis.com',
    'clients2.google.com', 'edgedl.me.gvt1.com',
    # Major cloud infra / CDN edge (bulk content, not user file-share)
    'akamai.net', 'akamaiedge.net', 'akamaitechnologies.com',
    'cloudfront.net', 'fastly.net', 'fbcdn.net', 'azureedge.net',
    'azurefd.net', 'blob.core.windows.net', 'googleusercontent.com',
    'googlevideo.com', 'gvt1.com', 'gvt2.com', 'ytimg.com',
    's3.amazonaws.com', 'amazonaws.com', 'digitaloceanspaces.com',
    # Backup / endpoint protection (bulk outbound by design)
    'backblaze.com', 'backblazeb2.com', 'code42.com', 'crashplan.com',
    'druva.com', 'carbonite.com', 'acronis.com',
    # Video / conferencing (sustained outbound uploads are normal)
    'zoom.us', 'teams.microsoft.com', 'webex.com', 'whatsapp.net',
    'googlemeet.com', 'meet.google.com',
    # OS/vendor telemetry endpoints that push sizeable diagnostics
    'events.data.microsoft.com', 'settings-win.data.microsoft.com',
    'incoming.telemetry.mozilla.org',
)


def is_sanctioned_bulk_destination(hostnames):
    """True when any hostname matches (exact or suffix) a sanctioned bulk
    destination. `hostnames` is an iterable of lowercased host strings."""
    for h in hostnames or ():
        if not h:
            continue
        h = h.lower().strip().rstrip('.')
        for suffix in SANCTIONED_BULK_DESTINATIONS:
            if h == suffix or h.endswith('.' + suffix):
                return suffix
    return None


# --- JA4 / JA4S known-bad (client + server TLS fingerprints) ----------------
# JA4 (FoxIO) is the modern, more-stable successor to JA3. Built-in entries are
# intentionally minimal; operators extend via settings['known_malicious_ja4']
# and settings['known_malicious_ja4s'] = {'<fingerprint>': '<label>'}.
# JA4 client fingerprints look like 't13d1516h2_8daaf6152771_b186095e22b6'.
KNOWN_MALICIOUS_JA4 = {
    # Placeholder-curated from public C2 fingerprint research; tunable.
    't13d190900_9dc949149365_97f8aa674fd9': 'Cobalt Strike (default JA4)',
    't13d1715h2_5b57614c22b0_93c746dc1a19': 'Sliver C2 (default JA4)',
}
KNOWN_MALICIOUS_JA4S = {
    't130200_1301_a56c5b993250': 'Cobalt Strike (default JA4S)',
}
