"""
host_roles.py — inferência leve do papel funcional de cada host, e
suppression de alertas que são esperados para esse papel.

Motivação (B.10 do roadmap): um servidor DNS legítimo dispara queries em
volume; um Domain Controller responde Kerberos amplo; uma impressora faz
broadcast LLMNR/NBT-NS o tempo todo. Sem contexto, esses comportamentos
geram falsos positivos previsíveis que sufocam triagem.

A função infere papéis a partir do que já está em `results` (protocolos
agregados, assets DHCP) — não precisa de novo agregador nem de pacotes.
Cada alerta cuja origem é um host do papel correto é REBAIXADO (não
removido), com `suppressed_reason` registrando a justificativa para o
analista poder reativar.

Roles inferidos:
    dns_resolver  — local IP com tráfego DNS a >= 5 peers distintos.
    mail_server   — local IP com tráfego SMTP/SMTPS a >= 5 peers.
    printer       — asset cujo vendor-class ou hostname bate prefixos
                    conhecidos de impressora; mapeado para os IPs do MAC.
"""

from __future__ import annotations
from collections import defaultdict


SEV_RANK = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
RANK_SEV = {v: k for k, v in SEV_RANK.items()}


def _downgrade(severity, steps=1):
    """Drop severity `steps` tiers (critical→high→medium→low→info)."""
    rank = max(0, SEV_RANK.get(severity, 1) - steps)
    return RANK_SEV.get(rank, 'low')


_PRINTER_VENDOR_HINTS = (
    'hp ', 'hewlett', 'lexmark', 'canon', 'epson', 'brother',
    'xerox', 'kyocera', 'ricoh', 'samsung electronics', 'oki ',
    'zebra', 'sharp',
)
_PRINTER_HOSTNAME_HINTS = (
    'print', 'mfp', 'plotter', 'scanjet', 'officejet', 'laserjet',
    'phaser', 'workforce',
)


def _is_printer(asset):
    vendor = (asset.get('dhcp_vendor') or '').lower()
    if any(v in vendor for v in _PRINTER_VENDOR_HINTS):
        return True
    host = (asset.get('dhcp_hostname') or '').lower()
    if any(h in host for h in _PRINTER_HOSTNAME_HINTS):
        return True
    return False


def infer_host_roles(results):
    """Return {ip: set(role)} for local IPs whose role we can infer.

    Defaults to empty dict when results carry no protocol breakdown — the
    suppression step then becomes a no-op."""
    roles = defaultdict(set)
    ip_protocols = results.get('ip_protocols') or []

    for entry in ip_protocols:
        if not entry.get('is_local'):
            continue
        ip = entry.get('ip')
        if not ip:
            continue
        for proto in entry.get('protocols') or []:
            name = proto.get('name')
            peers = proto.get('peers') or []
            distinct = len({p.get('ip') for p in peers if p.get('ip')})
            if name == 'DNS' and distinct >= 5:
                roles[ip].add('dns_resolver')
            elif name in ('SMTP', 'SMTPS') and distinct >= 5:
                roles[ip].add('mail_server')
            elif name == 'SMB' and distinct >= 10:
                # Pode ser file server ou DC. Sem porta 88 individualizada
                # aqui, conservadoramente rotulamos só como file_server e
                # deixamos o resto para o detector dedicado.
                roles[ip].add('file_server')

    # Impressoras via DHCP vendor / hostname.
    assets = results.get('assets') or {}
    for _mac, asset in assets.items():
        if not _is_printer(asset):
            continue
        for ip in asset.get('ip_addresses') or []:
            roles[ip].add('printer')

    return dict(roles)


# ---------------------------------------------------------
# Suppression rules
# ---------------------------------------------------------
# Cada regra: predicado sobre (alert, roles_of_ip) → (downgrade_steps, reason)
# ou None se a regra não aplica. Roles avaliados sobre alert['ip'] (origem).
#
# Conservador: jamais suprimimos alerta critical para abaixo de medium,
# nunca abaixo de low. Drop-to-info reservado para sinais notoriamente
# barulhentos (LLMNR de impressora).

def _rule_dns_resolver(alert, roles):
    if 'dns_resolver' not in roles:
        return None
    title = (alert.get('title') or '')
    # Resolvers fazem MUITAS queries; NXDOMAIN spike e suspicious TLD são
    # esperados em proporção a tráfego.
    if title.startswith('NXDOMAIN Spike Detected'):
        return (2, 'dns_resolver: NXDOMAIN spike é esperado em resolver')
    if title.startswith('Queries to Suspicious TLD'):
        return (1, 'dns_resolver: TLDs suspeitos refletem clients, não o resolver')
    if title.startswith('Possible DGA Domain Activity'):
        return (1, 'dns_resolver: queries DGA refletem clients downstream')
    if title.startswith('Fast-Flux Domain Suspected'):
        return (1, 'dns_resolver: respostas fast-flux são repassadas, não originadas')
    # First-seen external destinations: resolvers naturalmente atingem
    # zonas autoritativas novas. Não para o detector cumulative-exfil,
    # esse é payload-level e pode indicar resolver comprometido.
    if title.startswith('First-Seen External Destination'):
        return (1, 'dns_resolver: contato com zona autoritativa nova é rotineiro')
    return None


def _rule_mail_server(alert, roles):
    if 'mail_server' not in roles:
        return None
    title = (alert.get('title') or '')
    if title.startswith('First-Seen External Destination'):
        return (1, 'mail_server: contato com novo MX externo é rotineiro')
    if title.startswith('New Protocol on Known Host'):
        proto = (alert.get('details') or {}).get('protocol', '')
        if proto in ('SMTP', 'SMTPS', 'IMAPS', 'POP3S'):
            return (1, 'mail_server: protocolo mail esperado neste host')
    return None


def _rule_printer(alert, roles):
    if 'printer' not in roles:
        return None
    title = (alert.get('title') or '')
    if title.startswith('LLMNR/NBT-NS Response Activity'):
        # Impressoras notoriamente broadcastam LLMNR/NBT-NS em resposta
        # a discovery — sinal quase 100% FP em ambiente com printer.
        return (2, 'printer: LLMNR/NBT-NS broadcast é comportamento padrão')
    if title.startswith('New Internal Host Active on Network'):
        # Impressora "nova" rejoining após DHCP renew não é incidente.
        return (1, 'printer: re-aparição após DHCP é rotineira')
    return None


_RULES = (_rule_dns_resolver, _rule_mail_server, _rule_printer)


def apply_role_suppression(results, roles=None):
    """Mutate results['alerts'] downgrading severity by inferred role.

    Adiciona `suppressed_reason` ao alerta tocado e armazena a severity
    original em `severity_original` para que a UI possa explicar."""
    alerts = results.get('alerts') or []
    if not alerts:
        return results
    if roles is None:
        roles = infer_host_roles(results)
    if not roles:
        return results

    suppressed_count = 0
    for alert in alerts:
        ip = alert.get('ip')
        if not ip:
            continue
        ip_roles = roles.get(ip)
        if not ip_roles:
            continue
        for rule in _RULES:
            result = rule(alert, ip_roles)
            if result is None:
                continue
            steps, reason = result
            original = alert.get('severity', 'medium')
            new_sev = _downgrade(original, steps)
            # Nunca rebaixa abaixo da severity já presente (segurança contra
            # múltiplas regras aplicando em cascata).
            if SEV_RANK.get(new_sev, 0) >= SEV_RANK.get(original, 0):
                continue
            alert.setdefault('severity_original', original)
            alert['severity'] = new_sev
            existing_reason = alert.get('suppressed_reason')
            if existing_reason:
                alert['suppressed_reason'] = existing_reason + '; ' + reason
            else:
                alert['suppressed_reason'] = reason
            suppressed_count += 1
            break  # uma regra por alerta evita cascata

    if suppressed_count:
        meta = results.setdefault('_meta', {})
        meta['role_suppression'] = {
            'alerts_downgraded': suppressed_count,
            'roles': {ip: sorted(r) for ip, r in roles.items()},
        }
    return results


__all__ = ['infer_host_roles', 'apply_role_suppression']
