from dataclasses import dataclass
from typing import TYPE_CHECKING, List, Optional

import dns.rdatatype
import dns.resolver

if TYPE_CHECKING:
    from ipam.models import IPAddress
    from netbox_ddns.models import Zone


@dataclass
class ManagedDNSNameRow:
    """Primary DNS name from IPAddress, with optional zone."""
    dns_name: str
    ip_address: 'IPAddress'
    zone: Optional['Zone']
    obj: 'IPAddress'
    view_url: str = ''
    edit_url: str = ''
    delete_url: Optional[str] = None
    forward_status_html: str = ''


def _find_zone_for_dns_name(dns_name: str, zones_by_name: dict) -> Optional['Zone']:
    """In-memory zone lookup."""
    parts = dns_name.lower().rstrip('.').split('.')
    for i in range(len(parts)):
        candidate = '.'.join(parts[i:])
        for suffix in (candidate + '.', candidate):
            if suffix in zones_by_name:
                return zones_by_name[suffix]
    return None


def get_managed_dns_names(user) -> List[ManagedDNSNameRow]:
    """
    Return all primary DNS names (from IPAddress.dns_name), with or without a zone.
    Extra DNS names are shown in the separate Extra DNS Names view.
    """
    from django.urls import reverse

    from dns import rcode

    from ipam.models import IPAddress
    from netbox_ddns.models import ACTION_CHOICES, DNSStatus, Zone, get_rcode_display

    rows: List[ManagedDNSNameRow] = []
    no_zone_status = '<span class="text-muted">No zone configured</span>'

    zones = list(Zone.objects.all().restrict(user, 'view'))
    zones_by_name = {z.name: z for z in zones}
    for z in zones:
        n = z.name.rstrip('.')
        if n != z.name:
            zones_by_name[n] = z

    ip_addresses = (
        IPAddress.objects.filter(dns_name__isnull=False)
        .exclude(dns_name='')
        .restrict(user, 'view')
        .prefetch_related('dnsstatus')
        .order_by('dns_name')
    )

    for ip_address in ip_addresses:
        zone = _find_zone_for_dns_name(ip_address.dns_name, zones_by_name)
        if zone is None:
            forward_status = no_zone_status
        else:
            try:
                status = ip_address.dnsstatus
                if status.forward_action is not None:
                    output = next(
                        label for value, label in ACTION_CHOICES if value == status.forward_action
                    )
                    output += ': '
                    output += get_rcode_display(status.forward_rcode) or ''
                    colour = 'green' if status.forward_rcode == rcode.NOERROR else 'red'
                    forward_status = f'<span style="color:{colour}">{output}</span>'
                else:
                    forward_status = '<span class="text-muted">Not created</span>'
            except DNSStatus.DoesNotExist:
                forward_status = '<span class="text-muted">Not created</span>'

        rows.append(ManagedDNSNameRow(
            dns_name=ip_address.dns_name,
            ip_address=ip_address,
            zone=zone,
            obj=ip_address,
            view_url=ip_address.get_absolute_url(),
            edit_url=reverse('ipam:ipaddress_edit', args=[ip_address.pk]),
            delete_url=None,
            forward_status_html=forward_status,
        ))

    return rows


def normalize_fqdn(dns_name: str) -> str:
    if not dns_name:
        return ''

    return dns_name.lower().rstrip('.') + '.'


def nameserver_has_zone(zone_name: str, nameserver: str, port: int = 53) -> bool:
    """
    Check if the given nameserver is authoritative for the zone.
    Returns True if SOA query at the nameserver returns the zone.
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [nameserver]
        resolver.port = port
        zone_fqdn = normalize_fqdn(zone_name)
        answer = resolver.resolve(zone_fqdn, dns.rdatatype.SOA)
        return bool(answer)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, OSError):
        return False


def get_soa(dns_name: str) -> str:
    parts = dns_name.rstrip('.').split('.')
    for i in range(len(parts)):
        zone_name = normalize_fqdn('.'.join(parts[i:]))

        try:
            dns.resolver.query(zone_name, dns.rdatatype.SOA)
            return zone_name
        except dns.resolver.NoAnswer:
            # The name exists, but has no SOA. Continue one level further up
            continue
        except dns.resolver.NXDOMAIN as e:
            # Look for a SOA record in the authority section
            for query, response in e.responses().items():
                for rrset in response.authority:
                    if rrset.rdtype == dns.rdatatype.SOA:
                        return rrset.name.to_text()
