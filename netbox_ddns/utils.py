from dataclasses import dataclass
from typing import TYPE_CHECKING, List, Optional, Union

import dns.rdatatype
import dns.resolver

if TYPE_CHECKING:
    from ipam.models import IPAddress
    from netbox_ddns.models import ExtraDNSName, Zone


@dataclass
class ManagedDNSNameRow:
    """A DNS name managed by a DDNS zone (primary from IPAddress or extra from ExtraDNSName)."""
    dns_name: str
    ip_address: 'IPAddress'
    zone: 'Zone'
    is_primary: bool
    obj: Union['IPAddress', 'ExtraDNSName']
    view_url: str = ''
    edit_url: str = ''
    delete_url: Optional[str] = None
    forward_status_html: str = ''


def get_managed_dns_names(user) -> List[ManagedDNSNameRow]:
    """
    Return all DNS names managed by DDNS zones (primary + extra), restricted by user permissions.
    """
    from ipam.models import IPAddress  # noqa: F811
    from netbox_ddns.models import ExtraDNSName, Zone  # noqa: F401

    rows: List[ManagedDNSNameRow] = []

    from django.urls import reverse

    from dns import rcode

    from netbox_ddns.models import ACTION_CHOICES, DNSStatus, get_rcode_display

    for zone in Zone.objects.all().restrict(user, 'view'):
        # Primary names: IPAddress with dns_name in this zone
        ip_addresses = zone.get_managed_ip_address().restrict(user, 'view')
        for ip_address in ip_addresses:
            if ip_address.dns_name:
                try:
                    status = ip_address.dnsstatus
                    if status.forward_action is not None:
                        output = next(
                            label for value, label in ACTION_CHOICES if value == status.forward_action
                        )
                        output += ': '
                        output += get_rcode_display(status.forward_rcode) or ''
                        colour = 'green' if status.forward_rcode == rcode.NOERROR else 'red'
                        forward_status = (
                            f'<span style="color:{colour}">{output}</span>'
                        )
                    else:
                        forward_status = '<span class="text-muted">Not created</span>'
                except DNSStatus.DoesNotExist:
                    forward_status = '<span class="text-muted">Not created</span>'

                rows.append(ManagedDNSNameRow(
                    dns_name=ip_address.dns_name,
                    ip_address=ip_address,
                    zone=zone,
                    is_primary=True,
                    obj=ip_address,
                    view_url=ip_address.get_absolute_url(),
                    edit_url=reverse('ipam:ipaddress_edit', args=[ip_address.pk]),
                    delete_url=None,
                    forward_status_html=forward_status,
                ))

        # Extra names: ExtraDNSName in this zone
        extra_names = zone.get_managed_extra_dns_name().restrict(user, 'view')
        for extra in extra_names:
            if extra.forward_action is not None:
                forward_status = extra.get_forward_rcode_html_display() or ''
            else:
                forward_status = '<span class="text-muted">Not created</span>'

            rows.append(ManagedDNSNameRow(
                dns_name=extra.name,
                ip_address=extra.ip_address,
                zone=zone,
                is_primary=False,
                obj=extra,
                view_url=extra.get_absolute_url(),
                edit_url=reverse('plugins:netbox_ddns:extradnsname_edit', args=[extra.pk]),
                delete_url=reverse('plugins:netbox_ddns:extradnsname_delete', args=[extra.pk]),
                forward_status_html=forward_status,
            ))

    return sorted(rows, key=lambda r: r.dns_name.lower())


def normalize_fqdn(dns_name: str) -> str:
    if not dns_name:
        return ''

    return dns_name.lower().rstrip('.') + '.'


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
