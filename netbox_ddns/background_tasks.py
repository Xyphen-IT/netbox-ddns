import logging
from typing import List, Optional

import dns.query
import dns.rdatatype
import dns.resolver
from django.db import IntegrityError
from django_rq import job
from dns import rcode
from netaddr import ip

from netbox_ddns.models import ACTION_CREATE, ACTION_DELETE, DNSStatus, RCODE_NO_ZONE, ReverseZone, Zone, Protocol
from netbox_ddns.utils import get_soa

logger = logging.getLogger('netbox_ddns')


def status_update(output: List[str], operation: str, response) -> None:
    code = response.rcode()

    if code == dns.rcode.NOERROR:
        message = f"{operation} successful"
        logger.info(message)
    else:
        message = f"{operation} failed: {dns.rcode.to_text(code)}"
        logger.error(message)

    output.append(message)


def send_dns_update(update, server, protocol):
    """Send DNS update via TCP or UDP. Returns response or None on unknown protocol."""
    if protocol == Protocol.TCP:
        return dns.query.tcp(update, server.address, port=server.server_port)
    elif protocol == Protocol.UDP:
        return dns.query.udp(update, server.address, port=server.server_port)
    else:
        logger.error(f"Unknown protocol {protocol} for server {server}")
        return None


def create_forward(dns_name: str, address: ip.IPAddress, status: Optional[DNSStatus], output: List[str]):
    if status:
        status.forward_action = ACTION_CREATE

    zone = Zone.objects.find_for_dns_name(dns_name)
    if zone:
        logger.debug(f"Found zone {zone.name} for {dns_name}")

        # Check the SOA, we don't want to write to a parent zone if it has delegated authority
        soa = get_soa(zone.name)
        protocol = zone.server.protocol
        if soa == zone.name:
            record_type = 'A' if address.version == 4 else 'AAAA'
            update = zone.server.create_update(zone.name)
            update.add(
                dns_name,
                zone.ttl,
                record_type,
                str(address)
            )
            response = send_dns_update(update, zone.server, protocol)
            if response is None:
                return
            status_update(output, f'Adding {dns_name} {record_type} {address}', response)
            if status:
                status.forward_rcode = response.rcode()
        else:
            logger.warning(f"Can't update zone {zone.name} for {dns_name}, "
                           f"it has delegated authority for {soa}")
            if status:
                status.forward_rcode = rcode.NOTAUTH
    else:
        logger.debug(f"No zone found for {dns_name}")
        if status:
            status.forward_rcode = RCODE_NO_ZONE


def delete_forward(dns_name: str, address: ip.IPAddress, status: Optional[DNSStatus], output: List[str]):
    if status:
        status.forward_action = ACTION_DELETE

    zone = Zone.objects.find_for_dns_name(dns_name)
    if zone:
        logger.debug(f"Found zone {zone.name} for {dns_name}")

        # Check the SOA, we don't want to write to a parent zone if it has delegated authority
        soa = get_soa(zone.name)
        protocol = zone.server.protocol
        if soa == zone.name:
            record_type = 'A' if address.version == 4 else 'AAAA'
            update = zone.server.create_update(zone.name)
            update.delete(
                dns_name,
                record_type,
                str(address)
            )
            response = send_dns_update(update, zone.server, protocol)
            if response is None:
                return
            status_update(output, f'Deleting {dns_name} {record_type} {address}', response)
            if status:
                status.forward_rcode = response.rcode()
        else:
            logger.warning(f"Can't update zone {zone.name} {dns_name}, "
                           f"it has delegated authority for {soa}")
            if status:
                status.forward_rcode = rcode.NOTAUTH
    else:
        logger.debug(f"No zone found for {dns_name}")
        if status:
            status.forward_rcode = RCODE_NO_ZONE


def create_reverse(dns_name: str, address: ip.IPAddress, status: Optional[DNSStatus], output: List[str]):
    if status:
        status.reverse_action = ACTION_CREATE

    zone = ReverseZone.objects.find_for_address(address)
    if zone:
        record_name = zone.record_name(address)
        logger.debug(f"Found zone {zone.name} for {record_name}")

        # Check the SOA, we don't want to write to a parent zone if it has delegated authority
        soa = get_soa(record_name)
        protocol = zone.server.protocol
        if soa == zone.name:
            update = zone.server.create_update(zone.name)
            update.add(
                record_name,
                zone.ttl,
                'ptr',
                dns_name
            )
            response = send_dns_update(update, zone.server, protocol)
            if response is None:
                return
            status_update(output, f'Adding {record_name} PTR {dns_name}', response)
            if status:
                status.reverse_rcode = response.rcode()
        else:
            logger.warning(f"Can't update zone {zone.name} for {record_name}, "
                           f"it has delegated authority for {soa}")
            if status:
                status.reverse_rcode = rcode.NOTAUTH
    else:
        logger.debug(f"No zone found for {address}")
        if status:
            status.reverse_rcode = RCODE_NO_ZONE


def delete_reverse(dns_name: str, address: ip.IPAddress, status: Optional[DNSStatus], output: List[str]):
    if status:
        status.reverse_action = ACTION_DELETE

    zone = ReverseZone.objects.find_for_address(address)
    if zone:
        record_name = zone.record_name(address)
        logger.debug(f"Found zone {zone.name} for {record_name}")

        # Check the SOA, we don't want to write to a parent zone if it has delegated authority
        soa = get_soa(record_name)
        protocol = zone.server.protocol
        if soa == zone.name:
            update = zone.server.create_update(zone.name)
            update.delete(
                record_name,
                'ptr',
                dns_name
            )
            response = send_dns_update(update, zone.server, protocol)
            if response is None:
                return
            status_update(output, f'Deleting {record_name} PTR {dns_name}', response)
            if status:
                status.reverse_rcode = response.rcode()
        else:
            logger.warning(f"Can't update zone {zone.name} for {record_name}, "
                           f"it has delegated authority for {soa}")
            if status:
                status.reverse_rcode = rcode.NOTAUTH
    else:
        logger.debug(f"No zone found for {address}")
        if status:
            status.reverse_rcode = RCODE_NO_ZONE


@job
def dns_create(dns_name: str, address: ip.IPAddress, forward=True, reverse=True, status: DNSStatus = None):
    output = []

    if forward:
        create_forward(dns_name, address, status, output)
    if reverse:
        create_reverse(dns_name, address, status, output)

    if status:
        try:
            status.save()
        except IntegrityError:
            # Race condition when creating?
            status.save(force_update=True)

    return ', '.join(output)


@job
def create_rfc2317_delegation(reverse_zone_pk: int) -> str:
    """
    Create RFC 2317 CNAME records in the parent zone to delegate to the given child ReverseZone.
    Validates that the target nameserver (child zone's server) has the zone before delegating.
    """
    from netbox_ddns.models import Protocol, ReverseZone
    from netbox_ddns.utils import nameserver_has_zone, normalize_fqdn

    reverse_zone = ReverseZone.objects.get(pk=reverse_zone_pk)
    records = reverse_zone.get_rfc2317_delegation_cnames()
    if not records:
        return 'No RFC 2317 delegation needed (no parent, IPv6, or prefix on octet boundary)'

    parent = reverse_zone.get_parent()

    target_address = reverse_zone.server.address
    if not target_address:
        raise ValueError(
            f'Cannot delegate: could not resolve target nameserver {reverse_zone.server.server}'
        )
    if not nameserver_has_zone(
        reverse_zone.name,
        target_address,
        reverse_zone.server.server_port,
    ):
        raise ValueError(
            f'Cannot delegate: target nameserver {reverse_zone.server.server} '
            f'does not have zone {reverse_zone.name} (NXDOMAIN)'
        )

    output = []
    protocol = parent.server.protocol
    update = parent.server.create_update(parent.name)

    for name_in_parent, target in records:
        name_fqdn = normalize_fqdn(name_in_parent)
        target_fqdn = normalize_fqdn(target)
        update.add(name_fqdn, reverse_zone.ttl, 'CNAME', target_fqdn)

    response = send_dns_update(update, parent.server, protocol)
    if response is None:
        raise ValueError('Failed to send RFC 2317 delegation update')
    status_update(output, f'RFC 2317 delegation ({len(records)} CNAMEs)', response)
    return ', '.join(output)


def delete_rfc2317_delegation(reverse_zone) -> bool:
    """
    Remove RFC 2317 CNAME records from the parent zone.
    Returns True if cleanup was attempted (and succeeded or had nothing to do), False on failure.
    """
    from netbox_ddns.utils import normalize_fqdn

    records = reverse_zone.get_rfc2317_delegation_cnames()
    if not records:
        return True

    parent = reverse_zone.get_parent()
    if not parent or not parent.server.address:
        return True

    protocol = parent.server.protocol
    update = parent.server.create_update(parent.name)

    for name_in_parent, _target in records:
        name_fqdn = normalize_fqdn(name_in_parent)
        update.delete(name_fqdn, 'CNAME')

    response = send_dns_update(update, parent.server, protocol)
    return response is not None and response.rcode() == dns.rcode.NOERROR


@job
def dns_delete(dns_name: str, address: ip.IPAddress, forward=True, reverse=True, status: DNSStatus = None):
    output = []

    if forward:
        delete_forward(dns_name, address, status, output)
    if reverse:
        delete_reverse(dns_name, address, status, output)

    if status:
        try:
            status.save()
        except IntegrityError:
            # Race condition when creating?
            status.save(force_update=True)

    return ', '.join(output)
