import logging
from typing import List, Optional

import dns.query
import dns.rdatatype
import dns.resolver
from django.db import IntegrityError
from django_rq import job
from dns import rcode
from netaddr import ip, IPNetwork

from netbox_ddns.models import ACTION_CREATE, ACTION_DELETE, DNSStatus, RCODE_NO_ZONE, ReverseZone, Zone
from netbox_ddns.utils import get_soa, check_servers_authoritative, get_ip

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


def create_forward(dns_name: str, address: ip.IPAddress, status: Optional[DNSStatus], output: List[str]):
    if status:
        status.forward_action = ACTION_CREATE

    zone = Zone.objects.find_for_dns_name(dns_name)
    if zone:
        logger.debug(f"Found zone {zone.name} for {dns_name}")

        # Check the SOA, we don't want to write to a parent zone if it has delegated authority
        soa = get_soa(zone.name)
        if soa == zone.name:
            record_type = 'A' if address.version == 4 else 'AAAA'
            update = zone.server.create_update(zone.name)
            update.add(
                dns_name,
                zone.ttl,
                record_type,
                str(address)
            )
            response = dns.query.udp(update, zone.server.address, port=zone.server.server_port)
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
        if soa == zone.name:
            record_type = 'A' if address.version == 4 else 'AAAA'
            update = zone.server.create_update(zone.name)
            update.delete(
                dns_name,
                record_type,
                str(address)
            )
            response = dns.query.udp(update, zone.server.address, port=zone.server.server_port)
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
        if soa == zone.name:
            update = zone.server.create_update(zone.name)
            update.add(
                record_name,
                zone.ttl,
                'ptr',
                dns_name
            )
            response = dns.query.udp(update, zone.server.address, port=zone.server.server_port)
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
        if soa == zone.name:
            update = zone.server.create_update(zone.name)
            update.delete(
                record_name,
                'ptr',
                dns_name
            )
            response = dns.query.udp(update, zone.server.address, port=zone.server.server_port)
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


# TODO: dns_create,dns_remove check if it is not delegated to another server
def create_reverse_delegation(nameservers: List[str], prefix: IPNetwork, status: Optional[DNSStatus], output: List[str]):
    if prefix.size > 24:
        output.append(f'Classless delegation is not implemented, prefix size too big: {prefix.cidr}')

    if status:
        status.reverse_action = ACTION_CREATE

    nameservers = {x: get_ip(x) for x in nameservers}

    subnets = prefix.subnet(24)
    while 1:
        subnet = next(subnets, None)
        if subnet is None:
            break

        zone = ReverseZone.objects.find_for_address(subnet.network)
        if zone:
            for nameserver, addresses in nameservers.items():
                # TODO: check authority
                nameserver = {nameserver: address}
                if check_servers_authoritative(zone.name, addresses):
                    pass
            update = zone.server.create_update(zone.name)
            for nameserver in nameservers.keys():
                update.add(
                    zone.name,
                    zone.ttl,
                    dns.rdatatype.NS,
                    nameserver
                )
