import logging
from django.db.models.signals import post_delete, post_save, pre_delete, pre_save
from django.dispatch import receiver
from netaddr import IPNetwork

from ipam.models import IPAddress
from netbox_ddns.background_tasks import delete_rfc2317_delegation, dns_create, dns_delete
from netbox_ddns.models import DNSStatus, ExtraDNSName, ReverseZone
from netbox_ddns.utils import normalize_fqdn

logger = logging.getLogger('netbox_ddns')


@receiver(pre_save, sender=IPAddress)
def store_original_ipaddress(instance: IPAddress, **_kwargs):
    instance.before_save = IPAddress.objects.filter(pk=instance.pk).first()


@receiver(post_save, sender=IPAddress)
def trigger_ddns_update(instance: IPAddress, **_kwargs):
    old_address = instance.before_save.address.ip if instance.before_save else None
    old_dns_name = normalize_fqdn(instance.before_save.dns_name) if instance.before_save else ''

    new_address = IPNetwork(instance.address).ip
    new_dns_name = normalize_fqdn(instance.dns_name)

    extra_dns_names = {normalize_fqdn(extra.name): extra for extra in instance.extradnsname_set.all()}

    if new_address != old_address or new_dns_name != old_dns_name:
        status, created = DNSStatus.objects.get_or_create(ip_address=instance)

        if old_address and old_dns_name and old_dns_name not in extra_dns_names:
            delete = dns_delete.delay(
                dns_name=old_dns_name,
                address=old_address,
                status=status,
            )
        else:
            delete = None

        if new_address and new_dns_name:
            dns_create.delay(
                dns_name=new_dns_name,
                address=new_address,
                status=status,
                depends_on=delete,
            )

    if old_address != new_address:
        # This affects extra names
        for dns_name, status in extra_dns_names.items():
            # Don't touch the main dns_name
            if dns_name == old_dns_name or dns_name == new_dns_name:
                continue

            if old_dns_name:
                delete = dns_delete.delay(
                    dns_name=dns_name,
                    address=old_address,
                    reverse=False,
                    status=status,
                )
            else:
                delete = None

            if new_dns_name:
                dns_create.delay(
                    dns_name=dns_name,
                    address=new_address,
                    reverse=False,
                    status=status,
                    depends_on=delete,
                )


@receiver(post_delete, sender=IPAddress)
def trigger_ddns_delete(instance: IPAddress, **_kwargs):
    old_address = instance.address.ip
    old_dns_name = normalize_fqdn(instance.dns_name)

    if old_address and old_dns_name:
        dns_delete.delay(
            address=old_address,
            dns_name=old_dns_name,
        )


@receiver(pre_save, sender=ExtraDNSName)
def store_original_extra(instance: ExtraDNSName, **_kwargs):
    instance.before_save = ExtraDNSName.objects.filter(pk=instance.pk).first()


@receiver(post_save, sender=ExtraDNSName)
def trigger_extra_ddns_update(instance: ExtraDNSName, **_kwargs):
    address = instance.ip_address.address.ip
    old_dns_name = instance.before_save.name if instance.before_save else ''
    new_dns_name = instance.name

    if new_dns_name != old_dns_name:
        if old_dns_name:
            delete = dns_delete.delay(
                dns_name=old_dns_name,
                address=address,
                reverse=False,
                status=instance,
            )
        else:
            delete = None

        dns_create.delay(
            dns_name=new_dns_name,
            address=address,
            status=instance,
            reverse=False,
            depends_on=delete,
        )


@receiver(pre_delete, sender=ReverseZone)
def cleanup_rfc2317_delegation(instance: ReverseZone, **_kwargs):
    """Remove RFC 2317 CNAME records from parent zone when ReverseZone is deleted."""
    success = delete_rfc2317_delegation(instance)
    if not success:
        raise RuntimeError(
            f'Cannot delete reverse zone {instance}: failed to remove RFC 2317 '
            f'delegation from parent zone. Fix or remove the parent zone records manually.'
        )


@receiver(post_delete, sender=ExtraDNSName)
def trigger_extra_ddns_delete(instance: ExtraDNSName, **_kwargs):
    address = instance.ip_address.address.ip
    old_dns_name = instance.name

    if old_dns_name == normalize_fqdn(instance.ip_address.dns_name):
        return

    dns_delete.delay(
        dns_name=old_dns_name,
        address=address,
        reverse=False,
    )
