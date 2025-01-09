import dns.tsigkeyring
import dns.update
import logging
import socket
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q
from django.db.models.functions import Length
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _
from django.urls import reverse
from dns import rcode
from dns.tsig import HMAC_MD5, HMAC_SHA1, HMAC_SHA224, HMAC_SHA256, HMAC_SHA384, HMAC_SHA512
from netaddr import IPNetwork, ip
from typing import Optional
from netbox.models import NetBoxModel
from ipam.fields import IPNetworkField
from ipam.models import IPAddress
from utilities.querysets import RestrictedQuerySet
from .utils import normalize_fqdn
from .validators import HostnameAddressValidator, HostnameValidator, validate_base64, MinValueValidator, \
    MaxValueValidator

logger = logging.getLogger('netbox_ddns')

TSIG_ALGORITHM_CHOICES = (
    (str(HMAC_MD5), 'HMAC MD5'),
    (str(HMAC_SHA1), 'HMAC SHA1'),
    (str(HMAC_SHA224), 'HMAC SHA224'),
    (str(HMAC_SHA256), 'HMAC SHA256'),
    (str(HMAC_SHA384), 'HMAC SHA384'),
    (str(HMAC_SHA512), 'HMAC SHA512'),
)

ACTION_CREATE = 1
ACTION_DELETE = 2

ACTION_CHOICES = (
    (ACTION_CREATE, 'Create'),
    (ACTION_DELETE, 'Delete'),
)

# Use a private rcode for internal errors
RCODE_NO_ZONE = 4095


def get_rcode_display(code):
    if code is None:
        return None
    elif code == rcode.NOERROR:
        return _('Success')
    elif code == rcode.SERVFAIL:
        return _('Server failure')
    elif code == rcode.NXDOMAIN:
        return _('Name does not exist')
    elif code == rcode.NOTIMP:
        return _('Not implemented')
    elif code == rcode.REFUSED:
        return _('Refused')
    elif code == rcode.NOTAUTH:
        return _('Server not authoritative')
    elif code == RCODE_NO_ZONE:
        return _('No zone configured')
    else:
        return _('Unknown response: {}').format(code)


class Server(NetBoxModel):
    server = models.CharField(
        verbose_name=_('DDNS Server'),
        max_length=255,
        validators=[HostnameAddressValidator()],
    )
    server_port = models.PositiveIntegerField(
        verbose_name=_('Server Port'),
        default=53,
        validators=[
            MinValueValidator(53),
            MaxValueValidator(65535),
        ]
    )
    tsig_key_name = models.CharField(
        verbose_name=_('TSIG Key Name'),
        max_length=255,
        validators=[HostnameValidator()],
    )
    tsig_algorithm = models.CharField(
        verbose_name=_('TSIG Algorithm'),
        max_length=32,  # Longest is 24 chars for historic reasons, new ones are shorter, so 32 is more than enough
        choices=TSIG_ALGORITHM_CHOICES,
    )
    tsig_key = models.CharField(
        verbose_name=_('TSIG Key'),
        max_length=512,
        validators=[validate_base64],
        help_text=_('in base64 notation'),
    )

    class Meta:
        unique_together = (
            ('server', 'tsig_key_name'),
        )
        ordering = ('server', 'tsig_key_name')
        verbose_name = _('dynamic DNS Server')
        verbose_name_plural = _('dynamic DNS Servers')

    def __str__(self):
        return f'{self.server} ({self.tsig_key_name})'

    def clean(self):
        # Remove trailing dots from the server name/address
        self.server = self.server.lower().rstrip('.')

        # Ensure trailing dots from domain-style fields
        self.tsig_key_name = normalize_fqdn(self.tsig_key_name.lower().rstrip('.'))

    def get_absolute_url(self):
        return reverse('plugins:netbox_ddns:server', args=[self.pk])

    @property
    def address(self) -> Optional[str]:
        return socket.gethostbyname(self.server)

    def create_update(self, zone: str) -> dns.update.Update:
        return dns.update.Update(
            zone=normalize_fqdn(zone),
            keyring=dns.tsigkeyring.from_text({
                self.tsig_key_name: self.tsig_key
            }),
            keyname=self.tsig_key_name,
            keyalgorithm=self.tsig_algorithm
        )


class ZoneQuerySet(RestrictedQuerySet):
    def find_for_dns_name(self, dns_name: str) -> Optional['Zone']:
        # Generate all possible zones
        zones = []
        parts = dns_name.lower().split('.')
        for i in range(len(parts)):
            zones.append('.'.join(parts[-i - 1:]))

        # Find the zone, if any
        return self.filter(name__in=zones).order_by(Length('name').desc()).first()


class Zone(NetBoxModel):
    name = models.CharField(
        verbose_name=_('zone name'),
        max_length=255,
        validators=[HostnameValidator()],
        unique=True,
    )
    ttl = models.PositiveIntegerField(
        verbose_name=_('TTL'),
    )
    server = models.ForeignKey(
        to=Server,
        verbose_name=_('DDNS Server'),
        on_delete=models.PROTECT,
    )

    objects = ZoneQuerySet.as_manager()

    class Meta:
        ordering = ('name',)
        verbose_name = _('forward zone')
        verbose_name_plural = _('forward zones')

    def __str__(self):
        return self.name

    def get_managed_ip_address(self):
        # Find all more-specific zones
        more_specifics = Zone.objects.filter(name__endswith=self.name).exclude(pk=self.pk)

        # Find all IPAddress objects in this self but not in the more-specifics
        ip_addresses = IPAddress.objects.filter(Q(dns_name__endswith=self.name) |
                                                Q(dns_name__endswith=self.name.rstrip('.')))
        for more_specific in more_specifics:
            ip_addresses = ip_addresses.exclude(Q(dns_name__endswith=more_specific.name) |
                                                Q(dns_name__endswith=more_specific.name.rstrip('.')))
        return ip_addresses

    def get_managed_extra_dns_name(self):
        # Find all more-specific zones
        more_specifics = Zone.objects.filter(name__endswith=self.name).exclude(pk=self.pk)

        # Find all ExtraDNSName objects in this zone but not in the more-specifics
        extra_names = ExtraDNSName.objects.filter(name__endswith=self.name)
        for more_specific in more_specifics:
            extra_names = extra_names.exclude(name__endswith=more_specific.name)
        return extra_names

    def clean(self):
        # Ensure trailing dots from domain-style fields
        self.name = normalize_fqdn(self.name)

    def get_updater(self):
        return self.server.create_update(self.name)

    def get_absolute_url(self):
        return reverse('plugins:netbox_ddns:zone', args=[self.pk])


class ReverseZoneQuerySet(RestrictedQuerySet):
    def find_for_address(self, address: ip.IPAddress) -> Optional['ReverseZone']:
        # Find the zone, if any
        zones = list(ReverseZone.objects.filter(prefix__net_contains=address))
        if not zones:
            return None

        zones.sort(key=lambda zone: zone.prefix.prefixlen)
        return zones[-1]


class ReverseZone(NetBoxModel):
    prefix = IPNetworkField(
        verbose_name=_('prefix'),
        unique=True,
    )
    name = models.CharField(
        verbose_name=_('reverse zone name'),
        max_length=255,
        blank=True,
        help_text=_("RFC 2317 style reverse DNS, required when the prefix doesn't map to a reverse zone"),
    )
    ttl = models.PositiveIntegerField(
        verbose_name=_('TTL'),
    )
    server = models.ForeignKey(
        to=Server,
        verbose_name=_('DDNS Server'),
        on_delete=models.PROTECT,
    )

    objects = ReverseZoneQuerySet.as_manager()

    class Meta:
        ordering = ('prefix',)
        verbose_name = _('reverse zone')
        verbose_name_plural = _('reverse zones')

    def __str__(self):
        return f'{self.prefix}'

    def get_managed_ip_address(self):
        # Find all more-specific zones
        more_specifics = ReverseZone.objects.filter(prefix__net_contained=self.prefix).exclude(pk=self.pk)
        # Find all IPAddress objects in this zone but not in the more-specifics
        ip_addresses = IPAddress.objects.filter(address__net_contained_or_equal=self.prefix)
        for more_specific in more_specifics:
            ip_addresses = ip_addresses.exclude(address__net_contained_or_equal=more_specific.prefix)
        return ip_addresses

    def get_absolute_url(self):
        return reverse('plugins:netbox_ddns:reversezone', args=[self.pk])

    def record_name(self, address: ip.IPAddress):
        record_name = self.name
        if IPNetwork(self.prefix).version == 4:
            for pos, octet in enumerate(address.words):
                if (pos + 1) * 8 <= self.prefix.prefixlen:
                    continue

                record_name = f'{octet}.{record_name}'
        else:
            nibbles = f'{address.value:032x}'
            for pos, nibble in enumerate(nibbles):
                if (pos + 1) * 4 <= self.prefix.prefixlen:
                    continue

                record_name = f'{nibble}.{record_name}'

        return record_name

    def clean(self):
        if isinstance(self.prefix, IPNetwork) and self.prefix.version == 4:
            if self.prefix.prefixlen not in [0, 8, 16, 24] and not self.name:
                raise ValidationError({
                    'name': _('Required when prefix length is not 0, 8, 16 or 24'),
                })
            elif not self.name:
                # Generate it for the user
                self.name = 'in-addr.arpa'
                for pos, octet in enumerate(self.prefix.ip.words):
                    if pos * 8 >= self.prefix.prefixlen:
                        break

                    self.name = f'{octet}.{self.name}'

        elif isinstance(self.prefix, IPNetwork) and self.prefix.version == 6:
            if self.prefix.prefixlen % 4 != 0 and not self.name:
                raise ValidationError({
                    'name': _('Required when prefix length is not a nibble boundary'),
                })
            elif not self.name:
                # Generate it for the user
                self.name = 'ip6.arpa'
                nibbles = f'{self.prefix.ip.value:032x}'
                for pos, nibble in enumerate(nibbles):
                    if pos * 4 >= self.prefix.prefixlen:
                        break

                    self.name = f'{nibble}.{self.name}'

        # Ensure trailing dots from domain-style fields
        self.name = normalize_fqdn(self.name)


class DNSStatus(models.Model):
    ip_address = models.OneToOneField(
        to=IPAddress,
        verbose_name=_('IP address'),
        on_delete=models.CASCADE,
    )

    last_update = models.DateTimeField(
        verbose_name=_('last update'),
        auto_now=True,
    )

    forward_action = models.PositiveSmallIntegerField(
        verbose_name=_('forward record action'),
        choices=ACTION_CHOICES,
        blank=True,
        null=True,
    )
    forward_rcode = models.PositiveIntegerField(
        verbose_name=_('forward record response'),
        blank=True,
        null=True,
    )

    reverse_action = models.PositiveSmallIntegerField(
        verbose_name=_('reverse record action'),
        choices=ACTION_CHOICES,
        blank=True,
        null=True,
    )
    reverse_rcode = models.PositiveIntegerField(
        verbose_name=_('reverse record response'),
        blank=True,
        null=True,
    )

    class Meta:
        verbose_name = _('DNS status')
        verbose_name_plural = _('DNS status')

    def get_forward_rcode_display(self) -> Optional[str]:
        return get_rcode_display(self.forward_rcode)

    def get_forward_rcode_html_display(self) -> Optional[str]:
        output = get_rcode_display(self.forward_rcode)
        colour = 'green' if self.forward_rcode == rcode.NOERROR else 'red'
        return format_html('<span style="color:{colour}">{output}</span', colour=colour, output=output)

    def get_reverse_rcode_display(self) -> Optional[str]:
        return get_rcode_display(self.reverse_rcode)

    def get_reverse_rcode_html_display(self) -> Optional[str]:
        output = get_rcode_display(self.reverse_rcode)
        colour = 'green' if self.reverse_rcode == rcode.NOERROR else 'red'
        return format_html('<span style="color:{colour}">{output}</span', colour=colour, output=output)


class ExtraDNSName(NetBoxModel):
    ip_address = models.ForeignKey(
        to=IPAddress,
        verbose_name=_('IP address'),
        on_delete=models.CASCADE,
    )
    name = models.CharField(
        verbose_name=_('DNS name'),
        max_length=255,
        validators=[HostnameValidator()],
    )

    last_update = models.DateTimeField(
        verbose_name=_('last update'),
        auto_now=True,
    )

    forward_action = models.PositiveSmallIntegerField(
        verbose_name=_('forward record action'),
        choices=ACTION_CHOICES,
        blank=True,
        null=True,
    )
    forward_rcode = models.PositiveIntegerField(
        verbose_name=_('forward record response'),
        blank=True,
        null=True,
    )

    before_save = None

    class Meta:
        unique_together = (
            ('ip_address', 'name'),
        )
        verbose_name = _('extra DNS name')
        verbose_name_plural = _('extra DNS names')

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse('plugins:netbox_ddns:extradnsname', args=[self.pk])

    def clean(self):
        # Ensure trailing dots from domain-style fields
        self.name = normalize_fqdn(self.name)

    def get_forward_rcode_display(self) -> Optional[str]:
        return get_rcode_display(self.forward_rcode)

    def get_forward_rcode_html_display(self) -> Optional[str]:
        output = get_rcode_display(self.forward_rcode)
        colour = 'green' if self.forward_rcode == rcode.NOERROR else 'red'
        return format_html('<span style="color:{colour}">{output}</span', colour=colour, output=output)
