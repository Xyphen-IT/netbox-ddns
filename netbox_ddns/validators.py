import base64
import binascii

from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator, URLValidator, MinValueValidator, MaxValueValidator
from django.utils.translation import gettext_lazy as _


class HostnameValidator(RegexValidator):
    regex = r'^(' + URLValidator.hostname_re + r'((' + URLValidator.domain_re + URLValidator.tld_re + r')|\.?))$'
    message = _('Enter a valid hostname.')


class HostnameAddressValidator(RegexValidator):
    regex = '^(' + HostnameValidator.regex + '|' + URLValidator.ipv6_re + '|' + URLValidator.ipv4_re + '|' + URLValidator.host_re + ')$'
    message = _('Enter a valid hostname or IP address.')


def validate_base64(value):
    try:
        base64.b64decode(value, validate=True)
    except binascii.Error:
        raise ValidationError('Invalid base64 string')

class DNSNameValidator(RegexValidator):
    regex = r"^([0-9A-Za-z_-]+|\*)(\.[0-9A-Za-z_-]+)*\.?$"
    message = _(
        "Only alphanumeric characters, asterisks, hyphens, periods, and underscores are allowed in DNS names"
    )
