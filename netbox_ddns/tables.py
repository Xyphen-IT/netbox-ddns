import django_tables2 as tables
from django_tables2 import LinkColumn, RelatedLinkColumn

from netbox_ddns.models import ExtraDNSName, Server, ReverseZone, Zone

from netbox.tables import NetBoxTable

FORWARD_DNS = """
    {% if record.forward_action is not None %}
        {{ record.get_forward_action_display }}:
        {{ record.get_forward_rcode_html_display }}
    {% else %}
        <span class="text-muted">Not created</span>
    {% endif %}
"""


class ReverseZoneTable(NetBoxTable):
    name = LinkColumn()
    server = RelatedLinkColumn()

    class Meta(NetBoxTable.Meta):
        model = ReverseZone
        fields = ("id", "name", "prefix", "server", "ttl")


class ZoneTable(NetBoxTable):
    name = LinkColumn()
    server = RelatedLinkColumn()

    class Meta(NetBoxTable.Meta):
        model = Zone
        fields = ("id", "name", "server", "ttl")


class ServerTable(NetBoxTable):
    server = LinkColumn()

    class Meta(NetBoxTable.Meta):
        model = Server
        fields = ("id", "server", "server_port", "tsig_key_name", "tsig_algorithm")


class ExtraDNSNameTable(NetBoxTable):
    ip_address = RelatedLinkColumn()
    name = LinkColumn()
    forward_dns = tables.TemplateColumn(template_code=FORWARD_DNS)

    class Meta(NetBoxTable.Meta):
        model = ExtraDNSName
        fields = ('id', 'name', 'ip_address', 'last_update', 'forward_dns')
