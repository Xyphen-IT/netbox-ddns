import django_tables2 as tables
from django_tables2 import LinkColumn, RelatedLinkColumn

from netbox_ddns.models import ExtraDNSName, Server, ReverseZone, Zone

from netbox.tables import NetBoxTable

MANAGED_DNS_ACTIONS = """
<a href="{{ record.view_url }}" class="btn btn-sm btn-outline-primary" title="View">
    <i class="mdi mdi-eye"></i>
</a>
<a href="{{ record.edit_url }}" class="btn btn-sm btn-outline-warning" title="Edit">
    <i class="mdi mdi-pencil"></i>
</a>
{% if record.delete_url %}
<a href="{{ record.delete_url }}" class="btn btn-sm btn-outline-danger" title="Delete">
    <i class="mdi mdi-delete"></i>
</a>
{% endif %}
"""

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
        fields = ("id", "server", "server_port", "protocol", "tsig_key_name", "tsig_algorithm")


class ExtraDNSNameTable(NetBoxTable):
    ip_address = RelatedLinkColumn()
    name = LinkColumn()
    forward_dns = tables.TemplateColumn(template_code=FORWARD_DNS)

    class Meta(NetBoxTable.Meta):
        model = ExtraDNSName
        fields = ('id', 'name', 'ip_address', 'last_update', 'forward_dns')


class ManagedDNSNameTable(tables.Table):
    """Table for the unified Managed DNS Names list view (primary + extra)."""
    dns_name = tables.Column(
        accessor='dns_name',
        linkify=lambda record: record.view_url,
    )
    ip_address = tables.Column(
        accessor='ip_address',
        linkify=lambda record: record.ip_address.get_absolute_url(),
    )
    zone = tables.Column(
        accessor='zone',
        linkify=lambda record: record.zone.get_absolute_url(),
    )
    record_type = tables.Column(
        accessor='is_primary',
        verbose_name='Type',
        default='',
    )
    forward_status = tables.TemplateColumn(
        template_code='{{ record.forward_status_html|safe }}',
        verbose_name='Forward DNS',
    )
    actions = tables.TemplateColumn(
        template_code=MANAGED_DNS_ACTIONS,
        verbose_name='Actions',
        orderable=False,
    )

    def render_record_type(self, value):
        return 'Primary' if value else 'Extra'

    class Meta:
        attrs = {'class': 'table table-hover object-list'}
