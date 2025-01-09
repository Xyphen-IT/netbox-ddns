from rest_framework import serializers
from rest_framework.relations import PrimaryKeyRelatedField
from ipam.models import IPAddress
from netbox.api.serializers import NetBoxModelSerializer
from ..models import ExtraDNSName, Server, Zone, ReverseZone


class ExtraDNSNameSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(
        view_name='plugins-api:netbox_ddns-api:extradnsname-detail'
    )
    ip_address = PrimaryKeyRelatedField(queryset=IPAddress.objects.all())

    class Meta:
        model = ExtraDNSName
        fields = ('id', 'ip_address', 'name', 'url')
        read_only_fields = ('id', 'url')


class ServerSerializer(NetBoxModelSerializer):
    class Meta:
        model = Server
        fields = ('server', 'server_port', 'tsig_key_name', 'tsig_algorithm', "tsig_key")


class ZoneSerializer(NetBoxModelSerializer):
    class Meta:
        model = Zone
        fields = ('name', 'ttl', 'server')


class ReverseZoneSerializer(NetBoxModelSerializer):
    class Meta:
        model = ReverseZone
        fields = ('name', 'prefix', 'ttl', 'server')
