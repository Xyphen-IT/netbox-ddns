from netbox.api.viewsets import NetBoxModelViewSet
from ..filtersets import ExtraDNSNameFilterSet, ServerFilterSet, ZoneFilterSet
from ..models import ExtraDNSName, Server, Zone
from .serializers import ExtraDNSNameSerializer, ServerSerializer, ZoneSerializer


class ExtraDNSNameViewSet(NetBoxModelViewSet):
    queryset = ExtraDNSName.objects.select_related("ip_address").all()
    serializer_class = ExtraDNSNameSerializer
    filterset_class = ExtraDNSNameFilterSet


class ZoneViewSet(NetBoxModelViewSet):
    queryset = Zone.objects.select_related("server").all()
    serializer_class = ZoneSerializer
    filterset_class = ZoneFilterSet


class ServerViewSet(NetBoxModelViewSet):
    queryset = Server.objects.all()
    serializer_class = ServerSerializer
    filterset_class = ServerFilterSet
