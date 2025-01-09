from django.urls import path, include

from utilities.urls import get_model_urls
from .views import ExtraDNSNameCreateView, IPAddressDNSNameRecreateView, \
     UpdateForwardZone, UpdateReverseZone

urlpatterns = [

    path('extra-dns-names/', include(get_model_urls('netbox_ddns', 'extradnsname', detail=False))),
    path('extra-dns-names/<int:pk>/', include(get_model_urls('netbox_ddns', 'extradnsname'))),

    path('reverse-zones/', include(get_model_urls('netbox_ddns', 'reversezone', detail=False))),
    path('reverse-zones/<int:pk>/', include(get_model_urls('netbox_ddns', 'reversezone'))),

    path('zones/', include(get_model_urls('netbox_ddns', 'zone', detail=False))),
    path('zones/<int:pk>/', include(get_model_urls('netbox_ddns', 'zone'))),

    path('servers/', include(get_model_urls('netbox_ddns', 'server', detail=False))),
    path('servers/<int:pk>/', include(get_model_urls('netbox_ddns', 'server'))),

    path(route='zones/<int:pk>/recreate_records/',
         view=UpdateForwardZone.as_view(),
         name='zone_recreate_record'),
    path(route='reverse-zones/<int:pk>/recreate_records/',
         view=UpdateReverseZone.as_view(),
         name='reversezone_recreate_record'),
    path(route='ip-addresses/<int:ipaddress_pk>/recreate/',
         view=IPAddressDNSNameRecreateView.as_view(),
         name='ipaddress_dnsname_recreate'),
    path(route='ip-addresses/<int:ipaddress_pk>/extra-dns-name/create/',
         view=ExtraDNSNameCreateView.as_view(),
         name='extradnsname_ip_address_create'),

]
