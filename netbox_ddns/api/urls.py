from netbox.api.routers import NetBoxRouter
from . import views


app_name = "netbox_ddns"

router = NetBoxRouter()
router.register("extra-dns-name", views.ExtraDNSNameViewSet)
router.register("zone", views.ZoneViewSet)
router.register("server", views.ServerViewSet)

urlpatterns = router.urls
