from api.views import (
    ProvideCollateralView,
    custom_disallowed_host_handler,
    custom_page_not_found,
    healthz_view,
    known_hosts_view,
    landing_page,
    metrics_view,
)
from django.urls import path, re_path
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

urlpatterns = [
    path("", landing_page, name="landing_page"),
    re_path(r"^(?P<environment>[^/]+)/collateral/?$", ProvideCollateralView.as_view(), name="collateral"),
    re_path(r"^known_hosts/?$", known_hosts_view, name="known_hosts"),
    re_path(r"^healthz/?$", healthz_view, name="healthz"),
    re_path(r"^metrics/?$", metrics_view, name="metrics"),

    # OpenAPI schema + interactive docs
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path("api/docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger"),
    path("api/redoc/", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),
]

handler404 = custom_page_not_found
handler400 = custom_disallowed_host_handler
