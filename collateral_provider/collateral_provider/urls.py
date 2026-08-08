from api.views import (
    ProvideCollateralView,
    custom_disallowed_host_handler,
    custom_page_not_found,
    healthz_view,
    known_hosts_view,
    landing_page,
    livez_view,
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
    re_path(r"^livez/?$", livez_view, name="livez"),
    re_path(r"^metrics/?$", metrics_view, name="metrics"),

    # OpenAPI schema + interactive docs. Trailing slash is optional on all
    # three so /api/docs and /api/docs/ both resolve directly (no 308
    # redirect dance, which APPEND_SLASH would otherwise impose).
    re_path(r"^api/schema/?$", SpectacularAPIView.as_view(), name="schema"),
    re_path(r"^api/docs/?$", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger"),
    re_path(r"^api/redoc/?$", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),
]

handler404 = custom_page_not_found
handler400 = custom_disallowed_host_handler
