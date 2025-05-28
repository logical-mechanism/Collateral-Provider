from api.views import (ProvideCollateralView, custom_disallowed_host_handler,
                       custom_page_not_found, known_hosts_view, landing_page)
from django.urls import path, re_path
from django.contrib import admin
urlpatterns = [
    path("support-portal-44203/", admin.site.urls),
    path('', landing_page, name='landing_page'),
    re_path(r'^(?P<environment>[^/]+)/collateral/?$', ProvideCollateralView.as_view(), name='collateral'),
    re_path(r'^known_hosts/?$', known_hosts_view, name='known_hosts'),
]

handler404 = custom_page_not_found
handler400 = custom_disallowed_host_handler
