from api.views import (ProvideCollateralView, custom_page_not_found,
                       landing_page)
from django.conf.urls import handler404
from django.urls import path

urlpatterns = [
    path('', landing_page, name='landing_page'),
    path('<str:environment>/collateral/', ProvideCollateralView.as_view(), name='collateral'),
]


handler404 = custom_page_not_found
