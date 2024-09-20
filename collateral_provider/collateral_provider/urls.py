from django.urls import path

from api.views import ProvideCollateralView

urlpatterns = [
    path('<str:environment>/collateral/', ProvideCollateralView.as_view(), name='collateral'),
]
