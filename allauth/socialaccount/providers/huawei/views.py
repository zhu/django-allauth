from __future__ import annotations

from django.http import HttpRequest

from allauth.socialaccount.providers.oauth2.views import (
    OAuth2Adapter,
    OAuth2CallbackView,
    OAuth2LoginView,
)
from allauth.socialaccount.providers.openid_connect.views import (
    OpenIDConnectOAuth2Adapter,
)


class HuaweiAdapter(OpenIDConnectOAuth2Adapter):
    provider_id = "huawei"

    def __init__(self, request: HttpRequest, provider_id=None) -> None:
        super().__init__(request, provider_id or self.provider_id)

    def _fetch_user_info(self, access_token):
        # no userinfo endpoint
        return None

    def get_callback_url(self, request: HttpRequest, app):
        return OAuth2Adapter.get_callback_url(self, request, app)


oauth2_login = OAuth2LoginView.adapter_view(HuaweiAdapter)
oauth2_callback = OAuth2CallbackView.adapter_view(HuaweiAdapter)
