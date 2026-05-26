import json
import time
from http import HTTPStatus
from urllib.parse import parse_qs, urlparse

from django.test import TestCase
from django.urls import reverse

import jwt

from allauth.socialaccount.models import SocialAccount
from allauth.socialaccount.providers.huawei.provider import HuaweiProvider
from tests.apps.socialaccount.base import OAuth2TestsMixin
from tests.mocking import MockedResponse, mocked_response


class HuaweiTests(OAuth2TestsMixin, TestCase):
    provider_id = HuaweiProvider.id
    openid_config = {
        "authorization_endpoint": "https://huawei.example.com/oauth2/v3/authorize",
        "token_endpoint": "https://huawei.example.com/oauth2/v3/token",
        "jwks_uri": "https://huawei.example.com/oauth2/v3/certs",
        "issuer": "https://accounts.huawei.com",
    }
    id_token = {
        "iss": "https://accounts.huawei.com",
        "aud": "app123id",
        "sub": "huawei-sub",
        "name": "Jane Doe",
        "given_name": "Jane",
        "family_name": "Doe",
        "picture": "https://example.com/jane.jpg",
    }

    def setup_provider(self):
        super().setup_provider()
        self.app.settings = {
            "server_url": "https://huawei.example.com",
        }
        self.app.save()
        self.provider = self.app.get_provider(self.request)

    def get_id_token(self):
        data = self.id_token.copy()
        now = int(time.time())
        data.update({"iat": now, "exp": now + 3600})
        return data

    def get_login_response_json(self, with_refresh_token=True):
        data = json.loads(
            super().get_login_response_json(with_refresh_token=with_refresh_token)
        )
        data["id_token"] = jwt.encode(self.get_id_token(), "secret")
        return json.dumps(data)

    def mocked_response(self, *responses):
        return mocked_response(*responses, callback=self._mocked_responses)

    def get_mocked_response(self):
        # Enable OAuth2TestsMixin tests; Huawei does not fetch userinfo.
        return True

    def get_expected_to_str(self):
        return "Jane Doe"

    def _mocked_responses(self, url, *args, **kwargs):
        if url.endswith("/.well-known/openid-configuration"):
            return MockedResponse(HTTPStatus.OK, json.dumps(self.openid_config))

    def test_login_uses_static_provider_urls(self):
        with self.mocked_response():
            resp = self.client.post(self.provider.get_login_url(self.request))

        assert resp.status_code == HTTPStatus.FOUND
        redirect = urlparse(resp["location"])
        assert redirect.scheme == "https"
        assert redirect.netloc == "huawei.example.com"
        assert redirect.path == "/oauth2/v3/authorize"
        query = parse_qs(redirect.query)
        assert query["redirect_uri"] == [
            "http://testserver" + reverse("huawei_callback")
        ]

    def test_login_stores_id_token_claims_without_userinfo(self):
        resp = self.login()

        self.assertRedirects(resp, "/accounts/profile/", fetch_redirect_response=False)
        account = SocialAccount.objects.get(provider=self.provider.id)
        assert account.uid == "huawei-sub"
        assert account.extra_data == {"id_token": self.get_id_token(), "userinfo": None}

    def test_extract_uid_falls_back_to_union_id(self):
        assert self.provider.extract_uid({"unionId": "union-id"}) == "union-id"
