import json
import requests
import time
from http import HTTPStatus
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from django.core.exceptions import ValidationError
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

    def test_verify_token_with_quick_login_code(self):
        with self.mocked_response(
            MockedResponse(
                HTTPStatus.OK,
                {
                    "openId": "huawei-open-id",
                    "unionId": "huawei-union-id",
                    "phoneNumber": "008613800138000",
                    "phoneNumberValid": 1,
                    "purePhoneNumber": "13800138000",
                    "phoneCountryCode": "0086",
                },
            )
        ):
            sociallogin = self.provider.verify_token(
                self.request, {"code": "quick-login-code"}
            )
            assert requests.Session.post.call_args.kwargs["url"] == (
                "https://account-api.cloud.huawei.com/oauth2/v6/quickLogin/getPhoneNumber"
            )
            assert requests.Session.post.call_args.kwargs["json"] == {
                "code": "quick-login-code",
                "clientId": self.app.client_id,
                "clientSecret": self.app.secret,
            }

        assert sociallogin.account.uid == "huawei-union-id"
        assert sociallogin.account.extra_data == {
            "openId": "huawei-open-id",
            "unionId": "huawei-union-id",
            "phoneNumber": "008613800138000",
            "phoneNumberValid": 1,
            "purePhoneNumber": "13800138000",
            "phoneCountryCode": "0086",
        }
        assert sociallogin.phone == "+8613800138000"
        assert sociallogin.phone_verified is True

    def test_verify_token_with_quick_login_code_handles_huawei_errors(self):
        with self.mocked_response(
            MockedResponse(
                HTTPStatus.OK,
                {
                    "resultCode": 60180008,
                    "resultDesc": "user or phone number not exist",
                },
            )
        ):
            with self.assertRaises(ValidationError):
                self.provider.verify_token(self.request, {"code": "quick-login-code"})

    def test_verify_token_without_quick_login_code_uses_openid_connect(self):
        with patch(
            "allauth.socialaccount.providers.openid_connect.provider."
            "OpenIDConnectProvider.verify_token"
        ) as verify_token:
            ret = self.provider.verify_token(self.request, {"id_token": "token"})

        verify_token.assert_called_once_with(self.request, {"id_token": "token"})
        assert ret is verify_token.return_value
