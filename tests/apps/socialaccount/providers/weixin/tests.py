import json
import requests

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.contrib.messages.middleware import MessageMiddleware
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import RequestFactory, TestCase
from django.test.utils import override_settings
from django.urls import reverse

from allauth.account.utils import user_username
from allauth.core import context
from allauth.socialaccount.helpers import complete_social_login
from allauth.socialaccount.models import SocialAccount
from allauth.socialaccount.tests import OAuth2TestsMixin, setup_app
from allauth.tests import MockedResponse, mocked_response

from allauth.socialaccount.providers.weixin.provider import (
    WeixinOfficialAccountOAuth2Provider,
    WeixinProvider
)


class MockedUserInfoResponse(MockedResponse):
    def __init__(self, status, content, headers=None):
        orig_content_type = (headers or {}).get("content-type")
        super().__init__(status, content, headers)
        if orig_content_type:
            self.headers["content-type"] = orig_content_type
        self.encoding = requests.utils.get_encoding_from_headers(self.headers)

    @property
    def text(self):
        return self.content.decode(self.encoding or "utf8")


class WeixinTestsMixin:
    provider_id: str

    def setup_provider(self):
        self.app = setup_app(self.provider_id)
        self.app.provider_id = self.provider_id
        self.app.provider = WeixinProvider.id
        self.app.save()
        self.request = RequestFactory().get("/")
        self.provider = self.app.get_provider(self.request)


class WeixinOAuth2TestsMixin(OAuth2TestsMixin):
    def get_scope(self):
        return ",".join(self.provider.get_scope())

    def get_login_response_json(self, with_refresh_token=True):
        # TODO: unionid does not always exist
        # XXX: weixin always return refresh_token
        return {
            "access_token": self.get_access_token(),
            "expires_in": 7200,
            "refresh_token": self.get_refresh_token(),
            "openid": f"{self.app.client_id}-ofh-A6kbx2Q4wu-JBn-NFPZLH-PY",
            "scope": self.get_scope(),
            "unionid": "op8Zewu3SvtyA6s2zi-ebjvJ5t1c",
        }

    def get_mocked_response(self):
        return MockedUserInfoResponse(
            200,
            json.dumps(
                {
                    "openid": "ofh-A6kbx2Q4wu-JBn-NFPZLH-PY",
                    "nickname": "某某某",
                    "sex": 0,
                    "province": "",
                    "city": "",
                    "country": "",
                    "headimgurl": "http://wx.qlogo.cn/mmopen/"
                    "VkvLVEpoJiaibYsVyW8GzxHibzlnqSM7iaX09r6TWUJXCNQHibHz37"
                    "krvN65HR1ibEpgH5K5sukcIzA3r1C4KQ9qyyX9XIUdY9lNOk/0",
                    "privilege": [],
                    "unionid": "op8Zewu3SvtyA6s2zi-ebjvJ5t1c",
                },
                ensure_ascii=False,
            ),
            headers={
                "content-type": "text/plain",
            },
        )  # noqa

    def get_expected_to_str(self):
        return "某某某"

    def test_get_userinfo(self):
        adapter = WeixinOfficialAccountOAuth2Provider.adapter_class(
            self.request, self.app, self.provider
        )
        with mocked_response(self.get_mocked_response()):
            resp = adapter.get_userinfo("somesk", "someopenid")
        assert resp["nickname"] == "某某某"


class WeixinOpenPlatformTests(WeixinTestsMixin, WeixinOAuth2TestsMixin, TestCase):
    provider_id = "open-platform"

    def get_weixin_code_payload(self):
        return "testcode"

    def test_verify_token(self):
        code = self.get_weixin_code_payload()
        with mocked_response(
            self.get_login_response_json(), self.get_mocked_response()
        ):
            sociallogin = self.provider.verify_token(None, {"code": code})
            assert sociallogin.account.uid == "ofh-A6kbx2Q4wu-JBn-NFPZLH-PY"


class WeixinOfficialAccountTests(WeixinTestsMixin, WeixinOAuth2TestsMixin, TestCase):
    provider_id = "official-account"

    def get_login_response_json(self, with_refresh_token=True):
        resp = super().get_login_response_json(with_refresh_token)
        del resp["unionid"]
        return resp

    def get_expected_to_str(self):
        return self.app.name


class mocked_provider:
    def __init__(self, testcase, provider_id):
        self.testcase = testcase
        self.provider_id = provider_id

    def __enter__(self):
        testcase = self.testcase
        self.orig_provider_id = testcase.provider_id
        testcase.provider_id = self.provider_id
        testcase.setup_provider()
        if not testcase.app.client_id.endswith(self.provider_id):
            testcase.app.client_id += self.provider_id
            testcase.app.save()

    def __exit__(self, type, value, traceback):
        self.testcase.provider_id = self.orig_provider_id
        self.testcase.setup_provider()


class WeixinOfficialAccountUserInfoScopeTests(
    WeixinTestsMixin, WeixinOAuth2TestsMixin, TestCase
):
    provider_id = "official-account"

    def setup_provider(self):
        super().setup_provider()
        self.app.settings["scope"] = ["snsapi_userinfo"]
        self.app.save()

    def get_weixin_js_code_payload(self):
        return "testcode"

    def test_unionid(self):
        user = get_user_model()(is_active=True)
        user_username(user, "user")
        user.set_password("test")
        user.save()
        self.client.login(username=user.username, password="test")
        self.login(self.get_mocked_response(), process="connect")
        account = SocialAccount.objects.get(user=user, provider=self.provider_id)
        provider_account = account.get_provider_account()
        self.client.logout()

        js_code = self.get_weixin_js_code_payload()
        with mocked_response(
            {
                "session_key": "DUK3Jpmjqv6KeYawybU4OQ==",
                "openid": "o7Vve53fsGBFDlROb_gjZc0S9NSs",
                "unionid": self.get_login_response_json()["unionid"],
            }
        ):
            with mocked_provider(self, "mini-program"):
                sociallogin = self.provider.verify_token(None, {"js_code": js_code})

            assert account != sociallogin.account
            assert (
                provider_account.get_unionid()
                == sociallogin.account.get_provider_account().get_unionid()
            )
            assert sociallogin.user != user

            request = RequestFactory().get("/")
            with context.request_context(request):
                SessionMiddleware(lambda request: None).process_request(request)
                MessageMiddleware(lambda request: None).process_request(request)
                request.user = AnonymousUser()
                resp = complete_social_login(request, sociallogin)
            assert sociallogin.user == user
            self.assertRedirects(
                resp, "/accounts/profile/", fetch_redirect_response=False
            )

        with mocked_provider(self, "open-platform"):
            resp = self.login(self.get_mocked_response())
            self.assertRedirects(
                resp, "/accounts/profile/", fetch_redirect_response=False
            )
            assert resp.context["user"] == user

    @override_settings(
        SOCIALACCOUNT_PROVIDERS={
            "weixin": {
                "APP": {
                    "provider_id": "official-account:another"
                }
            }
        }
    )
    def test_multiple_apps_with_same_subprovider(self):
        user = get_user_model()(is_active=True)
        user_username(user, "user")
        user.set_password("test")
        user.save()
        self.client.login(username=user.username, password="test")
        self.login(self.get_mocked_response(), process="connect")
        account = SocialAccount.objects.get(user=user, provider=self.provider_id)
        account.get_provider_account()


class WeixinMiniProgramTests(WeixinTestsMixin, TestCase):
    provider_id = "mini-program"

    def setUp(self):
        super().setUp()
        self.setup_provider()

    def get_weixin_js_code_payload(self):
        return "testcode"

    def test_verify_token(self):
        js_code = self.get_weixin_js_code_payload()
        with mocked_response(
            {
                "session_key": "DUK3Jpmjqv6KeYawybU4OQ==",
                "openid": "o7Vve53fsGBFDlROb_gjZc0S9NSs",
                "unionid": "op8Zewu3SvtyA6s2zi-ebjvJ5t1c",
            }
        ):
            sociallogin = self.provider.verify_token(None, {"js_code": js_code})
            assert sociallogin.account.uid == "o7Vve53fsGBFDlROb_gjZc0S9NSs"


class WeixinAppEmptyProviderIdCompatibleTests(WeixinOpenPlatformTests):
    def setup_provider(self):
        super().setup_provider()
        self.app.provider_id = ""
        self.app.save()


class WeixinLegecyUrlTests(WeixinOpenPlatformTests):
    def setup_provider(self):
        super().setup_provider()
        self.provider.legacy_url = True

    def test_legacy_url(self):
        login_url = self.provider.get_login_url(self.request)
        assert login_url == reverse("weixin_login")
