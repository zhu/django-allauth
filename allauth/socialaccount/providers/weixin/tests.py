# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from urllib.parse import parse_qs, urlparse

from allauth.account.signals import user_logged_in
from allauth.socialaccount.providers import registry
from allauth.socialaccount.tests import create_oauth2_tests, setup_app
from allauth.tests import MockedResponse, mocked_response
from django.urls import reverse

from .provider import WeixinProvider


class WeixinTests(create_oauth2_tests(registry.by_id(WeixinProvider.id))):
    def get_mocked_response(self):
        return MockedResponse(
            200,
            """
{"access_token":
 "OezXcEiiBSKSxW0eoylIeO5cPxb4Ks1RpbXGMv9uiV35032zNHGzXcld-EKsSScE3gRZMrUU78skCbp1ShtZnR0dQB8Wr_LUf7FA-H97Lnd2HgQah_GnkQex-vPFsGEwPPcNAV6q1Vz3uRNgL0MUFg",
 "city": "Pudong New District",
 "country": "CN",
 "expires_in": 7200,
 "headimgurl":
 "http://wx.qlogo.cn/mmopen/VkvLVEpoJiaibYsVyW8GzxHibzlnqSM7iaX09r6TWUJXCNQHibHz37krvN65HR1ibEpgH5K5sukcIzA3r1C4KQ9qyyX9XIUdY9lNOk/0",
 "language": "zh_CN",
 "nickname": "某某某",
 "openid": "ohS-VwAJ9GEXlplngwybJ3Z-ZHrI",
 "privilege": [],
 "province": "Shanghai",
 "refresh_token":
 "OezXcEiiBSKSxW0eoylIeO5cPxb4Ks1RpbXGMv9uiV35032zNHGzXcld-EKsSScEbMnnMqVExcSpj7KRAuBA8BU2j2e_FK5dgBe-ro32k7OuHtznwqqBn5QR7LZGo2-P8G7gG0eitjyZ751sFlnTAw",
 "scope": "snsapi_login",
 "sex": 1,
 "unionid": "ohHrhwKnD9TOunEW0eKTS45vS5Qo"}""",
        )  # noqa


class AnotherWeixinTests(WeixinTests):
    def make_openid(self, app_id=None):
        if not app_id:
            return "ohS-VwAJ9GEXlplngwybJ3Z-ZHrI"

        return app_id +  "ohS-VwAJ9GEXlplngwybJ3Z-ZHrI"

    def get_mocked_response(self, app_id=None, unionid="ohHrhwKnD9TOunEW0eKTS45vS5Qo"):
        return MockedResponse(
            200,
            """
{"access_token":
 "OezXcEiiBSKSxW0eoylIeO5cPxb4Ks1RpbXGMv9uiV35032zNHGzXcld-EKsSScE3gRZMrUU78skCbp1ShtZnR0dQB8Wr_LUf7FA-H97Lnd2HgQah_GnkQex-vPFsGEwPPcNAV6q1Vz3uRNgL0MUFg",
 "city": "Pudong New District",
 "country": "CN",
 "expires_in": 7200,
 "headimgurl":
 "http://wx.qlogo.cn/mmopen/VkvLVEpoJiaibYsVyW8GzxHibzlnqSM7iaX09r6TWUJXCNQHibHz37krvN65HR1ibEpgH5K5sukcIzA3r1C4KQ9qyyX9XIUdY9lNOk/0",
 "language": "zh_CN",
 "nickname": "某某某",
 "openid": "%s",
 "privilege": [],
 "province": "Shanghai",
 "refresh_token":
 "OezXcEiiBSKSxW0eoylIeO5cPxb4Ks1RpbXGMv9uiV35032zNHGzXcld-EKsSScEbMnnMqVExcSpj7KRAuBA8BU2j2e_FK5dgBe-ro32k7OuHtznwqqBn5QR7LZGo2-P8G7gG0eitjyZ751sFlnTAw",
 "scope": "snsapi_login",
 "sex": 1,
 "unionid": "%s"}""" % (self.make_openid(app_id), unionid),
        )  # noqa

    def login(self, resp_mock, process="login", with_refresh_token=True, app_id=None):
        qs = dict(process=process)
        if app_id:
            qs['app_id'] = app_id
        resp = self.client.get(
            reverse(self.provider.id + "_login"), qs
        )
        p = urlparse(resp["location"])
        q = parse_qs(p.query)
        complete_url = reverse(self.provider.id + "_callback")
        self.assertGreater(q["redirect_uri"][0].find(complete_url), 0)
        response_json = self.get_login_response_json(
            with_refresh_token=with_refresh_token
        )
        if isinstance(resp_mock, list):
            resp_mocks = resp_mock
        else:
            resp_mocks = [resp_mock]

        with mocked_response(
            MockedResponse(200, response_json, {"content-type": "application/json"}),
            *resp_mocks,
        ):
            resp = self.client.get(complete_url, self.get_complete_parameters(q))
        return resp

    def test_multi_app(self):
        self.another_app = setup_app(self.provider)
        self.another_app.client_id = 'another_app'
        self.another_app.save()

        login_users = []

        def on_login_user(sender, request, user, **kwargs):
            sociallogin = kwargs["sociallogin"]
            self.assertEqual(sociallogin.account.provider, WeixinProvider.id)
            self.assertEqual(sociallogin.account.user, user)
            login_users.append(user)

        user_logged_in.connect(on_login_user)

        self.login(self.get_mocked_response(app_id=self.app.client_id), app_id=self.app.client_id)

        self.assertEqual(len(login_users), 1)

        self.login(self.get_mocked_response(app_id=self.another_app.client_id), app_id=self.another_app.client_id)

        self.assertEqual(len(login_users), 2)
        self.assertEqual(*login_users)
