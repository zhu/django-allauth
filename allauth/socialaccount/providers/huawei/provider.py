import requests

from django.http import HttpRequest

from allauth.socialaccount.adapter import get_adapter
from allauth.socialaccount.providers.base import ProviderException
from allauth.socialaccount.providers.openid_connect.provider import (
    OpenIDConnectProvider,
    OpenIDConnectProviderAccount,
)

from .views import HuaweiAdapter


class HuaweiProviderAccount(OpenIDConnectProviderAccount):
    pass


class GetPhoneNumberFailed(ProviderException):
    def __init__(self, msg, data):
        self.data = data
        super().__init__(msg, data)


class HuaweiProvider(OpenIDConnectProvider):
    id = "huawei"
    name = "Huawei"
    account_class = HuaweiProviderAccount
    oauth2_adapter_class = HuaweiAdapter
    default_server_url = "https://oauth-login.cloud.huawei.com"
    phone_number_url = (
        "https://account-api.cloud.huawei.com/oauth2/v6/quickLogin/getPhoneNumber"
    )

    @property
    def server_url(self):
        url = self.app.settings.get("server_url", self.default_server_url)
        return self.wk_server_url(url)

    def get_login_url(self, request: HttpRequest, **kwargs):
        return super(OpenIDConnectProvider, self).get_login_url(request, **kwargs)

    def get_callback_url(self):
        return super(OpenIDConnectProvider, self).get_callback_url()

    def extract_uid(self, data):
        if id_token := data.get("id_token"):
            return id_token["sub"]
        else:
            # assume get_phone_number response
            return data["unionId"]

    def extract_common_fields(self, data):
        ret = super().extract_common_fields(data)
        if "phoneNumber" in data:
            # assume get_phone_number response
            phone = data["phoneNumber"]
            if phone.startswith("00"):
                phone = f"+{phone[2:]}"
            ret["phone"] = phone
            ret["phone_verified"] = data["phoneNumberValid"] == 1
        return ret

    def get_phone_number(self, code):
        """
        https://developer.huawei.com/consumer/cn/doc/harmonyos-references/account-api-get-user-info-quicklogin-by-code

        response successful:
        {
            "openId": "AQAxrBzThFv*****lv9tV_4rMCc",
            "unionId": "AQAxrB1HNA*****n-IfWRSUVq2M7xU",
            // 华为账号绑定号码，使用该手机号完成一键登录(返回数据实际为明文)
            "phoneNumber": "0086191******08",
            // 通过一键登录功能获取的华为账号绑定号码的实时有效性, 0表示需要进一步验证有效性， 1表示可以直接使用
            "phoneNumberValid": 1,
            // 不带国际冠码与国际电话区号的形式(返回数据实际为明文)
            "purePhoneNumber": "191******08",
            "phoneCountryCode": "0086"
        }

        response error:
        {
            "resultCode": 60180008,
            "resultDesc": "user or phone number not exist"
        }
        """
        app = self.app
        res = get_adapter().get_requests_session().post(
            url=self.phone_number_url,
            json={
                "code": code,
                "clientId": app.client_id,
                "clientSecret": app.secret,
            },
        )
        res.raise_for_status()
        data = res.json()

        if "resultCode" in data:
            raise GetPhoneNumberFailed("Something went wrong", data)

        return data

    def verify_token(self, request, token):
        # XXX: access_token or id_token is required in headless provider token input.
        #      so you need to send {"code": "...", "id_token": "placeholder"}
        code = token.get("code")
        if not code:
            return super().verify_token(request, token)
        try:
            identity_data = self.get_phone_number(code)
        except (requests.RequestException, GetPhoneNumberFailed) as e:
            raise get_adapter().validation_error("invalid_token") from e
        login = self.sociallogin_from_response(request, identity_data)
        return login


provider_classes = [HuaweiProvider]
