from django.urls import include, path, re_path

from allauth.socialaccount.providers.weixin import views


urlpatterns = [
    re_path(
        r"^(?P<weixin_appid>[^/]+)/",
        include(
            [
                path(
                    "login/",
                    views.login,
                    name="weixin_login",
                ),
                path(
                    "login/callback/",
                    views.callback,
                    name="weixin_callback",
                ),
            ]
        ),
    ),
    path(
        "login/",
        views.oauth2_login,
        name="weixin_login",
    ),
    path(
        "login/callback/",
        views.oauth2_callback,
        name="weixin_callback",
    ),
]

urlpatterns = [path("weixin/", include(urlpatterns))]
