from django.urls import path
from . views import register, login, logout, generate, search, upload

urlpatterns = [
	path("", register.as_view()),
	path("login/", login.as_view()),
	path("logout/", logout.as_view()),
	path("generate/", generate.as_view()),
	path("upload/", upload.as_view()),
	path("search/", search.as_view())
]