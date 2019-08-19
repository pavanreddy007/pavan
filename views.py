from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from . models import UserKey
from . serializers import createSerializer, keySerializer
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.status import (
	HTTP_200_OK,
	HTTP_400_BAD_REQUEST,
	HTTP_404_NOT_FOUND)
from Crypto.PublicKey import RSA

# Create your views here.
class register(APIView):
	def get(self, request):
		user = User.objects.all()
		data = createSerializer(user, many=True)
		return Response(data.data)

	def post(self, request):
		user = createSerializer(data=request.data)
		if user.is_valid():
			user.save()
			return Response(user.data)
		else:
			return Response(user.errors)

class login(APIView):
	def post(self, request):
		username = request.data.get("username")
		password = request.data.get("password")
		if username is None or password is None:
			return Response({'error': 'Please provide both username and password'}, status=HTTP_400_BAD_REQUEST)
		user = authenticate(username=username, password=password)
		if not user:
			return Response({'error': 'Invalid Credentials'},status=HTTP_404_NOT_FOUND)
		token, _ = Token.objects.get_or_create(user=user)
		return Response({'token': token.key,
			'username':username}, status=HTTP_200_OK)
		
class logout(APIView):
	authentication_classes = (TokenAuthentication, )
	permission_classes = (IsAuthenticated, )
	def post(self, request):
		key = request.user.auth_token
		user = Token.objects.get(key=key).user
		user2 = createSerializer(User.objects.get(username=user))
		username = user2.data.get("username")
		request.user.auth_token.delete()
		logout()
		return Response({"Token Deleted of the user" :username }, status = 204)

class generate(APIView):
	authentication_classes = (TokenAuthentication, )
	permission_classes = (IsAuthenticated, )

	def get(self, request):
		data = keySerializer(UserKey.objects.all(), many=True)
		return Response(data.data)

	def post(self, request):
		username = request.data.get("username")
		password = request.data.get("password")
		if username is None or password is None:
			return Response({'error': 'Please provide both username and password'}, status=HTTP_400_BAD_REQUEST)
		flag = authenticate(username=username, password=password)
		if not flag:
			return Response({'error': 'Invalid Credentials'},status=HTTP_404_NOT_FOUND)

		mod = 1024
		priv_key = RSA.generate(mod)
		pub_key = priv_key.publickey()
		private_key = priv_key.exportKey()
		public_key = pub_key.exportKey()

		user = Token.objects.get(key=request.user.auth_token).user
		user2 = createSerializer(User.objects.get(username=user))
		username2 = user2.data.get("username")
		if username == username2:
			userkey, created = UserKey.objects.update_or_create(username=user, 
				defaults = {'public_key':public_key})
			userk = keySerializer(userkey)
			return Response({"Saved Data": userk.data, "Private Key": private_key})
		else:
			return Response({"username and token owner are different"})

class upload(APIView):
	authentication_classes = (TokenAuthentication, )
	permission_classes = (IsAuthenticated, )
	def put(self, request):
		public_key = request.data.get("public_key")
		username = request.data.get("username")

		user = Token.objects.get(key=request.user.auth_token).user
		user2 = createSerializer(User.objects.get(username=user))
		username2 = user2.data.get("username")
		if username == username2:
			userkey, created = UserKey.objects.update_or_create(username=user, 
				defaults = {'public_key':public_key})
			userk = keySerializer(userkey)
			return Response(userk.data)
		else:
			return Response({"username and token owner are different"})

class search(APIView):
	def post(self, request):
		username = request.data.get("username")
		user = User.objects.get(username = username)
		userk = keySerializer(UserKey.objects.get(username=user))
		return Response(userk.data.get("public_key"))
