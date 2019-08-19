from rest_framework import serializers
from django.contrib.auth.models import User
from . models import UserKey
from django.contrib.auth.hashers import make_password
from rest_framework.validators import UniqueValidator

class createSerializer(serializers.Serializer):
	username = serializers.CharField(max_length=50, min_length=3, 
		validators = [UniqueValidator(queryset=User.objects.all(), message="User with same username already exists")]) #have to show msg about length
	password = serializers.CharField(max_length=30, min_length=4)#have to show msg about length and rules about password
	email = serializers.EmailField(validators = [UniqueValidator(queryset=User.objects.all(), message="User with same email already exists")])

	def create(self, validated_data):
		user = User(
			username=validated_data['username'],
			password=make_password(validated_data['password']),
			email=validated_data['email'])
		user.save()
		return user

	class Meta:
		model = User

class keySerializer(serializers.Serializer):
	username = serializers.CharField()
	public_key = serializers.CharField(validators = [UniqueValidator(queryset=UserKey.objects.all(), message="User with same public key already exists")])
	key_updated = serializers.DateTimeField()

	class Meta:
		model = UserKey

	def create(self, validated_data):
		userkey = UserKey(
			username=validated_data["username"],
			public_key=validated_data["public_key"],
			key_updated=validated_data["key_updated"])
		userkey.save()
		return userkey

	def update(self, instance, validated_data):
		instance.username = validated_data.get("username", instance.username)
		instance.public_key = validated_data.get('public_key', instance.public_key)
		instance.key_updated = validated_data.get('key_updated', instance.key_updated)
		return instance