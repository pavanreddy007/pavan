from django.db import models
from django.contrib.auth.models import User
# Create your models here.


class UserKey(models.Model):
	username = models.OneToOneField(User, unique=True, on_delete=models.CASCADE)
	public_key = models.TextField(unique=True)
	key_updated = models.DateTimeField(auto_now=True)

	def __str__(self):
		return self.username
