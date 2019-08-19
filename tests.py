from django.test import TestCase
# Create your tests here.
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User
from .config import site_url
from passlib.hash import pbkdf2_sha256


#test reg_get ,login,logout and generate methods## 
class Test_GReg(APITestCase):
	def setUp(self):

		self.url = site_url
		
		self.data = {'username': 'asfin','password':'  asfin@123   ','email':'asfin123@gmail.com'}
		response = self.client.post(self.url,self.data)

		self.data2 = {'username': 'jamesbond','password':'jamesbond007','email':'james007@gmail.com'}
		response2= self.client.post(self.url,self.data2)

		self.data3 = {'username': 'nepolean','password':'king@123','email':'nepolean@gmail.com'}
		response3= self.client.post(self.url,self.data3)
		
		 
##########test reg_get method################	

	def test_get_reg(self):
		self.url=site_url
		response=self.client.get(self.url)
		cont=eval(response.content.decode())

		self.assertEqual(response.status_code,200)
		self.assertTrue(len(cont)==3)
		self.assertTrue(cont[0]['username']=='asfin')
		self.assertTrue(cont[1]['username']=='jamesbond')
		self.assertTrue(cont[2]['username']=='nepolean')
		self.assertTrue(cont[0]['email']=='asfin123@gmail.com')

		self.assertIn('username',response.content.decode())
		self.assertIn('password',response.content.decode())
		self.assertIn('email',response.content.decode())

		self.assertIn('asfin123@gmail.com',response.content.decode())
		self.assertIn('james007@gmail.com',response.content.decode())
		self.assertIn('nepolean@gmail.com',response.content.decode())
		self.assertIn('asfin',response.content.decode())
		# print(cont[1]['password'],'fromcontent')
		# hash1 = pbkdf2_sha256.encrypt("jamesbond007",rounds=150000)
		# print(hash1,'from pbkdf2 sha256')
		# # self.assertTrue(cont[1]['password']==result.hexdigest())


##############test login method####################

	def test_login1(self):

		self.data1={'username':'jamesbond','password':'jamesbond007'}
		response1=self.client.post('%slogin/'%site_url,self.data1)
		# print(response1.content)
		self.assertEqual(response1.status_code,200)
		self.assertIn(r'"username":"jamesbond"',response1.content.decode())

	def test_login2(self):
		self.data2={'username':'jamesbond','password':'jamesbond'}
		response2=self.client.post('%slogin/'%site_url,self.data2)
		# print(response2.content)
		self.assertEqual(response2.status_code,401)

	def test_login3(self):
		self.data3={'username':'nepolan','password':'king123@'}
		response3=self.client.post('%slogin/'%site_url,self.data3)
		# print(response3.content)
		self.assertEqual(response3.status_code,401)

	def test_login4(self):
		self.data4={'username':'hitler','password':'hitler13'}
		response4=self.client.post('%slogin/'%site_url,self.data4)
		# print(response4.content)
		self.assertEqual(response4.status_code,401)

###############	generate post method###############

	def  test_generate(self):
		self.data3={'username':'jamesbond','password':'jamesbond007'}
		response4=self.client.post('%slogin/'%site_url,self.data3)
		cont=eval(response4.content.decode())
		KEY=cont['token']
		res=self.client.post('%sgenerate/'%site_url,self.data3,HTTP_AUTHORIZATION='Token %s'%KEY)
		# dic=eval(res.content.decode())
		self.assertIn('public_key',res.content.decode())
		self.assertIn('Private Key',res.content.decode())
		self.assertIn(r'"username":"jamesbond"',res.content.decode())
		# dic1=dic['Saved Data']['public_key']
		# print(dic1,'PUBLIC')
	
		self.assertEqual(res.status_code,200)
		# print(res.status_code,res.content,'generate success')

############## test logout method###############
	def test_logout(self):
		self.data3={'username':'jamesbond','password':'jamesbond007'}
		res=self.client.post('%slogin/'%site_url,self.data3)
		cont=eval(res.content.decode())
		key=cont['token']
		username=cont['username']
		res2=self.client.post('%slogout/'%site_url,HTTP_AUTHORIZATION='Token %s'%key)
		self.assertEqual(res2.status_code,204)
		self.assertEqual(res2.content,("{\"Token Deleted of the user\":\"%s\"}"%username).encode())

	def test_logout_2(self):
		self.data_logout={'username':'nepolean','password':'king@123'}
		res=self.client.post('%slogin/'%site_url,self.data_logout)
		cont=eval(res.content.decode())
		key=cont['token']
		username=cont['username']
		res2=self.client.post('%slogout/'%site_url,HTTP_AUTHORIZATION='Token %s'%key)
		res3=self.client.post('%slogout/'%site_url,HTTP_AUTHORIZATION='Token %s'%key)
		self.assertEqual(res2.status_code,204)
		self.assertEqual(res3.status_code,401)
		

	def test_search(self):
		self.urla='%slogin/'%site_url
		self.urlb='%sgenerate/'%site_url
		self.data2={'username':'jamesbond','password':'jamesbond007'}
		resk=self.client.post(self.urla,self.data2)
		info=eval(resk.content.decode())
		dat=info['username']
		cont=eval(resk.content.decode())
		KEY=cont['token']
		res=self.client.post(self.urlb,self.data2,HTTP_AUTHORIZATION='Token %s'%KEY)
		
		
		self.urlx='%ssearch/'%site_url
		datax={'username':dat}
		res=self.client.post(self.urlx,datax)
		# print(res.status_code,res.content,'search')
		self.assertEqual(res.status_code,200)
		self.assertIn('BEGIN PUBLIC KEY',res.content.decode())
		self.assertNotIn('Private Key',res.content.decode())

#test registration post method
class registration_Tests(APITestCase):

	def test_registration_1(self):
		#username may not start with integer
		self.url = ""
		self.data = {'username': '777rameshnaidu','password':'rajesh@123','email':'rajeshsh@gmail.com'}
		response = self.client.post(self.url,self.data)
		# print(response.status_code)
		self.assertEqual(response.status_code,400)

	def test_registration_2(self):
		self.url = ""
		self.data = {'username': 'suresh','password':'suresh@123','email':'suresh@gmail.com.com'}
		response = self.client.post(self.url,self.data)
		# print(response.status_code)
		self.assertEqual(response.status_code,400)

	def test_registration_3(self):
		#password may not contain spaces
		self.url = ""
		self.data = {'username': 'irfan','password':'  irfan  123   ','email':'irfan@gmail.com'}
		response = self.client.post(self.url,self.data)
		# print(response.status_code,response.content)
		self.assertEqual(response.status_code,400)

	def test_registration_4(self):
		#password should not be blank
		self.url=""
		self.data = {'username': '@@@@@@@@@@@@@@','password':'        ','email':'pavan98@gmail.com'}
		response=self.client.post(self.url,self.data, format='json')
		# print(response.status_code)
		self.assertEqual(response.status_code,400)

	def test_registration_5(self):
		#username must not contain all special characters
		self.url=""
		self.data = {'username': '@@@@@@@@@@@@@@','password':'rammmy@   123','email':'rammy123@gmail.com'}
		response=self.client.post(self.url,self.data, format='json')
		# print(response.status_code)
		self.assertEqual(response.status_code,400)

	def test_registration_twice(self):
		self.url = ""
		self.data = {'username': 'rameshnaidu','password':'ramesh@123','email':'ramesh@gmail.com'}
		self.data2 = {'username': 'rameshnaidu','password':'ramesh@123','email':'ramesh@gmail.com'}
		response = self.client.post(self.url,self.data)
		response2 = self.client.post(self.url,self.data)
		# print(response.content,"1st time register",response.status_code)
		# print(response2.content,"2nd time register",response2.status_code)
		self.assertEqual(response.status_code,200)
		self.assertEqual(response2.status_code,409)



