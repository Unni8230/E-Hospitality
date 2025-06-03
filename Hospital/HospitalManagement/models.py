from django.db import models

class Credentials(models.Model):
    username = models.CharField(max_length=100,unique=True, default="Unknown")
    name = models.CharField(max_length=255, default="Unknown")
    email = models.EmailField(max_length=255,unique=True, default="Unknown")
    phone = models.CharField(max_length=12,default="Unknown")
    password = models.CharField(max_length=255, default="Unknown")
    type=models.CharField(max_length=50,default="Unknown")
    def __str__(self):
        return self.username

class Doctor(models.Model):
    doctor_name = models.CharField(max_length=100,default="None")
    specialization = models.CharField(max_length=100,default="None")
    def __str__(self):
        return self.doctor_name
class Appointments(models.Model):
    user = models.ForeignKey(Credentials, on_delete=models.CASCADE)
    doctor = models.ForeignKey(Doctor, on_delete=models.CASCADE)
    date = models.DateField()
    time = models.TimeField()  
    doctors_description = models.CharField(max_length=255,default="") 
    medicines = models.CharField(max_length=255,default="None") 

class PatientRecords(models.Model):
    username = models.ForeignKey(Credentials,on_delete=models.CASCADE)
    disease = models.CharField(max_length=255,default="None")
    
    