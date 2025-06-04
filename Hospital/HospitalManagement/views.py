from django.shortcuts import render, redirect
from . import urls
import bcrypt
from .models import *
from django.contrib import messages
# Create your views here.

def homePage(request):
    return render(request, 'homePage.html')
def loginPage(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = Credentials.objects.filter(username=username).first()
        if user is not None:
            if bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
                if user.type == "Patient":
                    request.session['user_id'] = user.id
                    return redirect('userprofile')
                elif user.type == "Doctor":
                    request.session['user_id'] = user.id
                    return redirect('doctorprofile')
                elif user.type=="Admin":
                    request.session['user_id'] = user.id
                    return redirect('adminprofile')
            else:
                messages.error(request,"Invalid Password!")
                return redirect('login')
        else:
            messages.error(request,"Invalid User!")
            return redirect('login')
    return render(request,'loginPage.html')
def logout(request):
    request.session.flush()
    return redirect('login')
def registerUser(request):
    if request.method == 'POST':
        name = request.POST['name']
        email = request.POST['email']
        phone = request.POST['phone']
        username = request.POST['username']
        password = request.POST['password']
        cpassword = request.POST['cpassword']
        type = request.POST['type']

        if(password != cpassword):
            messages.error(request,"Passwords do not match!")
            return redirect('register')
        else:
            if Credentials.objects.filter(email=email).exists():
                messages.error(request,"Username already taken")
                return redirect('register')
            elif Credentials.objects.filter(email=email).exists():
                messages.error(request,"Email already taken")
                return redirect('register')
            else:
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                Credentials.objects.create(name=name,email=email,phone=phone,username=username,password=hashed_password,type=type)
                messages.success(request,"Registration Succesful, Please Login")
                return redirect('login')
    return render(request,'registerUser.html')

def userProfile(request):
    if "user_id" not in request.session:
        return redirect('login')
    else:
        user = Credentials.objects.get(id=request.session['user_id'])
        appointments = Appointments.objects.filter(user=user)
        doctors = Doctor.objects.all()
        if request.method == "POST":
            doctor_id = request.POST['doctor']
            date = request.POST['date']
            time = request.POST['time']
            doctor = Doctor.objects.get(id=doctor_id)
            Appointments.objects.create(user=user,doctor=doctor,date=date,time=time)
            messages.success(request,"Appointment Booked Successfully")
            return redirect('userprofile')

    return render(request,'userProfile.html', {"user": user, "appointments": appointments, "doctors": doctors})

def doctorProfile(request):
    if "user_id" not in request.session:
        return redirect('login')
    else:
        user = Credentials.objects.get(id=request.session['user_id'])
        doctor = Doctor.objects.get(doctor_name=user.name)

        query = """SELECT * FROM Hospital_Appointments inner join Hospital_PatientRecords 
        on Hospital_Appointments.user_id = Hospital_PatientRecords.username_id 
        inner join Hospital_Credentials on Hospital_Appointments.user_id = Hospital_Credentials.id
        where Hospital_Appointments.doctor_id = %s """
        
        patients = Appointments.objects.raw(query,[doctor.id])
    
    return render(request, "doctorProfile.html", {
        "doctor": doctor,
        "patients":patients
    })
def logout(request):
    request.session.flush()
    return redirect('login')

def adminProfile(request):
    if "user_id" not in request.session:
        return redirect('login')
    else:
        user = Credentials.objects.get(id=request.session['user_id'])
        doctors = Doctor.objects.all()
        appointments = Appointments.objects.select_related("doctor").all()
        patients = PatientRecords.objects.all()

        context = {
            "doctors": doctors,
            "appointments": appointments,
            "patients": patients
        }

    return render(request,'adminProfile.html', context)