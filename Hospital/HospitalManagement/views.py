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