from django.urls import path
from . import views
urlpatterns = [
   path('',views.homePage,name='home'),
   path('login/',views.loginPage,name='login'),
   path('register/',views.registerUser,name='register'),
]