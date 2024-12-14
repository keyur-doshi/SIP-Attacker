from django.urls import path
from .views import dashboard, execute_attack, attack_form

urlpatterns = [
    path("", dashboard, name="dashboard"),
    path("execute/", execute_attack, name="execute_attack"),
    path('attack_form/', attack_form, name='attack_form'),
]
