from .methodologies import *
from django.http import HttpResponse
from django.shortcuts import render

def dashboard(request):
    return render(request, "dashboard.html")

def attack_form(request):
    attack = request.GET.get('attack', None)
    if not attack:
        return render(request, 'attack_result.html', {'result': "No attack type specified."})
    return render(request, 'attack_form.html', {'attack': attack})

def execute_attack(request):
    if request.method == "POST":
        attack = request.POST.get('attack', None)
        if(attack=="enumerate"):
            return enumerationAttack(request)
        elif(attack=="invite_flood"):
            return inviteAttack(request)
        elif(attack=="spit_attack"):
            return SPITAttack(request)
        elif(attack=="register_flood"):
            return registerAttack(request)
        elif(attack=="traffic_capture"):
            return trafficCapture(request)
        return HttpResponse("Invalid attack.")
    return HttpResponse("Invalid request.")