#Version 2.0    By: StaryDark     Telegram: @Dark_zly   github.com/starydarkzly/evilorigindetection 

import requests, json, re
from urllib3 import disable_warnings
from colorama import Fore, init

init()
disable_warnings()

#Tokens de APIS
token_virustotal = "e551cf081d9319b4657544309baf4e36355b8e61dbc39cda50c97eac2e954fa1"
token_abuseip = "c37cb9cbe5bd2edfb8a0b3fd6d3e317ed62a40400eb0282ffcb939a4a9aa58812af3e23f2d9cc17e"
token_urlscan = "248c787c-2c58-4bd8-8576-86f29d2be7ca"

menu = (Fore.WHITE + '''
________________________________________________________________
   .-._                                                   _,-, |
    `._`-._                                           _,-'_,'  |
       `._ `-._                                   _,-' _,'     |
          `._  `-._        __.----.__        _,-'   _,'        |
             `._   `#==="""          """===#'    _,'           |
  ___________ `._/)  ._                   _.    (              |
 /\          \.  )*'   \___         ____/    *(                |
| |Evil       |.  #  .==..__""     ""__..=.   #                |
\_| Origin    |.  #   "._('''+Fore.RED+'''#'''+Fore.WHITE+''')>       <('''+Fore.RED+'''#'''+Fore.WHITE+''')_."   #                |
""|  Deteccion|."""""""""""""""""""""""""""""""""""""""""""""""|
  |           |.                                               |
  |   ________|___                                             |
  |  / By:       /.                                            |
  \_/_StaryDark_/.                                             |
_______________________________________________________________|

Target: [0 = Salir]\n--->'''+Fore.GREEN)


#Funciones basicas
def readcsv(csvfile):
    """Lee un archivo csv y retorna una lista"""
    
    import csv
    with open(csvfile, 'r', encoding="utf8") as csvfile:
        content_csv = csv.reader(csvfile)
        result = []
        
        for fila in content_csv:
            result.append(fila)
        if len(result) == 1:
            lista = []
            for element in range(0,len(result[0])):
                lista.append(0)
            result.append(lista)         
    return result

def clearwindow():
    """ Limpiar la terminal en cualquier sistema operativo"""
    from os import name, system
    if name == 'nt':
        system("cls")
    else:
        system("clear")

def is_valid_IP(str):
    return bool(re.match(r'^((0|[1-9][0-9]?|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.|$)){4}$', str))
    


#Fuentes de inteligencia
def virustotal(inputurl):
  """Api de virustotal"""

  #Validacion de datos de entrada
  if is_valid_IP(inputurl):
    url = f"http://www.virustotal.com/api/v3/ip_addresses/{inputurl}"
  else:
    url = f"http://www.virustotal.com/api/v3/domains/{inputurl}"

  #Requests a la api
  headers = {
      "Accept": "application/json",
      "x-apikey": f"{token_virustotal}"
  }

  response = requests.get(url, headers=headers, verify=False)
  datos = json.loads(response.text)
  resultado = ""
  
  #Parser de los datos  
  resumen = (datos["data"]["attributes"]["last_analysis_stats"])
  last_result = (datos["data"]["attributes"]["last_analysis_results"])
  end_data = {}

  if resumen["malicious"] != 0:
    print(Fore.WHITE + "Resultados de Virustotal: \n" + "------------------------\n") #Cantidad de detecciones
    
    try:
      for element in last_result.keys():
        if (last_result[element]["category"]) == "malicious" or "suspicious" == (last_result[element]["category"]):
          end_data[element] =  last_result[element]["result"]
    except:
      end_data["Resultados de virustotal"] = "[ERROR] - Virustotal is not Working"

  else:
    end_data["Resultados de virustotal"] = Fore.GREEN + "Clean"
  
  return end_data

def abuseip(inputurl):

  url = ("https://api.abuseipdb.com/api/v2/check")
  resultado = ""

  querystring = {
      'ipAddress': inputurl,
      'maxAgeInDays': '90'
  }

  headers = {
      'Accept': 'application/json',
      'Key': 'c37cb9cbe5bd2edfb8a0b3fd6d3e317ed62a40400eb0282ffcb939a4a9aa58812af3e23f2d9cc17e'
  }
 
  try:
    response = requests.request(method='GET', url=url,  headers=headers, params=querystring, verify=False)
    datos = json.loads(response.text)
   # domainname = (datos["data"]["domain"])
  
    if int(datos["data"]["totalReports"]) > 0:
      resultado = (Fore.WHITE + "\n\nResultados de AbuseIP:\n" + "------------------------\n" + Fore.WHITE + "\nReportes Maliciosos: " + Fore.RED + str(datos["data"]["totalReports"]))
    else:
      resultado = (Fore.WHITE + "Resultados de AbuseIP: " + Fore.GREEN + "Clean")
   
    domainname = (datos["data"]["domain"])
    return resultado, str(domainname)
  except:
    resultado = ("[ERROR] - AbuseIP is not Working")
    
def info(inputurl):
  info = requests.get(f"https://ipapi.co/{inputurl}/json/", verify=False)
  info = json.loads(info.text)
  

  print (Fore.WHITE + "Investigacion del origen:\n" + "------------------------\n")
  print (Fore.WHITE + "Target: "+ Fore.GREEN + inputurl + "\n")
  print (Fore.WHITE + "Pais: " + Fore.GREEN + info["country_name"])
  try:
    domain = abuseip(inputurl)
    print (Fore.WHITE + "Domain Name: " + Fore.GREEN + domain[1])
  except:
    pass
  investigacion = invest(inputurl)
  if investigacion is not None:
    print (Fore.WHITE +"Origen:"+ Fore.GREEN + investigacion[1] + Fore.WHITE + "\nDescripcion:\n\n" + Fore.GREEN + investigacion[2] + Fore.WHITE + "\n\nMas informacion: "+ Fore.GREEN + investigacion[3] + "\n")
  else:
    print ("\n")

def urlscan(inputurl):
  import os
  headers = {'API-Key':'248c787c-2c58-4bd8-8576-86f29d2be7ca','Content-Type':'application/json'}
  data = {"url":inputurl, "visibility": "public"}

  response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data), verify=False)
  response = json.loads(response.text)
  urlapi = (response["api"])
  print (urlapi)
  
  a = "https://urlscan.io/api/v1/result/1f8ee754-d40b-419b-9031-7f95bd7f8d41/"
  print (a)
  
  urlscanresult = requests.get(urlapi, verify=False)

  urlscanresult = json.loads(urlscanresult.text)

  screenshot = (urlscanresult["task"]["screenshotURL"])
  urlacortada = (urlscanresult["data"]["links"][0]["href"])

  os.system(f"start {screenshot} ")

def invest(ip):
  db = readcsv("default/db_ip.csv")

  #Buscar a ver si la ip esta
  for line in db:
    if ip == line[0]:
      return line

def main (menu = menu):
  while True:
    clearwindow()
    inputurl = input(menu)
    clearwindow()
    if inputurl == "0":
      break

    try:
      info(inputurl)
    except:
      pass


    #VirusTotal
    datosvirustotal = virustotal(inputurl)
    for elements in datosvirustotal:
      print (Fore.WHITE + elements, ": " + Fore.RED + datosvirustotal[elements])

    #AbuseIP  
    try:
      datosabuseip = abuseip(inputurl)
      print (datosabuseip[0])
    except:
      pass


    sel = (input("\n\n" + Fore.GREEN + "Mas infofrmacion? Y/n (Default=n) -->"))
    if sel == "y" or sel == "Y":
      print ("Aun no disponible...")

if __name__== "__main__":
  main()
