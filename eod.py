#Version 2.1    By: StaryDark     Telegram: @Dark_zly   github.com/starydarkzly/EvilOriginDetection 

import requests, json, re
from urllib3 import disable_warnings
from colorama import Fore, init
import sys

init()
disable_warnings()

#Tokens de APIS
token_virustotal = "e551cf081d9319b4657544309baf4e36355b8e61dbc39cda50c97eac2e954fa1"
token_abuseip = "c37cb9cbe5bd2edfb8a0b3fd6d3e317ed62a40400eb0282ffcb939a4a9aa58812af3e23f2d9cc17e"

ipinfo_token = "69162063957794"
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

  #Validacion de datos de entrada /ip_addresses/{ip_address}/communicating_files

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
  
  #Extraer datos del resultado
  #print (datos)
  resumen = (datos["data"]["attributes"]["last_analysis_stats"])
  last_result = (datos["data"]["attributes"]["last_analysis_results"])
  last_result_time = (datos["data"]["attributes"]["last_analysis_date"])
  tags = (datos["data"]["attributes"]["tags"])
  
  try:
    categories = (datos["data"]["attributes"]["categories"])
    category = []
    for element in categories:
      category = categories[element] 
  except:
    category = []

  AV = {}
  end_data = {}

  if resumen["malicious"] > 0:
    end_data["VT_EVIL"] = True

 #Cantidad de detecciones
    for element in last_result.keys():
      if (last_result[element]["category"]) == "malicious" or "suspicious" == (last_result[element]["category"]):
        AV[element] =  last_result[element]["result"]
    
    #Cargar data
    end_data["AV"] = AV
    end_data["tags"] = tags
    end_data["category"] = category
    end_data["last_result_time"] = last_result_time

  else:
    end_data["VT_EVIL"] = False
 
  return end_data

def abuseip(inputurl):

  url = ("https://api.abuseipdb.com/api/v2/check")
  resultado = ""

  num_category = []

  categories = {1:"DNS Compromise", 2:"DNS Poisoning", 3:"Fraud Orders", 4: "DDoS Attack", 5:"FTP Brute-Force",
  6:"Ping of Death", 7:"Phishing", 8:"Fraud VoIP", 9:"Open Proxy", 10:"Web Spam", 11:"Email Spam", 12:"Blog Spam", 
  13:"VPN IP", 14:"Port Scan", 15:"Hacking", 16:"SQL Injection", 17:"Spoofing", 18:"Brute-Force", 19:"Bad Web Bot",
  20:"Exploited Host", 21:"Web App Attack", 22:"SSH", 23:"IoT Targeted"}

  querystring = {
      'ipAddress': inputurl,
      'maxAgeInDays': 300,
      'verbose': True
  }

  headers = {
      'Accept': 'application/json',
      'Key': f'{token_abuseip}'
  }
 
  try:
    response = requests.get(url=url,  headers=headers, params=querystring, verify=False)
    datos = json.loads(response.text)
  except:
    resultado = ("[ERROR] - AbuseIP is not Working")
    sys.exit()
  #print (datos)

  IPpublic = datos["data"]["isPublic"]
  if IPpublic == False:
    print (Fore.LIGHTRED_EX + "Esta Direccion IP es Privada, solo se aceptan IP Publicas...")
    sys.exit()
  #if int(datos["data"]["totalReports"]) > 0:
  total_reports = (datos["data"]["totalReports"])

  try:
    comentarios = datos["data"]["reports"]
    for element in comentarios:
      num_category.extend(element["categories"]) 
    categorias = detect_unique_element(num_category, categories)       
  except:
    categorias = ""
    print ("ERROR")
  

  return total_reports, categorias


def detect_unique_element(lista, categories):
    unique = []
    resultado = ""
    
    for elemento in lista:
        if elemento not in unique:
            unique.append(elemento)
            resultado = resultado + (categories[elemento] + "\n")
            #print (categories[elemento])

    return resultado

def info(inputurl):

  url = f"http://ipinfo.io/{inputurl}?token={ipinfo_token}"
  info = requests.get(url, verify=False)
  info = info.json()


  print (Fore.LIGHTCYAN_EX + ">>Informacion sobre el objetivo:\n")
  print (Fore.WHITE + "Target: "+ Fore.GREEN + inputurl)


  print (Fore.WHITE + "Pais: " + Fore.GREEN + info["country"])
  print (Fore.WHITE + "Org: " + Fore.GREEN + info["org"])



def format_tag(tags, category):
  """ Tomar una lista y convertira en STR separado por coma"""

  lista= []

  if len(tags) > 1 and tags[0] != "":
    lista.extend(tags)
  if len(category) > 1 and category[0] != "":
    if str(category):
      lista.append(category)
    else:
      lista.extend(category)


  resultado = ""
  if len(lista) >= 2:
    for element in lista:
      resultado = resultado + element + "," + " "
    resultado = resultado[:-2]
  elif len(lista) == 1:
    resultado = lista[0]
  else:
    resultado = ("")
  return resultado


#Ejecucion
def main (menu = menu):

  clearwindow()
  inputurl = input(menu)
  clearwindow()

  if is_valid_IP(inputurl):
    
    #IPinfo
    try:
      info(inputurl)
    except:
      print (Fore.RED + "[ERROR] - No se pudo cargar info()")
    
    #AbuseIP  
    reportes, tags = abuseip(inputurl)

    print (Fore.LIGHTCYAN_EX + "\n\n>>Investigacion realizada con AbuseIpDB")
    if reportes > 0:
      print (Fore.WHITE + "\nTotal de reportes maliciosos: " + Fore.RED + str(reportes))
      if len(tags) > 1:
        print (Fore.WHITE + "\nCategorias:\n" + Fore.RED + tags)
    else:
      print (Fore.WHITE + "AbuseIP:"  + Fore.GREEN + "Clean")






  #VirusTotal
  try:
    datosvirustotal = virustotal(inputurl)
  except:
    print (Fore.WHITE + "Virustotal: " + Fore.GREEN + "Clean or No Data")
    sys.exit()
  if datosvirustotal["VT_EVIL"]:
    """ Trabajo de la data exportada de VT """
    print (Fore.LIGHTCYAN_EX + "\n\n>>Investigacion realizada con Virustotal:\n")
    data = format_tag(datosvirustotal["tags"], datosvirustotal["category"])
    if len(data) > 0:
      print (Fore.WHITE + "TAGS:" + Fore.RED + data)
    print (Fore.WHITE + "\nAnalisis de AV:")
    
    for elements in datosvirustotal["AV"]:
      print (Fore.WHITE + "  " + elements, ": " + Fore.RED + datosvirustotal["AV"][elements])
  else:
    print (Fore.WHITE + "Virustotal: " + Fore.GREEN + "Clean")




if __name__== "__main__":
  main()
  print ("\n\n")
