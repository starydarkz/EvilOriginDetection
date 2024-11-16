#v2.3   By: StaryDark   Tlg: @StaryDarkz  

import requests, json, re, sys
from config import menu
from urllib3 import disable_warnings
from colorama import Fore, init


init()
disable_warnings()

#Funciones basicas

def clearwindow():
    """ Limpiar la terminal en cualquier sistema operativo"""
    from os import name, system
    if name == 'nt':
        system("cls")
    else:
        system("clear")

#Deteccion de tipos de IOC
def is_valid_IP(str):
    return bool(re.match(r"\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", str))

def is_valid_Hash(str): # Proxima version
  pass

def is_valid_Domain(str): # Proxima version
  pass


#Funciones de extraccion de informacion atravez de API
def virustotal_api(ioc, typeioc):
  """Api de virustotal"""

  from config import token_virustotal

  if typeioc == "ip":
    url = f"http://www.virustotal.com/api/v3/ip_addresses/{ioc}"

  elif typeioc == "domain":
    url = f"http://www.virustotal.com/api/v3/domains/{ioc}"

  elif typeioc == "hash":
    pass

  #Requests a la api
  headers = {
      "Accept": "application/json",
      "x-apikey": f"{token_virustotal}"
  }

  response = requests.get(url, headers=headers, verify=False)
  datos = json.loads(response.text)
  
  #Extraer datos del resultado
  
  resumen = (datos["data"]["attributes"]["last_analysis_stats"])
  last_result = (datos["data"]["attributes"]["last_analysis_results"])
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

  else:
    end_data["VT_EVIL"] = False
  
  return end_data

def abuseip_api(inputurl):

  from config import token_abuseip

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

def info(ioc):
  from config import token_ipinfo
  url = f"http://ipinfo.io/{ioc}?token={token_ipinfo}"
  info = requests.get(url, verify=False)
  info = info.json()


  print (Fore.LIGHTCYAN_EX + "\n>>Informacion sobre el objetivo:\n")
  print (Fore.WHITE + "Target: "+ Fore.GREEN + ioc)


  print (Fore.WHITE + "Pais: " + Fore.GREEN + info["country"])
  print (Fore.WHITE + "Org: " + Fore.GREEN + info["org"])


#Manipulacion de datos
def detect_unique_element(lista, categories):
    unique = []
    resultado = ""
    
    for elemento in lista:
        if elemento not in unique:
            unique.append(elemento)
            resultado = resultado + (categories[elemento] + "\n")
            #print (categories[elemento])

    return resultado

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
def main (menu):
  while True:
    clearwindow()
    type_indicator = input(menu)
    clearwindow()


    if type_indicator == '0': #IP
      #IPinfo

      ioc = input(Fore.WHITE + "Target IP:\n--->"+Fore.GREEN)
      
      if is_valid_IP(ioc):
        try:
          info(ioc)
        except:
          print (Fore.RED + "[ERROR] - No se pudo cargar info()")
        virustotal = virustotal_api(ioc, typeioc="ip")
        abuseip = abuseip_api(ioc)

        print (Fore.LIGHTCYAN_EX + "\nInvestigacion realizada:")
        
        #Print: AbuseIP
        if abuseip[0] > 0:
          print (Fore.LIGHTCYAN_EX + "\n\n-->>AbuseIPDB:\n")
          print (Fore.WHITE + "Total de reportes maliciosos: " + Fore.RED + str(abuseip[0]))
          if len(abuseip[1]) > 1:
            print (Fore.WHITE + "\nCategorias:\n" + Fore.RED + abuseip[1])
        else:
          print (Fore.WHITE + "\nAbuseIP:"  + Fore.GREEN + "Clean")

        #Print VirusTotal
        if virustotal["VT_EVIL"]:
          """ Trabajo de la data exportada de VT """
          print (Fore.LIGHTCYAN_EX + "\n-->> Virustotal:")
          data = format_tag(virustotal["tags"], virustotal["category"])
          if len(data) > 0:
            print (Fore.WHITE + "TAGS:" + Fore.RED + data)
          print (Fore.WHITE + "\nAnalisis de AV:")
          
          for elements in virustotal["AV"]:
            print (Fore.WHITE + "  " + elements, ": " + Fore.RED + virustotal["AV"][elements])
        else:
          print (Fore.WHITE + "Virustotal: " + Fore.GREEN + "Clean")         
    elif type_indicator == '1': #Domain
      ioc = input(Fore.WHITE + "Target DomainName:\n--->"+Fore.GREEN)
      
      try:
        virustotal = virustotal_api(ioc, typeioc="domain")
      except:
        print (Fore.RED + "[ERROR] - No se pudo analisar el Dominio en Virustotal"+Fore.WHITE)
        continue
      
      #Print VirusTotal
      if virustotal["VT_EVIL"]:
        """ Trabajo de la data exportada de VT """
        print (Fore.LIGHTCYAN_EX + "\n-->> Virustotal:")
        data = format_tag(virustotal["tags"], virustotal["category"])
        if len(data) > 0:
          print (Fore.WHITE + "TAGS:" + Fore.RED + data)
        print (Fore.WHITE + "\nAnalisis de AV:")
        
        for elements in virustotal["AV"]:
          print (Fore.WHITE + "  " + elements, ": " + Fore.RED + virustotal["AV"][elements])
      else:
        print (Fore.WHITE + "Virustotal: " + Fore.GREEN + "Clean")
      # elif type_indicator == '2': #Hash
      #   ioc = input(Fore.WHITE + "Target Hash:\n--->"+Fore.GREEN)
    else:
      print (Fore.RED + "[ERROR] - Tipo de IOC desconocido")
    print (input(Fore.LIGHTCYAN_EX+"\nPrecione enter para continuar..."+Fore.WHITE))
  
#Ejecucion Principal
if __name__== "__main__":
  main(menu)
