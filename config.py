from colorama import Fore, init
init()

version = "v2.3"

#TOKEN API CONFIG
token_virustotal = "50015dd4014a8889b3ef9dba5b0e720cdd1ed1d11d0f5fbb99b6164f82614959"
token_abuseip = "3e3fe339b6af4afd4105a45f1472fcc8f4952770d1755d9ee2e4aff930a5e648b6f29b2078c452f7"
token_ipinfo = "4bad97d0bd0e8e"


menu = (Fore.WHITE + '''
________________________________________________________________
   .-._                                                   _,-, |
    `._`-._                                           _,-'_,'  |
       `._ `-._                                   _,-' _,'     |
          `._  `-._        __.----.__        _,-'   _,'        |
             `._   `#==="""          """===#'    _,'           |
  ___________ `._/)  ._                   _.    (              |
 /\          \.  )*'   \___         ____/    *(                |
| |'''+Fore.LIGHTCYAN_EX+'''Evil'''+Fore.WHITE+'''       |.  #  .==..__""     ""__..=.   #                |
\_| '''+Fore.LIGHTCYAN_EX+'''Origin'''+Fore.WHITE+'''    |.  #   "._('''+Fore.RED+'''#'''+Fore.WHITE+''')>       <('''+Fore.RED+'''#'''+Fore.WHITE+''')_."   #                |
""|  '''+Fore.LIGHTCYAN_EX+'''Deteccion'''+Fore.WHITE+'''|."""""""""""""""""""""""""""""""""""""""""""""""|
  |   '''+Fore.LIGHTCYAN_EX+f'''{version}'''+Fore.WHITE+'''    |.                                               |
  |   ________|_____                                           |
  |  / By:         /.                                          |
  \_/_@StaryDarkz_/.                                           |
_______________________________________________________________|

Tipo de Indicador:

[0]-IP
[1]-DomainName
\n--->'''+Fore.GREEN)