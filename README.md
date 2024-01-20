# Evil Origin Detection
![](https://github.com/starydarkz/EvilOriginDetection/blob/main/images/menu.png)


Herramienta capaz de analizar posibles IOC para encontrar la maldad reportada en diferentes fuentes de Threat Intellence y mostrar un resumen elegante desde la terminal, o un informe detallado en pdf/html.

Actualmente es capaz de analizar:
- Direcciones IPv4
- Dominios

## Requisitos:
1. Descargar repositorio desde la web o mediante git clone:
```bash
git clone https://github.com/starydarkz/evilorigindetection.git
```
2. Tener instalado Python3
3. Instalar las dependencias necesarias usando el archivo requeriments:
```bash
cd EvilOriginDetection
pip3 install -r requeriments.txt
```

## Configuracion

### Configuracion de TOKENS

Para configurar tus propios TOKEN de las APIS integradas, puedes remplazar el TOKEN por defecto. Se recomienda usar vuestro token personal, ya que los que vienen por defecto son gratis, publicos y limitados.

```python
token_virustotal = "-->> Poner tu TOKEN AQUI <<--"
token_abuseip = "-->> Poner tu TOKEN AQUI <<--"
ipinfo_token = "-->> Poner tu TOKEN AQUI <<--"
```



## Uso
```bash
python3 eod.py
```
![](https://github.com/starydarkz/EvilOriginDetection/blob/main/images/menu.png)
![](https://github.com/starydarkz/EvilOriginDetection/blob/main/images/resultado.png)
