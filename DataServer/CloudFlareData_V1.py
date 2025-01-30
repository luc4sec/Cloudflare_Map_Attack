import datetime
import json
import time
import os
import pytz
import redis
import ssl
import random


import urllib3
# from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# load_dotenv()

import websocket
import requests
from tzlocal import get_localzone
import geoip2.database

CLOUDFLARE_API_KEY = os.environ['CLOUDFLARE_API_KEY']
CLOUDFLARE_EMAIL = os.environ['CLOUDFLARE_EMAIL']
CLOUDFLARE_ACCOUNT_ID = os.environ['CLOUDFLARE_ACCOUNT_ID']


redis_ip = 'map_redis'
redis_instance = None
redis_channel = 'attack-map-production'
version = 'CloudFlare Data V1'
local_tz = get_localzone()

# Inicializa o leitor de GeoIP
reader = geoip2.database.Reader('GeoLite2-City.mmdb')

event_count = 1
ips_tracked = {}
ports = {}
ip_to_code = {}
countries_to_code = {}
countries_tracked = {}
continent_tracked = {}

# Color Codes for Attack Map
service_rgb = {
    'FTP': '#ff0000',
    'SSH': '#ff8000',
    'TELNET': '#ffff00',
    'EMAIL': '#80ff00',
    'SQL': '#00ff00',
    'DNS': '#00ff80',
    'HTTP': '#00ffff',
    'HTTPS': '#0080ff',
    'VNC': '#0000ff',
    'SNMP': '#8000ff',
    'SMB': '#bf00ff',
    'MEDICAL': '#ff00ff',
    'RDP': '#ff0060',
    'SIP': '#ffccff',
    'ADB': '#ffcccc',
    'OTHER': '#ffffff'
}

def connect_redis(redis_ip):
    r = redis.StrictRedis(host=redis_ip, port=6379, db=0)
    return r

def push_honeypot_stats(honeypot_stats):
    redis_instance = connect_redis(redis_ip)
    tmp = json.dumps(honeypot_stats)
    redis_instance.publish(redis_channel, tmp)

def get_cloudflare_ws_url(zone_id):
    headers = {
        'X-Auth-Email': CLOUDFLARE_EMAIL,
        'X-Auth-Key': CLOUDFLARE_API_KEY,
        'Content-Type': 'application/json',
    }
    body = {
        "fields": "ClientIP,ClientRequestHost,ClientRequestMethod,ClientRequestURI,EdgeResponseStatus,EdgeStartTimestamp",
        "sample": 1,
        "filter": "{\"where\":{\"and\":[{\"key\":\"EdgeResponseStatus\",\"operator\":\"eq\",\"value\":403}]}}",
        "kind": "instant-logs"
    }
    try:
        res = requests.post(
            f'https://api.cloudflare.com/client/v4/zones/{zone_id}/logpush/edge/jobs',
            headers=headers,
            json=body,
            verify=False
        )
        
        response_json = res.json()
        
        if response_json['success'] and response_json['result']:
            print(f"[SUCCESS] WebSocket URL obtida para zona {zone_id}")
            return response_json['result']['destination_conf']
        else:
            error_msg = response_json.get('errors', [{'message': 'Unknown error'}])[0]['message']
            print(f"[ERROR] Falha ao obter WebSocket URL para zona {zone_id}: {error_msg}")
            return None
            
    except Exception as e:
        print(f"[ERROR] Exceção ao obter WebSocket URL para zona {zone_id}: {str(e)}")
        return None

def process_cloudflare_data(data):
    try:
        # print(f"[DEBUG] Processando dados do Cloudflare: {data}")
        
        # Extrair informações relevantes
        client_ip = data.get('ClientIP')
        host = data.get('ClientRequestHost', 'unknown')
        
        geo = reader.city(client_ip)
        
        # Debug das coordenadas
        # print(f"[DEBUG] Coordenadas: lat={geo.location.latitude}, long={geo.location.longitude}")

        # Garantir todos os campos necessários para o mapa
        color = random.choice(service_rgb)
        alert = {
            "type": "Traffic",
            "honeypot": "Cloudflare",
            "country": geo.country.name or "Unknown",
            "country_code": geo.country.iso_code or "XX",
            "iso_code": geo.country.iso_code or "XX",
            "continent_code": geo.continent.code or "XX",
            "latitude": float(geo.location.latitude or 0),  # Coordenadas da origem
            "longitude": float(geo.location.longitude or 0),
            "src_ip": client_ip,
            "dst_ip": host,
            "dst_port": 443,
            "src_port": 0,
            "protocol": "HTTPS",
            "event_time": datetime.datetime.now(pytz.UTC).strftime("%Y-%m-%d %H:%M:%S"),
            "color": color,
            "ip_rep": "Unknown",
            "dst_lat": -15.7801,  # Coordenadas do destino (Brasil)
            "dst_long": -47.9292,
            "dst_iso_code": "BR",
            "dst_country_name": "Brazil",
            "event_count": event_count,
            "ips_tracked": ips_tracked,
            "countries_tracked": countries_tracked,
            "continents_tracked": continent_tracked,
            "ip_to_code": ip_to_code,
            "country_to_code": countries_to_code
        }
        
        # print(f"[DEBUG] Alert processado com coordenadas: lat={alert['latitude']}, long={alert['longitude']}")
        return alert
    except Exception as e:
        print(f"[ERROR] Erro ao processar dados: {str(e)}")
        print(f"[ERROR] Dados recebidos: {data}")
        return None

def on_ws_close(ws, close_status_code, close_msg):
    print(f"[WARNING] WebSocket fechado: {close_status_code} - {close_msg}")
    retry_connection(ws)

def on_ws_error(ws, error):
    print(f"[ERROR] Erro no WebSocket: {error}")
    retry_connection(ws)

def retry_connection(ws, max_retries=5, initial_delay=1):
    """Tenta reconectar ao WebSocket com backoff exponencial"""
    retry_count = 0
    delay = initial_delay
    
    while retry_count < max_retries:
        try:
            print(f"[INFO] Tentativa de reconexão {retry_count + 1}/{max_retries} após {delay} segundos...")
            time.sleep(delay)
            ws.run_forever()
            return  # Se conseguir conectar, sai da função
        except Exception as e:
            print(f"[ERROR] Falha na reconexão: {e}")
            retry_count += 1
            delay *= 2  # Backoff exponencial
    
    print("[CRITICAL] Máximo de tentativas de reconexão atingido!")

def update_attack_data():
    zones = [
        '4ce6c6e752c7e7cb0a7d591af4f89ab9',
        '943b5c5011933841b755f17e4f6ace2b',
        '7098f3c602a9e334142111dc68fb3f92',
        '71da471b632d47942c9dcf73762e3254',
        '6eb4425e675970e22651fcf8d7ecba95',
        'b9b10f69a8c7ebd769fe40f8a2de8a05',
        '23208903b5eadcdf729b627ab13b22e8'
    ]
    websockets = []
    
    while True:
        try:
            for zone in zones:
                ws_url = get_cloudflare_ws_url(zone)
                if ws_url:
                    try:
                        ws = websocket.WebSocketApp(
                            ws_url,
                            on_message=on_ws_message,
                            on_error=on_ws_error,
                            on_close=on_ws_close,
                            on_open=lambda ws: print(f"[SUCCESS] WebSocket conectado para zonas")
                        )
                        websockets.append(ws)
                    except Exception as e:
                        print(f"[ERROR] Falha ao conectar WebSocket para zona {zone}: {str(e)}")
                        continue

            # Iniciar todas as conexões WebSocket em threads separadas
            import threading
            threads = []

            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            for ws in websockets:
                thread = threading.Thread(target=ws.run_forever, kwargs={"sslopt": {"context": ssl_context}})
                thread.daemon = True
                thread.start()
                threads.append(thread)
            
            # Monitorar threads e reconectar se necessário
            while True:
                for thread in threads:
                    if not thread.is_alive():
                        print("[WARNING] Thread WebSocket morta, reiniciando...")
                        thread.start()
                time.sleep(5)  # Verifica as threads a cada 5 segundos
                
        except Exception as e:
            print(f"[ERROR] Erro no loop principal: {e}")
            time.sleep(10)  # Espera 10 segundos antes de tentar novamente
            continue

def on_ws_message(ws, message):
    try:
        # print(f"[DEBUG] Mensagem WebSocket recebida: {message}...") #{message[:200]}
        data = json.loads(message)
        processed_data = process_cloudflare_data(data)
        if processed_data:
            # print("[DEBUG] Enviando dados processados para push()")
            push([processed_data])
        else:
            print("[WARNING] Dados processados retornaram None")
    except json.JSONDecodeError as e:
        print(f"[ERROR] Erro ao decodificar JSON: {e}")
    except Exception as e:
        print(f"[ERROR] Erro ao receber mensagem: {str(e)}")

def push(alerts):
    try:
        # print(f"[DEBUG] Iniciando push para {len(alerts)} alertas")
        redis_instance = connect_redis(redis_ip)

        for alert in alerts:
            if not alert:
                continue

            # Atualizar contadores antes de enviar
            ips_tracked[alert["src_ip"]] = ips_tracked.get(alert["src_ip"], 0) + 1
            countries_tracked[alert["country"]] = countries_tracked.get(alert["country"], 0) + 1
            ip_to_code[alert["src_ip"]] = alert["iso_code"]
            countries_to_code[alert["country"]] = alert["country_code"]

            try:
                # print(f"[DEBUG] Enviando para Redis: {json.dumps(alert)[:200]}...")
                redis_instance.publish(redis_channel, json.dumps(alert))
                # print("[DEBUG] Dados enviados com sucesso")
            except Exception as e:
                print(f"[ERROR] Erro ao publicar no Redis: {e}")

    except Exception as e:
        print(f"[ERROR] Erro no push: {str(e)}")

# No início do arquivo, após as importações
output_text = "DISABLED"  # ou "ENABLED" se quiser ver o output

if __name__ == '__main__':
    print(version)
    try:
        update_attack_data()        
    except KeyboardInterrupt:
        print('\nSHUTTING DOWN')
        exit()
