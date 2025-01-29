#!/usr/bin/python3

"""
Original code (tornado based) by Matthew May - mcmay.web@gmail.com
Adjusted code for asyncio, aiohttp and redis (asynchronous support) by t3chn0m4g3
"""

import asyncio
import json

import redis.asyncio as redis
from aiohttp import web

# redis_url = 'redis://10.1.10.69:6379'
redis_url = 'redis://map_redis:6379'
web_port = 8083
version = 'Attack Map Server 3 (CloudFlare Edition)'

async def redis_subscriber(websockets):
    while True:
        try:
            print("[DEBUG] Conectando ao Redis...")
            r = redis.Redis.from_url(redis_url, decode_responses=True)
            pubsub = r.pubsub()
            channel = "attack-map-production"
            await pubsub.subscribe(channel)
            print(f"[DEBUG] Inscrito no canal Redis: {channel}")
            
            while True:
                message = await pubsub.get_message(ignore_subscribe_messages=True)
                if message:
                    try:
                        data = message['data']
                        # print(f"[DEBUG] Mensagem Redis recebida: {data[:200]}...")
                        
                        # Garantir que os dados sejam JSON válido
                        if isinstance(data, str):
                            json_data = data
                            # Validar se é JSON válido
                            json.loads(data)
                        else:
                            json_data = json.dumps(data)
                        
                        if len(websockets) > 0:
                            # print(f"[DEBUG] Enviando para {len(websockets)} clientes WebSocket")
                            await asyncio.gather(*[ws.send_str(json_data) for ws in websockets])
                            # print("[DEBUG] Dados enviados com sucesso")
                        else:
                            print("[WARNING] Nenhum cliente WebSocket conectado")
                    except Exception as e:
                        print(f"[ERROR] Erro ao processar mensagem: {e}")
                await asyncio.sleep(0.1)
        except Exception as e:
            print(f"[ERROR] Erro na conexão Redis: {e}")
            await asyncio.sleep(5)

async def my_websocket_handler(request):
    ws = web.WebSocketResponse(heartbeat=30)  # Adiciona heartbeat para manter conexão
    await ws.prepare(request)
    
    print(f"[DEBUG] Nova conexão WebSocket de {request.remote}")
    request.app['websockets'].append(ws)
    print(f"[INFO] Clientes WebSocket ativos: {len(request.app['websockets'])}")

    try:
        async for msg in ws:
            if msg.type == web.WSMsgType.TEXT:
                # print(f"[DEBUG] Mensagem recebida do cliente: {msg.data[:200]}")
                await ws.send_str(msg.data)
            elif msg.type == web.WSMsgType.ERROR:
                print(f"[ERROR] Erro WebSocket de {request.remote}: {ws.exception()}")
    finally:
        request.app['websockets'].remove(ws)
        print(f"[INFO] Cliente {request.remote} desconectado. Clientes ativos: {len(request.app['websockets'])}")
    return ws

async def my_index_handler(request):
    return web.FileResponse('index.html')

async def start_background_tasks(app):
    app['websockets'] = []
    app['redis_subscriber'] = asyncio.create_task(redis_subscriber(app['websockets']))

async def cleanup_background_tasks(app):
    app['redis_subscriber'].cancel()
    await app['redis_subscriber']

async def make_webapp():
    app = web.Application()
    
    # Inicializar a lista de websockets
    app['websockets'] = []
    
    # Configurar CORS e cabeçalhos de segurança
    async def security_middleware(app, handler):
        async def middleware_handler(request):
            response = await handler(request)
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            return response
        return middleware_handler

    # Adicionar middleware e rotas
    app.middlewares.append(security_middleware)
    app.router.add_routes([
        web.get('/', my_index_handler),
        web.get('/websocket', my_websocket_handler),
        web.static('/static/', 'static'),
        web.static('/images/', 'static/images'),
        web.static('/flags/', 'static/flags')
    ])

    # Configurar eventos de inicialização e limpeza
    app.on_startup.append(start_background_tasks)
    app.on_cleanup.append(cleanup_background_tasks)

    return app


if __name__ == '__main__':
    print(version)
    try:
        web.run_app(make_webapp(), port=web_port, ssl_context=None)    
    except KeyboardInterrupt:
        print('\nSHUTTING DOWN')
        exit()
# if __name__ == '__main__':
#     print(version)
#       # Desabilita SSL por enquanto
