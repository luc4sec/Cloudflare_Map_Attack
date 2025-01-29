function connectWebSocket() {
    var ws_url = 'ws://' + window.location.hostname + ':8083/websocket';
    console.log("Connecting to WebSocket:", ws_url);
    
    var ws = new WebSocket(ws_url);
    
    ws.onopen = function() {
        console.log("WebSocket connection established");
    };
    
    ws.onerror = function(error) {
        console.error("WebSocket error:", error);
    };
    
    ws.onclose = function() {
        console.log("WebSocket connection closed");
        // Tentar reconectar após 5 segundos
        setTimeout(connectWebSocket, 5000);
    };

    ws.onmessage = function(event) {
        try {
            var data = JSON.parse(event.data);
            console.log("Received data:", data);
            // Aqui você pode adicionar o código para processar os dados recebidos
            // e atualizar o mapa
        } catch (e) {
            console.error("Error processing message:", e);
        }
    };

    return ws;
}

// Iniciar conexão quando o documento estiver pronto
document.addEventListener('DOMContentLoaded', function() {
    connectWebSocket();
});
