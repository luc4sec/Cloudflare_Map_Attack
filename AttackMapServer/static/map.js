var base = L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '<a href="https://www.openstreetmap.org/copyright">&copy OpenStreetMap</a> <a href="https://carto.com/attributions">&copy CARTO</a>',
        detectRetina: true,
        subdomains: 'abcd',
        minZoom: 2,
        maxZoom: 8,
        tileSize: 256
});

var map = L.map('map', {
    layers: [base],
    tap: false, // ref https://github.com/Leaflet/Leaflet/issues/7255
    center: new L.LatLng(20, 10),
    trackResize: true,
    worldCopyJump: true,
    minZoom: 2,
    maxZoom: 8,
    zoom: 3,
    zoomSnap: 0.1,
    zoomDelta: 0.1,
    fullscreenControl: true,
    fullscreenControlOptions: {
        title:"Fullscreen Mode",
        titleCancel:"Exit Fullscreen Mode"
    }
});

// Append <svg> to map
var svg = d3.select(map.getPanes().overlayPane).append("svg")
.attr("class", "leaflet-zoom-animated")
.attr("width", window.innerWidth)
.attr("height", window.innerHeight);

function translateSVG() {
    var viewBoxLeft = document.querySelector("svg.leaflet-zoom-animated").viewBox.animVal.x;
    var viewBoxTop = document.querySelector("svg.leaflet-zoom-animated").viewBox.animVal.y;

    // Resizing width and height in case of window resize
    svg.attr("width", window.innerWidth);
    svg.attr("height", window.innerHeight);

    // Adding the ViewBox attribute to our SVG to contain it
    svg.attr("viewBox", function () {
        return "" + viewBoxLeft + " " + viewBoxTop + " "  + window.innerWidth + " " + window.innerHeight;
    });

    // Adding the style attribute to our SVG to translate it
    svg.attr("style", function () {
        return "transform: translate3d(" + viewBoxLeft + "px, " + viewBoxTop + "px, 0px);";
    });
}

function update() {
    translateSVG();
    // additional stuff
}

// Re-draw on reset, this keeps the markers where they should be on reset/zoom
map.on("moveend", update);

function calcMidpoint(x1, y1, x2, y2, bend) {
    if(y2<y1 && x2<x1) {
        var tmpy = y2;
        var tmpx = x2;
        x2 = x1;
        y2 = y1;
        x1 = tmpx;
        y1 = tmpy;
    }
    else if(y2<y1) {
        y1 = y2 + (y2=y1, 0);
    }
    else if(x2<x1) {
        x1 = x2 + (x2=x1, 0);
    }

    var radian = Math.atan(-((y2-y1)/(x2-x1)));
    var r = Math.sqrt(x2-x1) + Math.sqrt(y2-y1);
    var m1 = (x1+x2)/2;
    var m2 = (y1+y2)/2;

    var min = 2.5, max = 7.5;
    //var min = 1, max = 7;
    var arcIntensity = parseFloat((Math.random() * (max - min) + min).toFixed(2));

    if (bend === true) {
        var a = Math.floor(m1 - r * arcIntensity * Math.sin(radian));
        var b = Math.floor(m2 - r * arcIntensity * Math.cos(radian));
    } else {
        var a = Math.floor(m1 + r * arcIntensity * Math.sin(radian));
        var b = Math.floor(m2 + r * arcIntensity * Math.cos(radian));
    }

    return {"x":a, "y":b};
}

function translateAlong(path) {
    var l = path.getTotalLength();
    return function(i) {
        return function(t) {
            // Put in try/catch because sometimes floating point is stupid..
            try {
            var p = path.getPointAtLength(t*l);
            return "translate(" + p.x + "," + p.y + ")";
            } catch(err){
            console.log("Caught exception.");
            return "ERROR";
            }
        }
    }
}

function handleParticle(color, srcPoint) {
    var i = 0;
    var x = srcPoint['x'];
    var y = srcPoint['y'];

    svg.append('circle')
        .attr('cx', x)
        .attr('cy', y)
        .attr('r', 0)
        .style('fill', 'none')
        .style('stroke', color)
        .style('stroke-opacity', 1)
        .style('stroke-width', 3)
        .transition()
        .duration(700)
        .ease(d3.easeCircleIn)
        // Circle radius source animation
        .attr('r', 50)
        .style('stroke-opacity', 0)
        .remove();
}

function handleTraffic(color, srcPoint, hqPoint) {
    var fromX = srcPoint['x'];
    var fromY = srcPoint['y'];
    var toX = hqPoint['x'];
    var toY = hqPoint['y'];
    var bendArray = [true, false];
    var bend = bendArray[Math.floor(Math.random() * bendArray.length)];

    var lineData = [srcPoint, calcMidpoint(fromX, fromY, toX, toY, bend), hqPoint]
    var lineFunction = d3.line()
        .curve(d3.curveBasis)
        .x(function(d) {return d.x;})
        .y(function(d) {return d.y;});

    var lineGraph = svg.append('path')
            .attr('d', lineFunction(lineData))
            .attr('opacity', 0.8)
            .attr('stroke', color)
            .attr('stroke-width', 2)
            .attr('fill', 'none');

    var circleRadius = 6

    // Circle follows the line
    var dot = svg.append('circle')
        .attr('r', circleRadius)
        .attr('fill', color)
        .transition()
        .duration(700)
        .ease(d3.easeCircleIn)
        .attrTween('transform', translateAlong(lineGraph.node()))
        .on('end', function() {
            d3.select(this)
                .attr('fill', 'none')
                .attr('stroke', color)
                .attr('stroke-width', 3)
                .transition()
                .duration(700)
                .ease(d3.easeCircleIn)
                // Circle radius destination animation
                .attr('r', 50)
                .style('stroke-opacity', 0)
                .remove();
    });

    var length = lineGraph.node().getTotalLength();
    lineGraph.attr('stroke-dasharray', length + ' ' + length)
        .attr('stroke-dashoffset', length)
        .transition()
        .duration(700)
        .ease(d3.easeCircleIn)
        .attr('stroke-dashoffset', 0)
        .on('end', function() {
            d3.select(this)
                .transition()
                .duration(700)
                .style('opacity', 0)
                .remove();
    });
}


var circles = new L.LayerGroup();
map.addLayer(circles);
var markers = new L.LayerGroup();
map.addLayer(markers);

var circlesObject = {};
function addCircle(country, iso_code, src_ip, ip_rep, color, srcLatLng) {
    circleCount = circles.getLayers().length;
    circleArray = circles.getLayers();

    // Only allow 100 circles to be on the map at a time
    if (circleCount >= 100) {
        circles.removeLayer(circleArray[0]);
        circlesObject = {};
    }

    var key = srcLatLng.lat + "," + srcLatLng.lng;
    // Only draw circle if its coordinates are not already present in circlesObject
    if (!circlesObject[key]) {
        circlesObject[key] = L.circle(srcLatLng, 50000, {
            color: color,
            fillColor: color,
            fillOpacity: 0.2
        }).bindPopup(
//            "<h4><b><u>Source Info</u></b></h4>" +
            "<img src='flags/" + iso_code + ".svg' width='26' height='18'>" + "<b> " + country + "<br>" +
            "<b>" + src_ip + "<br>" +
            "<b>" + ip_rep
        ).addTo(circles);
    }
}

var markersObject = {};
function addMarker(dst_country_name, dst_iso_code, dst_ip, tpot_hostname, dstLatLng) {
    markerCount = markers.getLayers().length;
    markerArray = markers.getLayers();

    // Only allow 50 markers to be on the map at a time
    if (markerCount >= 50) {
        markers.removeLayer(markerArray[0]);
        markersObject = {};
    }

    var key = dstLatLng.lat + "," + dstLatLng.lng;
    // Only draw marker if its coordinates are not already present in markersObject
    if (!markersObject[key]) {
        markersObject[key] = L.marker(dstLatLng, {
            icon: L.icon({
                // svg color #E20074
                iconUrl: 'static/images/marker.svg',
                iconSize: [48, 48],
                iconAnchor: [24, 48],
                popupAnchor: [0, -48]
            }),
        }).bindPopup(
//            "<h4><b><u>T-Pot Info</u></b></h4>" +
            "<img src='flags/" + dst_iso_code + ".svg' width='26' height='18'>" + "<b> " + dst_country_name + "<br>" +
            "<b>" + dst_ip + "<br>" +
            "<b>" + tpot_hostname
        ).addTo(markers);
    }
}

function prependAttackRow(id, args) {
    var tr = document.createElement('tr');
    count = args.length;

    for (var i = 0; i < count; i++) {
        var td = document.createElement('td');
        if (args[i] === args[2]) {
        var path = 'flags/' + args[i] + '.svg';
        var img = document.createElement('img');
        img.src = path;
        td.appendChild(img);
        tr.appendChild(td);
        } else {
        var textNode = document.createTextNode(args[i]);
        td.appendChild(textNode);
        tr.appendChild(td);
        }
    }

    var element = document.getElementById(id);
    var rowCount = element.rows.length;

    // Only allow 50 rows
    if (rowCount >= 50) {
        element.deleteRow(rowCount -1);
    }

    element.insertBefore(tr, element.firstChild);
}

function redrawCountIP(hashID, id, countList, codeDict) {
    $(hashID).empty();
    var element = document.getElementById(id);

    // Sort ips greatest to least
    // Create items array from dict
    var items = Object.keys(countList[0]).map(function(key) {
        return [key, countList[0][key]];
    });
    // Sort the array based on the second element
    items.sort(function(first, second) {
        return second[1] - first[1];
    });
    // Create new array with only the first 50 items
    var sortedItems = items.slice(0, 50);
    var itemsLength = sortedItems.length;

    for (var i = 0; i < itemsLength; i++) {
        tr = document.createElement('tr');
        td1 = document.createElement('td');
        td2 = document.createElement('td');
        td3 = document.createElement('td');
        var key = sortedItems[i][0];
        value = sortedItems[i][1];
        var keyNode = document.createTextNode(key);
        var valueNode = document.createTextNode(value);
        var path = 'flags/' + codeDict[key] + '.svg';
        var img = document.createElement('img');
        img.src = path;
        td1.appendChild(valueNode);
        td2.appendChild(img);
        td3.appendChild(keyNode);
        tr.appendChild(td1);
        tr.appendChild(td2);
        tr.appendChild(td3);
        element.appendChild(tr);
    }
}

function redrawCountIP2(hashID, id, countList, codeDict) {
    $(hashID).empty();
    var element = document.getElementById(id);

    // Sort ips greatest to least
    // Create items array from dict
    var items = Object.keys(countList[0]).map(function(key) {
        return [key, countList[0][key]];
    });
    // Sort the array based on the second element
    items.sort(function(first, second) {
        return second[1] - first[1];
    });
    // Create new array with only the first 50 items
    var sortedItems = items.slice(0, 50);
    var itemsLength = sortedItems.length;

    for (var i = 0; i < itemsLength; i++) {
        tr = document.createElement('tr');
        td1 = document.createElement('td');
        td2 = document.createElement('td');
        td3 = document.createElement('td');
        var key = sortedItems[i][0];
        value = sortedItems[i][1];
        var keyNode = document.createTextNode(key);
        var valueNode = document.createTextNode(value);
        var path = 'flags/' + codeDict[key] + '.svg';
        var img = document.createElement('img');
        img.src = path;
        td1.appendChild(valueNode);
        td2.appendChild(img);
        td3.appendChild(keyNode);
        tr.appendChild(td1);
        tr.appendChild(td2);
        tr.appendChild(td3);
        element.appendChild(tr);
    }
}

// Adicionar novo objeto para rastrear hosts
var hosts_tracked = {};

function handleLegend(msg) {
    var eventTime = luxon.DateTime.fromFormat(msg.event_time, 'yyyy-MM-dd HH:mm:ss', { zone: 'utc' })
        .setZone(Intl.DateTimeFormat().resolvedOptions().timeZone);
    var ipCountList = [msg.ips_tracked, msg.iso_code];
    var countryCountList = [msg.countries_tracked, msg.iso_code];
    var hostCountList = [msg.hosts_tracked];
    
    // Lista modificada sem o protocolo
    var attackList = [
        eventTime.toFormat('yyyy-MM-dd HH:mm:ss'),
        msg.src_ip,
        msg.iso_code,
        msg.country,
        msg.dst_ip  // Trocado de honeypot para host
    ];
    
    redrawCountIP('#ip-tracking', 'ip-tracking', ipCountList, msg.ip_to_code);
    redrawCountIP2('#country-tracking', 'country-tracking', countryCountList, msg.country_to_code);
    redrawHosts('#host-tracking', 'host-tracking', hostCountList);
    prependAttackRow('attack-tracking', attackList);
}

// Nova função para desenhar a tabela de hosts
function redrawHosts(hashID, id, countList) {
    $(hashID).empty();
    var element = document.getElementById(id);

    var items = Object.keys(countList[0]).map(function(key) {
        return [key, countList[0][key]];
    });
    
    items.sort(function(first, second) {
        return second[1] - first[1];
    });
    
    var sortedItems = items.slice(0, 50);
    
    for (var i = 0; i < sortedItems.length; i++) {
        var tr = document.createElement('tr');
        var td1 = document.createElement('td');
        var td2 = document.createElement('td');
        
        var value = document.createTextNode(sortedItems[i][1]);
        var host = document.createTextNode(sortedItems[i][0]);
        
        td1.appendChild(value);
        td2.appendChild(host);
        tr.appendChild(td1);
        tr.appendChild(td2);
        element.appendChild(tr);
    }
}

function handleStats(msg) {
    const last = ["last_1m", "last_1h", "last_24h"]
    last.forEach(function(i) {
        document.getElementById(i).innerHTML = msg[i];
    });
};

// WEBSOCKET STUFF

const messageHandlers = {
  Traffic: (msg) => {
    var srcLatLng = new L.LatLng(msg.src_lat, msg.src_long);
    var dstLatLng = new L.LatLng(msg.dst_lat, msg.dst_long);
    var dstPoint = map.latLngToLayerPoint(dstLatLng);
    var srcPoint = map.latLngToLayerPoint(srcLatLng);

    Promise.all([
        addCircle(msg.country, msg.iso_code, msg.src_ip, msg.ip_rep, msg.color, srcLatLng),
        addMarker(msg.dst_country_name, msg.dst_iso_code, msg.dst_ip, msg.tpot_hostname, dstLatLng),
        handleLegend(msg),
        handleParticle(msg.color, srcPoint),
        handleTraffic(msg.color, srcPoint, dstPoint, srcLatLng)
    ]).then(() => {
        // All operations have completed
    });
  },
  Stats: (msg) => {
    handleStats(msg);
  },
};

// For use within T-Pot:
//   - Access AttackMap via T-Pot's WebUI (https://<your T-Pot IP>:64297/map/)
//   - For Proxy_Pass to work we need to use wss:// instead of ws://
function connectWebSocket() {
    // Usar ws:// para HTTP e wss:// para HTTPS
    var protocol = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
    var ws_url = protocol + window.location.hostname + ':64299/websocket';
    console.log("Connecting to WebSocket:", ws_url);
    
    var ws = new WebSocket(ws_url);
    
    ws.onopen = function() {
        console.log("[INFO] WebSocket connection established");
    };
    
    ws.onerror = function(error) {
        console.error("[ERROR] WebSocket error:", error);
    };
    
    ws.onclose = function() {
        console.log("[INFO] WebSocket connection closed");
        // Tentar reconectar após 5 segundos
        setTimeout(connectWebSocket, 5000);
    };

    // Adicionar handler de mensagens do WebSocket
    ws.onmessage = function(event) {
        processMessage(event.data);
    };

    return ws;
}

function processMessage(data) {
    try {
        const msg = JSON.parse(data);
        
        // Atualizar contagem de hosts
        if (msg.dst_ip) {
            hosts_tracked[msg.dst_ip] = (hosts_tracked[msg.dst_ip] || 0) + 1;
            msg.hosts_tracked = hosts_tracked;
        }
        
        if (msg.type === 'Traffic') {
            // console.log("[DEBUG] Processando dados do tráfego:", msg);
            
            // Criar coordenadas usando os campos corretos
            var srcLatLng = new L.LatLng(msg.latitude, msg.longitude);  // Mudado de src_lat/src_long
            var dstLatLng = new L.LatLng(msg.dst_lat, msg.dst_long);
            
            // Converter coordenadas para pontos no mapa
            var dstPoint = map.latLngToLayerPoint(dstLatLng);
            var srcPoint = map.latLngToLayerPoint(srcLatLng);

            // console.log("[DEBUG] Coordenadas fonte:", srcLatLng);
            // console.log("[DEBUG] Coordenadas destino:", dstLatLng);

            // Adicionar elementos visuais ao mapa
            Promise.all([
                addCircle(msg.country, msg.iso_code, msg.src_ip, msg.ip_rep, msg.color, srcLatLng),
                addMarker(msg.dst_country_name, msg.dst_iso_code, msg.dst_ip, msg.dst_ip, dstLatLng),  // Usando dst_ip como hostname
                handleLegend(msg),
                handleParticle(msg.color, srcPoint),
                handleTraffic(msg.color, srcPoint, dstPoint)
            ]).then(() => {
                // console.log("[DEBUG] Elementos visuais adicionados com sucesso");
            });
        }
    } catch (error) {
        console.error("[ERROR] Erro ao processar mensagem:", error);
    }
}

connectWebSocket();
