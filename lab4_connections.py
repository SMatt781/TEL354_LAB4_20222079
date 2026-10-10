"""Conexiones proactivas del laboratorio: permisos, ruta y reglas por servicio.

No ejecuta operaciones de red al importar el módulo. Solo crea reglas cuando
el administrador elige Crear en el menú. REST se alcanza por túnel SSH local.
"""
import asyncio
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import time
import uuid

import requests

STATE = Path(__file__).with_name("lab4_conexiones.json")
MANUAL_ROUTE = Path(__file__).with_name("ruta_manual_vnrt.json")


def is_authorized(student, server, service, courses):
    return any(
        c.state.upper() == "ACTIVE" and student.name in c.students
        and any(
            entry["name"].casefold() == server.name.casefold()
            and service.name.casefold() in [s.casefold() for s in entry["allowed_services"]]
            for entry in c.servers
        )
        for c in courses
    )


def normalize_route(route):
    """Admite OFPort serializado como número o como objeto de Floodlight 1.2."""
    if not isinstance(route, list):
        raise ValueError("Respuesta de ruta inesperada; no se instalaron reglas.")
    result = []
    for point in route:
        if not isinstance(point, dict) or "switch" not in point or "port" not in point:
            raise ValueError("Punto de ruta sin switch o puerto.")
        port = point["port"]
        if isinstance(port, dict):
            port = port.get("portNumber")
        try:
            port = int(port)
        except (ValueError, TypeError):
            raise ValueError("Puerto de ruta inválido; no se instalaron reglas.") from None
        if port <= 0 or port >= 0xffffff00:
            raise ValueError("La ruta contiene un puerto reservado o inválido.")
        result.append({"switch": point["switch"], "port": port})
    return result


def route_hops(route):
    """Floodlight devuelve pares (entrada, salida) por cada switch."""
    if not isinstance(route, list) or not route or len(route) % 2:
        raise ValueError("No hay una ruta válida. Revisar los enlaces de Floodlight.")
    route = normalize_route(route)
    hops = []
    for i in range(0, len(route), 2):
        a, b = route[i:i + 2]
        if a["switch"] != b["switch"] or int(a["port"]) == int(b["port"]):
            raise ValueError("Formato de ruta inesperado: no se instalaron reglas.")
        hops.append((a["switch"], int(a["port"]), int(b["port"])))
    return hops


def build_route(route, student_mac, student_ip, server_mac, server_ip,
                protocol, port, handler):
    """Construye reglas sin enviarlas; protege L2/L3/L4 en ambos sentidos."""
    protocol = protocol.upper()
    if protocol not in ("TCP", "UDP") or not 1 <= int(port) <= 65535:
        raise ValueError("Servicio inválido; se admiten TCP y UDP.")
    for mac in (student_mac, server_mac):
        if not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac):
            raise ValueError("MAC inválida: debe tener seis grupos.")
    student_ip = str(ipaddress.IPv4Address(student_ip))
    server_ip = str(ipaddress.IPv4Address(server_ip))
    rules = []
    for index, (switch, in_port, out_port) in enumerate(route_hops(route)):
        for direction, smac, sip, dmac, dip, ingress, egress in (
            ("ida", student_mac, student_ip, server_mac, server_ip, in_port, out_port),
            ("retorno", server_mac, server_ip, student_mac, student_ip, out_port, in_port),
        ):
            base = {"switch": switch, "table": "0", "in_port": str(ingress),
                    "active": "true", "idle_timeout": "0", "hard_timeout": "0",
                    "actions": f"output={egress}"}
            transport = {**base, "name": f"lab4-{handler}-{index}-{direction}",
                        "priority": "300", "eth_type": "0x0800",
                        "eth_src": smac.lower(), "eth_dst": dmac.lower(),
                        "ipv4_src": sip + "/32", "ipv4_dst": dip + "/32",
                        "ip_proto": "6" if protocol == "TCP" else "17"}
            # Respuesta: el puerto del servicio es ORIGEN, no destino.
            field = protocol.lower() + ("_dst" if direction == "ida" else "_src")
            transport[field] = str(port)
            rules.append(transport)
            arp = {**base, "priority": "200", "eth_type": "0x0806",
                "eth_src": smac.lower(), "arp_spa": sip, "arp_tpa": dip}
            # Nombre compartido: no retirar ARP si otra conexión aún lo usa.
            digest = hashlib.sha256(json.dumps(arp, sort_keys=True).encode()).hexdigest()[:20]
            arp["name"] = "lab4-arp-" + digest
            rules.append(arp)
    return rules


class ConnectionManager:
    def __init__(self, state=STATE):
        self.url = os.environ.get("LAB4_CONTROLLER_URL", "http://127.0.0.1:8888").rstrip("/")
        self.state = Path(state)
        self.connections = json.loads(self.state.read_text(encoding="utf-8")) if self.state.exists() else {}

    def save(self):
        temp = self.state.with_suffix(".tmp")
        temp.write_text(json.dumps(self.connections, indent=2), encoding="utf-8")
        temp.replace(self.state)

    def api(self, method, path, **kwargs):
        response = requests.request(method, self.url + path, timeout=10, **kwargs)
        response.raise_for_status()
        data = response.json()
        if isinstance(data, dict) and any(key in data for key in ("error", "errors")):
            raise ValueError("Floodlight rechazó la petición: " + str(data))
        if isinstance(data, dict) and "status" in data:
            if re.search(r"error|invalid|failed", str(data["status"]), re.I):
                raise ValueError(str(data["status"]))
        return data

    def device(self, **params):
        rows = self.api("GET", "/wm/device/", params=params)
        if isinstance(rows, dict):
            rows = rows.get("devices", [])
        if len(rows) != 1:
            raise ValueError("Floodlight no conoce un dispositivo único para " + str(params)
                            + ". Genera tráfico desde ese host para que lo aprenda.")
        device = rows[0]
        points = [a for a in device.get("attachmentPoint", [])
                if not a.get("errorStatus") and int(a["port"]) > 0]
        if len(points) != 1 or len(device.get("ipv4", [])) != 1 or len(device.get("mac", [])) != 1:
            raise ValueError("Dispositivo sin ubicación, MAC o IPv4 única; no se instalaron reglas.")
        return device, points[0]

    def manual_route(self, source, destination):
        """Alternativa explícita para el cableado H1-H3 verificado, no descubrimiento LLDP."""
        if not MANUAL_ROUTE.exists():
            raise ValueError("Ruta vacía de Floodlight y sin archivo de ruta manual.")
        config = json.loads(MANUAL_ROUTE.read_text(encoding="utf-8"))
        if config.get("enabled") is not True:
            raise ValueError("Ruta manual deshabilitada; Floodlight no devolvió una ruta.")
        route = config["route"]
        hops = route_hops(route)
        endpoints = ((source["switchDPID"], int(source["port"])),
                    (destination["switchDPID"], int(destination["port"])))
        if endpoints != ((hops[0][0], hops[0][1]), (hops[-1][0], hops[-1][2])):
            raise ValueError("La ruta manual solo está definida para H1 (sw2/2) hacia H3 (sw3/2).")
        connected = self.api("GET", "/wm/core/controller/switches/json")
        dpids = {row["switchDPID"].lower() for row in connected}
        for switch, ingress, egress in hops:
            if switch.lower() not in dpids:
                raise ValueError("Switch de la ruta manual no conectado: " + switch)
            data = self.api("GET", f"/wm/core/switch/{switch}/port-desc/json")
            ports = {str(p["portNumber"]): p for p in data.get("portDesc", [])}
            for number in (ingress, egress):
                port = ports.get(str(number))
                expected = config["port_macs"].get(switch, {}).get(str(number))
                if not port or not expected or port["hardwareAddress"].lower() != expected.lower():
                    raise ValueError(f"Puerto/MAC distinto del cableado registrado: {switch}/{number}.")
                # OF1.3: config PORT_DOWN=1, NO_RECV=4, NO_FWD=32;
                # state LINK_DOWN=1, BLOCKED=2. LIVE=4 sí es válido.
                if int(port["config"], 0) & 37 or int(port["state"], 0) & 3:
                    raise ValueError(f"Puerto deshabilitado o bloqueado: {switch}/{number}.")
        return route

    async def send_rules(self, rules):
        # requests es bloqueante: se ejecuta en hilos para no bloquear asyncio.
        async def send(rule):
            return await asyncio.to_thread(self.api, "POST", "/wm/staticflowpusher/json", json=rule)
        return await asyncio.gather(*(send(r) for r in rules), return_exceptions=True)

    async def remove_names(self, names):
        async def remove(name):
            return await asyncio.to_thread(self.api, "DELETE", "/wm/staticflowpusher/json", json={"name": name})
        return await asyncio.gather(*(remove(n) for n in names), return_exceptions=True)

    @staticmethod
    def normalize(value):
        value = str(value).strip().lower()
        if value.endswith("/32"):
            value = value[:-3]
        if value.startswith("0x"):
            # Algunas versiones del serializador Match de Floodlight 1.2
            # duplican el prefijo: eth_type="0x0x800" (IPv4).
            digits = re.sub(r"^(?:0x)+", "", value)
            if re.fullmatch(r"[0-9a-f]+", digits):
                return str(int(digits, 16))
            # Un dato realmente inválido no coincide; no abortar la limpieza.
            return value
        return value

    def actual_present(self, rule):
        data = self.api("GET", f'/wm/core/switch/{rule["switch"]}/flow/json')
        flows = data.get("flows", []) if isinstance(data, dict) else []
        keys = [k for k in rule if k in ("in_port", "eth_type", "eth_src", "eth_dst",
                                    "ipv4_src", "ipv4_dst", "ip_proto", "tcp_dst",
                                    "tcp_src", "udp_dst", "udp_src", "arp_spa", "arp_tpa")]
        for flow in flows:
            match = flow.get("match", {})
            same = all(self.normalize(match.get(k, "")) == self.normalize(rule[k]) for k in keys)
            actions = json.dumps(flow.get("instructions", flow.get("actions", {})))
            output = rule["actions"].split("=", 1)[1]
            if same and int(flow.get("priority", -1)) == int(rule["priority"]):
                if re.search(r"output=" + re.escape(output) + r"(?!\d)", actions):
                    return True
        return False

    def verify(self, rules, present):
        # Confirmar el switch, no solo el catálogo del Static Flow Pusher.
        deadline = time.monotonic() + 8
        while True:
            if all(self.actual_present(rule) == present for rule in rules):
                return
            if time.monotonic() >= deadline:
                raise ValueError("El switch no confirmó el estado esperado. Revisar dump-flows.")
            time.sleep(0.4)

    def used_names(self, except_handler=None):
        return {r["name"] for h, c in self.connections.items() if h != except_handler for r in c["rules"]}

    def create(self, student, server, service, courses):
        if not is_authorized(student, server, service, courses):
            raise ValueError("DENEGADO: el alumno no tiene un curso ACTIVE con ese permiso.")
        if any(c["student"] == student.name and c["server"] == server.name and c["service"] == service.name
            for c in self.connections.values()):
            raise ValueError("La conexión ya está registrada; revisa su handler.")
        source, a = self.device(mac=student.mac)
        destination, b = self.device(ipv4=server.ip)
        path = f'/wm/topology/route/{a["switchDPID"]}/{a["port"]}/{b["switchDPID"]}/{b["port"]}/json'
        route = normalize_route(self.api("GET", path))
        route_source = "Floodlight (descubrimiento de topología)"
        if route == []:
            route = self.manual_route(a, b)
            route_source = "MANUAL: cableado H1-sw2-sw1-sw3-H3; LLDP no disponible"
            print("AVISO:", route_source)
        hops = route_hops(route)
        if hops[0][:2] != (a["switchDPID"], int(a["port"])) or (hops[-1][0], hops[-1][2]) != (b["switchDPID"], int(b["port"])):
            raise ValueError("La ruta no coincide con los extremos solicitados.")
        handler = "conn-" + uuid.uuid4().hex[:12]
        rules = build_route(route, student.mac, source["ipv4"][0], destination["mac"][0],
                            server.ip, service.protocol, service.port, handler)
        self.connections[handler] = {"student": student.name, "student_mac": student.mac,
                                    "server": server.name, "service": service.name,
                                    "route": route, "route_source": route_source,
                                    "rules": rules, "status": "pending"}
        self.save()  # Permite limpiar aun si Python se cierra durante la instalación.
        existing = self.used_names(except_handler=handler)
        new = [r for r in rules if r["name"] not in existing]
        try:
            results = asyncio.run(self.send_rules(new))
            if any(isinstance(x, Exception) for x in results):
                raise ValueError("Falló una inserción; se intentará retirar la conexión parcial.")
            self.verify(rules, True)
        except Exception:
            try:
                results = asyncio.run(self.remove_names([r["name"] for r in new]))
                if any(isinstance(x, Exception) for x in results):
                    raise ValueError("Limpieza pendiente")
                self.verify(new, False)
                del self.connections[handler]
            except Exception:
                self.connections[handler]["status"] = "cleanup_pending"
            self.save()
            raise
        self.connections[handler]["status"] = "active"
        self.save()
        return handler, rules

    def delete(self, handler, student, server, service, courses):
        connection = self.connections[handler]
        if not is_authorized(student, server, service, courses):
            raise ValueError("No autorizado según la política vigente. No se realizó el borrado.")
        used = self.used_names(except_handler=handler)
        rules = [r for r in connection["rules"] if r["name"] not in used]
        connection["status"] = "deleting"
        self.save()
        results = asyncio.run(self.remove_names([r["name"] for r in rules]))
        if any(isinstance(x, Exception) for x in results):
            raise ValueError("Borrado incompleto. Reintentar con el mismo handler.")
        self.verify(rules, False)
        del self.connections[handler]
        self.save()


def connections_menu(manager, students, servers, courses, select_item):
    while True:
        print("\nCONEXIONES\n1) Crear\n2) Listar\n3) Borrar por handler\n0) Volver")
        option = input("Opción: ").strip()
        if option == "0":
            return
        try:
            if option == "1":
                student = select_item(students)
                server = select_item(servers) if student else None
                service = select_item(server.services) if server else None
                if not service:
                    continue
                handler, rules = manager.create(student, server, service, courses)
                print("Conexión creada y verificada:", handler)
                print("Ruta:", manager.connections[handler]["route_source"])
                for rule in rules:
                    print(rule["switch"], rule["name"], rule["actions"])
            elif option == "2":
                if not manager.connections:
                    print("No hay conexiones registradas.")
                for handler, c in manager.connections.items():
                    print(handler, c["student"], "->", c["server"], c["service"], c["status"])
            elif option == "3":
                handler = input("Handler: ").strip()
                if handler not in manager.connections:
                    raise ValueError("Handler inexistente.")
                c = manager.connections[handler]
                student = next((s for s in students if s.name == c["student"] and s.mac == c["student_mac"]), None)
                server = next((s for s in servers if s.name == c["server"]), None)
                service = next((s for s in server.services if s.name == c["service"]), None) if server else None
                if not student or not service:
                    raise ValueError("Importa o recrea los datos del alumno y servidor de esta conexión.")
                manager.delete(handler, student, server, service, courses)
                print("Conexión eliminada y retirada de los switches:", handler)
            else:
                print("Opción inválida.")
        except (ValueError, requests.RequestException) as e:
            print("ERROR:", e)
            print("No se anunció una conexión exitosa. Revisa túnel, dispositivos y topología.")
