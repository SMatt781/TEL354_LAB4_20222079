import yaml
import json
import requests
import re
from pathlib import Path
from lab4_connections import ConnectionManager, connections_menu, build_route

class Student:
    # ADD YOUR CODE HERE
    def __init__(self, name, mac, code=None):
        self.name = name
        self.mac = mac.lower()
        self.code = code

class Service:
    # ADD YOUR CODE HERE
    def __init__(self, name, protocol, port):
        self.name = name
        self.protocol = protocol.upper()
        self.port = int(port)

class Server:
    # ADD YOUR CODE HERE
    def __init__(self, name, ip, services):
        self.name = name
        self.ip = ip

        # Convertimos cada servicio del YAML en un objeto.
        self.services = [
            Service(s["name"], s["protocol"], s["port"])
            for s in services
        ]


class Course:
    # ADD YOUR CODE HERE
    def __init__(self, name, state, students, servers, code):
        self.name = name
        self.state = state.upper()
        self.students = list(students)

        # Conservamos los servicios permitidos por servidor.
        self.servers = servers
        self.code = code


def load_data(filename):
    with open(filename, "r", encoding="utf-8") as file:
        data = yaml.safe_load(file)

    students = [
        Student(
            x["name"],
            x["mac"],
            x.get("code", f"ALU-{i:03d}")
        )
        for i, x in enumerate(data["students"], start=1)
    ]

    servers = [
        Server(x["name"], x["ip"], x["services"])
        for x in data["servers"]
    ]

    courses = [
        Course(
            x["name"],
            x["state"],
            x["students"],
            x["servers"],
            x["code"]
        )
        for x in data["courses"]
    ]

    return students, servers, courses


def get_attachment_point(controller_ip, mac):
    endpoint = '/wm/device/'
    url = 'http://' + controller_ip + ':8080' + endpoint
    response = requests.get(
        url,
        params={'mac': mac}
    )
    result, = response.json()
    attachment_points = result.get("attachmentPoint", [])

    if not attachment_points:
        return None, None

    attachment_point, = attachment_points
    return attachment_point["switchDPID"], attachment_point["port"]


def get_route(controller_ip, src_mac, dst_mac):
    src_sw_dpid, src_sw_port = get_attachment_point(controller_ip, src_mac)
    dst_sw_dpid, dst_sw_port = get_attachment_point(controller_ip, dst_mac)
    endpoint = f'/wm/topology/route/{src_sw_dpid}/{src_sw_port}/{dst_sw_dpid}/{dst_sw_port}/json'
    url = 'http://' + controller_ip + ':8080' + endpoint
    response = requests.get(url)
    return response.json()


def select_item(items):
    """Selecciona un objeto sin modificarlo."""
    if not items:
        print("No hay elementos disponibles.")
        return None

    for number, item in enumerate(items, start=1):
        code = getattr(item, "code", "")
        print(f"{number}) {code} {item.name}")

    try:
        number = int(input("Seleccione un número (0 para cancelar): "))
        if number == 0:
            return None
        if 1 <= number <= len(items):
            return items[number - 1]
    except ValueError:
        pass

    print("Selección inválida.")
    return None


def students_menu(students, courses):
    while True:
        print("\nALUMNOS")
        print("1) Crear")
        print("2) Listar / filtrar por curso")
        print("3) Mostrar detalles")
        print("0) Volver")
        option = input("Opción: ").strip()

        if option == "0":
            return

        elif option == "1":
            name = input("Nombre: ").strip()
            mac = input("MAC de la interfaz de datos: ").strip().lower()

            if not name:
                print("El nombre no puede estar vacío.")
                continue

            # Una MAC Ethernet tiene seis grupos hexadecimales.
            if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
                print("MAC inválida. Ejemplo: fa:16:3e:b5:e4:1f")
                continue

            if any(s.name.casefold() == name.casefold() for s in students):
                print("Ese alumno ya existe.")
                continue

            if any(s.mac.lower() == mac for s in students):
                print("Esa MAC ya está asociada a otro alumno.")
                continue

            code = f"ALU-{len(students) + 1:03d}"
            students.append(Student(name, mac, code))
            print(f"Alumno creado: {code} {name} — {mac}")

        elif option == "2":
            code = input(
                "Código del curso o Enter para listar todos: "
            ).strip().upper()

            selected = students

            if code:
                course = next(
                    (c for c in courses if c.code.upper() == code),
                    None
                )
                if course is None:
                    print("Curso inexistente.")
                    continue

                selected = [
                    s for s in students if s.name in course.students
                ]

            if not selected:
                print("No hay alumnos para mostrar.")

            for student in selected:
                print(student.code, student.name, student.mac)

        elif option == "3":
            student = select_item(students)
            if student:
                print("Código:", student.code)
                print("Nombre:", student.name)
                print("MAC:", student.mac)

                enrolled = [
                    c.code for c in courses
                    if student.name in c.students
                ]
                print("Cursos:", ", ".join(enrolled) or "Ninguno")

        else:
            print("Opción inválida.")


def courses_menu(students, courses):
    while True:
        print("\nCURSOS")
        print("1) Listar")
        print("2) Mostrar detalles")
        print("3) Gestionar alumnos")
        print("0) Volver")
        option = input("Opción: ").strip()

        if option == "0":
            return

        elif option == "1":
            for course in courses:
                print(course.code, course.name, course.state)

        elif option == "2":
            course = select_item(courses)
            if course:
                print("Código:", course.code)
                print("Nombre:", course.name)
                print("Estado:", course.state)
                print("Alumnos:", ", ".join(course.students) or "Ninguno")

                for server in course.servers:
                    services = ", ".join(server["allowed_services"])
                    print(f'{server["name"]}: {services}')

        elif option == "3":
            course = select_item(courses)
            if course is None:
                continue

            action = input("1) Agregar alumno  2) Retirar alumno: ").strip()
            if action not in ("1", "2"):
                print("Opción inválida.")
                continue

            student = select_item(students)
            if student is None:
                continue

            if action == "1":
                if student.name in course.students:
                    print("El alumno ya está matriculado.")
                else:
                    course.students.append(student.name)
                    print(f"{student.name} matriculado en {course.code}.")
                    print("Todavía no se han instalado reglas de red.")

            elif action == "2":
                if student.name not in course.students:
                    print("El alumno no está matriculado en este curso.")
                else:
                    course.students.remove(student.name)
                    print(f"{student.name} retirado de {course.code}.")

        else:
            print("Opción inválida.")


def servers_menu(servers):
    while True:
        print("\nSERVIDORES")
        print("1) Listar")
        print("2) Mostrar servicios")
        print("0) Volver")
        option = input("Opción: ").strip()

        if option == "0":
            return

        elif option == "1":
            for server in servers:
                print(server.name, server.ip)

        elif option == "2":
            server = select_item(servers)
            if server:
                print(server.name, "IP:", server.ip)
                for service in server.services:
                    print(
                        f"{service.name}: "
                        f"{service.protocol}/{service.port}"
                    )

        else:
            print("Opción inválida.")

def list_courses_for_service(courses, server_name, service_name):
    found = False

    for course in courses:
        for server in course.servers:
            same_server = (
                server["name"].casefold() == server_name.casefold()
            )
            allowed = [
                name.casefold()
                for name in server["allowed_services"]
            ]

            if same_server and service_name.casefold() in allowed:
                print(course.code, course.name, course.state)
                found = True

    if not found:
        print("No hay cursos con ese servicio declarado.")

    print("Solo los cursos ACTIVE pueden conceder acceso.")

def menu(students, servers, courses):
    manager = ConnectionManager()
    while True:
        print("\nGESTOR DE POLÍTICAS DE RED")
        print("1) Importar")
        print("2) Exportar")
        print("3) Cursos")
        print("4) Alumnos")
        print("5) Servidores")
        print("6) Políticas")
        print("7) Conexiones")
        print("8) Salir")
        option = input("Opción: ").strip()

        if option == "8":
            print("Aplicación finalizada.")
            return

        elif option == "3":
            courses_menu(students, courses)

        elif option == "4":
            students_menu(students, courses)

        elif option == "5":
            servers_menu(servers)

        elif option == "6":
            server_name = input("Servidor, por ejemplo Server 3: ").strip()
            service_name = input("Servicio, por ejemplo ssh: ").strip()

            list_courses_for_service(
                courses, server_name, service_name
            )

        elif option == "7":
            connections_menu(manager, students, servers, courses, select_item)

        elif option in ("1", "2"):
            print("No implementado en esta etapa.")

        else:
            print("Opción inválida.")


def main():
    students, servers, courses = load_data(Path(__file__).with_name("database.yaml"))
    menu(students, servers, courses)

if __name__ == "__main__":
    main()
