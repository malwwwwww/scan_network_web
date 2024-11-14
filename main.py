from flask import Flask, render_template, request
import nmap
from scapy.all import sniff, IP
import threading
import datetime
import paramiko

app = Flask(__name__)

# Página de bienvenida
@app.route('/')
def index():
    return render_template('index.html')

# Función para escanear hosts en una red
def escanear_hosts(red):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=red, arguments='-sn')  # Scan de hosts
        hosts_up = [host for host in nm.all_hosts() if nm[host].state() == "up"]
        print(f"Hosts encontrados: {hosts_up}")  # Impresión para depuración
        return hosts_up
    except Exception as e:
        print(f"Error al escanear hosts: {e}")  # Impresión para depuración
        return []

# Función para escanear puertos
def escanear_puertos(host):
    nm = nmap.PortScanner()
    try:
        nm.scan(host, arguments='-sS')  # Escaneo de puertos
        if 'tcp' in nm[host]:
            return [f"Puerto {port}: {info['name']} (Estado: {info['state']})" for port, info in nm[host]['tcp'].items()]
        else:
            return ["No se encontraron puertos abiertos."]
    except Exception as e:
        return [str(e)]


# Función para detectar sistema operativo con depuración
def detectar_sistema_operativo(host):
    nm = nmap.PortScanner()
    try:
        nm.scan(host, arguments='-O')
        print(nm[host])  # Imprimir información para depuración
        if 'osmatch' in nm[host] and len(nm[host]['osmatch']) > 0:
            return f"Sistema operativo detectado: {nm[host]['osmatch'][0]['name']}"
        else:
            return "No se pudo detectar el sistema operativo. Posiblemente debido a restricciones de red o falta de permisos."
    except Exception as e:
        return f"Error al detectar el sistema operativo: {str(e)}"



def escanear_vulnerabilidades(host):
    nm = nmap.PortScanner()
    resultados = []

    try:
        # Escanea el host buscando vulnerabilidades
        nm.scan(host, arguments='--script=vuln')  # Usa el argumento adecuado para tu configuración de nmap

        # Verificar si existen vulnerabilidades en la respuesta
        if 'hostscript' in nm[host] and len(nm[host]['hostscript']) > 0:
            for script in nm[host]['hostscript']:
                resultados.append({
                    'name': script['id'],  # Nombre del script que detectó la vulnerabilidad
                    'type': script.get('output', 'No se proporcionó información del tipo')  # Detalles del tipo de vulnerabilidad
                })
        else:
            return [{"name": "Sin vulnerabilidades detectadas", "type": "No se encontraron vulnerabilidades en el escaneo."}]

    except Exception as e:
        # Captura el error en un formato que pueda interpretarse fácilmente en el dashboard
        return [{"name": "Error", "type": str(e)}]

    return resultados





# Función para escanear servicios
def escanear_servicios(host):
    nm = nmap.PortScanner()
    try:
        nm.scan(host, arguments='-sV')
        return nm[host]['services'] if 'services' in nm[host] else "No se encontraron servicios."
    except Exception as e:
        return str(e)



paquetes=[]
def capturar_paquetes(interface, host_ip):
    def procesar_paquete(paquete):
        if IP in paquete:
            timestamp_legible = datetime.datetime.fromtimestamp(paquete.time).strftime('%Y-%m-%d %H:%M:%S')
            paquetes.append({
                "timestamp": timestamp_legible,
                "origen": paquete[IP].src,
                "destino": paquete[IP].dst,
                "protocolo": paquete.proto,
                "size": len(paquete),
                "detalle": paquete.show(dump=True)
            })

    try:
        sniff(iface=interface, prn=procesar_paquete, store=0)
    except Exception as e:
        print(f"Error en la captura: {e}")



def cerrar_puerto(host, username, password, puerto):
    try:
        # Establecer conexión SSH
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=username, password=password)
        puerto = int(puerto)

        # Imprimir el tipo y el valor del puerto para depuración
        print(f"Tipo: {type(puerto)}, Valor: {puerto}")

        # Validar que el puerto sea un entero y esté en el rango permitido
        if not isinstance(puerto, int) or not (1 <= puerto <= 65535):
            return f"Puerto inválido: {puerto}"

        # Comando para cerrar el puerto usando 'sudo -S'
        comando = f"echo {password} | sudo -S ufw deny {puerto}"
        stdin, stdout, stderr = client.exec_command(comando)

        # Leer resultados y errores
        error = stderr.read().decode().strip()
        if error and "[sudo]" not in error:  # Filtra el prompt de sudo
            resultado = f"Error al cerrar el puerto {puerto}: {error}"
        else:
            resultado = f"Puerto {puerto} cerrado exitosamente."

        client.close()
        return resultado

    except Exception as e:
        return f"Error en la conexión SSH: {str(e)}"




@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    global paquetes  # Usa la variable global para almacenar paquetes
    hosts = []
    puertos = []
    os_info = ""
    vulnerabilidades = []
    servicios = []
    cierre_resultado = ""

    if request.method == 'POST':
        action = request.form.get('action')
        interface = request.form.get("interface")
        host_ip = request.form.get("host_ip")

        if action == 'escanear_hosts':
            red = request.form['red']
            hosts = escanear_hosts(red)

        elif action == 'escanear_puertos':
            host = request.form['host']
            puertos = escanear_puertos(host)

        elif action == 'detectar_os':
            host = request.form['host']
            os_info = detectar_sistema_operativo(host)

        elif action == 'escanear_vulnerabilidades':
            host = request.form['host']
            vulnerabilidades = escanear_vulnerabilidades(host)

        elif action == 'escanear_servicios':
            host = request.form['host']
            servicios = escanear_servicios(host)

        elif action == "capturar_paquetes":
            # Inicia la captura en un hilo separado
            threading.Thread(target=capturar_paquetes, args=(interface, host_ip)).start()

        elif action == 'cerrar_puertos':
            host = request.form['host']
            username = request.form['username']
            password = request.form['password']
            puertos_a_cerrar = request.form['puertos']
            cierre_resultado = cerrar_puerto(host, username, password, puertos_a_cerrar)

    return render_template('dashboard.html', hosts=hosts, puertos=puertos, os_info=os_info, 
                           vulnerabilidades=vulnerabilidades, servicios=servicios, paquetes=paquetes,
                           cierre_resultado=cierre_resultado)

if __name__ == '__main__':
    app.run(debug=True,port=9000)
