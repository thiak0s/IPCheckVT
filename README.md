**README - IPCheck VT v2.1**

# IPCheck VT

![image](https://github.com/user-attachments/assets/004191d3-77c0-47e7-9a6b-1387d19e16af)

IPCheck VT (v2.1) es una herramienta desarrollada en Python que consulta y analiza direcciones IP utilizando la API de VirusTotal. Diseñada para profesionales en ciberseguridad y analistas, esta aplicación ofrece resultados detallados y visualizaciones enriquecidas en la consola, facilitando la identificación y evaluación de amenazas asociadas a direcciones IP.

---

## Características

- **Consulta asíncrona:** Permite realizar múltiples consultas de IP de forma simultánea, optimizando el tiempo de análisis.
- **Manejo de caché:** Almacena resultados en un archivo JSON para evitar solicitudes redundantes a la API.
- **Exportación a CSV:** Guarda los resultados en un archivo CSV para análisis posterior o integración con otros procesos.
- **Visualización enriquecida:** Utiliza la librería `rich` para mostrar tablas y banners coloridos en la consola.
- **Ajuste de verbosidad:** Ofrece distintos niveles de salida para mostrar información básica o detallada según se requiera.
- **Configuración flexible:** Se adapta mediante variables de entorno y argumentos de línea de comandos para personalizar tiempos de espera, reintentos y concurrencia.

---

## Requisitos

- **Python:** Versión 3.6 o superior.
- **Dependencias:**  
  - `aiohttp`
  - `rich`
  - `argparse`
  - `logging`
  - Otras dependencias estándar de Python.

> Se recomienda revisar el archivo `requirements.txt` para instalar todas las dependencias necesarias.

---

## Instalación

1. **Clonar el repositorio:**

   ```bash
   git clone https://github.com/thiak0s/IPCheckVT.git
   cd IPCheckVT
   ```

2. **Instalar dependencias:**

   Si cuentas con un archivo `requirements.txt`, ejecuta:

   ```bash
   pip install -r requirements.txt
   ```

   Si no, asegúrate de instalar manualmente las librerías mencionadas.

---

## Uso

IPCheck VT se ejecuta desde la línea de comandos y ofrece opciones tanto para consultar una única IP como para analizar un listado de IPs desde un archivo de texto.

### Ejemplo: Consulta de una sola IP

```bash
./ipcheckvt.py -i 8.8.8.8
```

Este comando consultará la dirección IP `8.8.8.8` y mostrará la información relevante en la consola.

![image](https://github.com/user-attachments/assets/021104e5-e84d-473d-b45b-4f4d74faa899)

### Ejemplo: Consulta de múltiples IPs desde un archivo

Supón que tienes un archivo llamado `ips.txt` con una IP por línea. Para analizar todas las IPs y exportar los resultados a un archivo CSV, puedes ejecutar:

```bash
./ipcheckvt.py -f ips.txt -o resultados.csv -u -vv
```

- `-f ips.txt`: Especifica el archivo de entrada con la lista de IPs.
- `-o resultados.csv`: Define la ruta y nombre del archivo CSV de salida.
- `-u`: Incluye en la salida la URL de validación en VirusTotal para cada IP.
- `-vv`: Incrementa la verbosidad para mostrar información adicional (tablas detalladas).

![image](https://github.com/user-attachments/assets/7183afc5-0d35-49d0-884d-3be087afb3e5)

![image](https://github.com/user-attachments/assets/2861f407-e041-4025-aabd-5212c3bb89f0)

![image](https://github.com/user-attachments/assets/966ca2b1-3110-406f-87b5-f7ae75770dd7)

---

## Configuración

IPCheck VT utiliza varias variables de entorno para personalizar su comportamiento:

- **VT_API_KEY:** Tu API key de VirusTotal.
- **VT_TIMEOUT:** Tiempo máximo de espera para cada consulta (en segundos).
- **VT_MAX_RETRIES:** Número máximo de reintentos ante errores o respuestas de límite (HTTP 429).
- **VT_BACKOFF_FACTOR:** Factor multiplicador para los tiempos de espera entre reintentos.
- **VT_SLEEP_INTERVAL:** Intervalo de tiempo entre consultas para evitar saturar la API.
- **VT_CONCURRENCY:** Número máximo de consultas concurrentes.

Puedes definir estas variables en tu entorno o en un archivo de configuración antes de ejecutar la herramienta.

---

### Notas Importantes

- Recuerda utilizar esta herramienta de manera ética y responsable.

### Licencia

Este proyecto se distribuye bajo la licencia [MIT](LICENSE).

---

¡Espero que encuentres útil IPCheck VT! Si tienes preguntas, problemas o sugerencias, no dudes en [contactarme](https://github.com/thiak0s). ¡Gracias por utilizar IPCheck VT!

Herramienta desarrollada por [thiak0s](https://github.com/thiak0s).
