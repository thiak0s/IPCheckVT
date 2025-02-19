import os
import sys
import csv
import json
import logging
import asyncio
import aiohttp
import argparse
import time
import textwrap
from datetime import datetime, timezone
from rich.console import Console
from rich.table import Table
from rich import box

API_KEY = os.environ.get("VT_API_KEY", "YourAPIkey") #Paste API key here
VT_TIMEOUT = int(os.environ.get("VT_TIMEOUT", "10"))
VT_MAX_RETRIES = int(os.environ.get("VT_MAX_RETRIES", "3"))
VT_BACKOFF_FACTOR = float(os.environ.get("VT_BACKOFF_FACTOR", "2"))
VT_SLEEP_INTERVAL = int(os.environ.get("VT_SLEEP_INTERVAL", "16"))
VT_CONCURRENCY = int(os.environ.get("VT_CONCURRENCY", "1"))

API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"
GUI_URL = "https://www.virustotal.com/gui/ip-address/{}/details"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
console = Console()

def print_banner() -> None:
    """
    Imprime el banner de la herramienta utilizando rich markup.
    """
    banner = textwrap.dedent("""
        [cyan bold] ██╗██████╗  ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗    ██╗   ██╗████████╗
         ██║██╔══██╗██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝    ██║   ██║╚══██╔══╝
         ██║██████╔╝██║     ███████║█████╗  ██║     █████╔╝     ██║   ██║   ██║   
         ██║██╔═══╝ ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗     ╚██╗ ██╔╝   ██║   
         ██║██║     ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗     ╚████╔╝    ██║   
         ╚═╝╚═╝      ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝      ╚═══╝     ╚═╝   
        [/cyan bold]
        [red bold]                                                                      v2.1[/red bold]

                        --- Información del Autor y Descripción ---

                        ******* ¡Esto es [cyan bold]IPCheck VT v2.1[/cyan bold]! *******
                         [Herramienta creada por [yellow]thiak0s[/yellow] - 2025]
            [white bold]Consulta información de direcciones IPs usando la API de VirusTotal[/white bold]
                             
        [white italic]***** Recuerda utilizar esta herramienta de manera ética y responsable *****[/white italic]
    """)
    console.print(banner)

def format_ts(ts) -> str:
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)

def print_analysis_stats_table(analysis_stats: dict) -> None:
    if not analysis_stats:
        console.print("No se encontraron estadísticas de análisis.", style="bold red")
        return
    table = Table(title="Estadísticas de análisis", box=box.SIMPLE)
    table.add_column("Tipo", style="cyan")
    table.add_column("Cantidad", justify="right", style="magenta")
    for stat, count in analysis_stats.items():
        table.add_row(str(stat), str(count))
    console.print(table)

def print_vendor_results_table(analysis_results: dict) -> None:
    if not analysis_results:
        console.print("No se encontraron resultados de análisis por motor.", style="bold red")
        return
    table = Table(title="Detalle por motor de análisis", box=box.SIMPLE)
    table.add_column("Security vendor", style="cyan")
    table.add_column("Method", style="yellow")
    table.add_column("Engine Name", style="green")
    table.add_column("Category", style="blue")
    table.add_column("Result", style="white")
    for vendor, info in analysis_results.items():
        method = info.get("method", "N/A")
        engine_name = info.get("engine_name", "N/A")
        category = info.get("category", "N/A")
        result_val = info.get("result", "N/A")
        style = None
        lower_category = category.lower()
        if lower_category in ["malicious", "phishing", "malware"]:
            style = "red"
        elif lower_category == "suspicious":
            style = "orange1"
        table.add_row(vendor, method, engine_name, category, result_val, style=style)
    console.print(table)

def print_general_info_table(data: dict) -> None:
    table = Table(title="Información General", box=box.SIMPLE)
    table.add_column("Atributo", style="cyan")
    table.add_column("Valor", style="magenta")
    table.add_row("JARM", str(data.get("jarm", "N/A")))
    table.add_row("Último análisis", format_ts(data.get("last_analysis_date", "N/A")))
    table.add_row("Última modificación", format_ts(data.get("last_modification_date", "N/A")))
    table.add_row("Fecha certificado HTTPS", format_ts(data.get("last_https_certificate_date", "N/A")))
    table.add_row("Registro Regional", str(data.get("regional_internet_registry", "N/A")))
    table.add_row("Fecha WHOIS", format_ts(data.get("whois_date", "N/A")))
    console.print(table)

def print_total_votes_table(data: dict) -> None:
    total_votes = data.get("total_votes", {})
    if not total_votes:
        console.print("No se encontraron votos totales.", style="bold red")
        return
    table = Table(title="Votos Totales", box=box.SIMPLE)
    table.add_column("Tipo", style="cyan")
    table.add_column("Cantidad", justify="right", style="magenta")
    for key, val in total_votes.items():
        table.add_row(str(key), str(val))
    console.print(table)

def print_crowdsourced_context_table(data: dict) -> None:
    contexts = data.get("crowdsourced_context", [])
    if not contexts:
        console.print("No se encontró contexto crowdsourced.", style="bold red")
        return
    table = Table(title="Contexto Crowdsourced", box=box.SIMPLE)
    table.add_column("Timestamp", style="cyan")
    table.add_column("Título", style="green")
    table.add_column("Severidad", style="yellow")
    table.add_column("Detalles", style="white")
    for ctx in contexts:
        ts = format_ts(ctx.get("timestamp", "N/A"))
        title = ctx.get("title", "N/A")
        severity = ctx.get("severity", "N/A")
        details = ctx.get("details", "N/A")
        table.add_row(ts, title, severity, details)
    console.print(table)

def print_additional_attributes_table(data: dict) -> None:
    additional_attrs = {}
    if "whois" in data:
        whois = data["whois"]
        if isinstance(whois, str) and len(whois) > 100:
            whois = whois[:100] + "..."
        additional_attrs["Whois"] = whois
    if "reputation" in data:
        additional_attrs["Reputation"] = data["reputation"]
    if "continent" in data:
        additional_attrs["Continent"] = data["continent"]
    if additional_attrs:
        table = Table(title="Información adicional", box=box.SIMPLE)
        table.add_column("Atributo", style="cyan")
        table.add_column("Valor", style="magenta")
        for attr, value in additional_attrs.items():
            table.add_row(attr, str(value))
        console.print(table)
    else:
        console.print("No se encontraron atributos adicionales.", style="bold red")

def guardar_resultados(datos: list, archivo_salida: str, vt_url: bool = False) -> None:
    header = ["IP", "Red", "Asociación", "Detecciones", "ASN", "País", "URL"] if vt_url else ["IP", "Red", "Asociación", "Detecciones", "ASN", "País"]
    try:
        with open(archivo_salida, 'w', newline='', encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(header)
            writer.writerows(datos)
    except Exception as e:
        logging.error("Error guardando resultados: %s", e)

async def fetch_ip_data(ip: str, session: aiohttp.ClientSession, headers: dict) -> dict:
    for attempt in range(VT_MAX_RETRIES):
        try:
            async with session.get(API_URL.format(ip), headers=headers, timeout=VT_TIMEOUT) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status == 429:
                    logging.warning("Límite de consumo alcanzado para %s. Esperando 60 segundos...", ip)
                    await asyncio.sleep(60)
                else:
                    logging.error("Error %s para IP %s", response.status, ip)
                    return None
        except Exception as e:
            logging.error("Error al obtener IP %s: %s", ip, e)
            await asyncio.sleep(VT_BACKOFF_FACTOR ** attempt)
    return None

async def process_ip(ip: str, session: aiohttp.ClientSession, headers: dict, cache: dict, semaphore: asyncio.Semaphore) -> tuple:
    async with semaphore:
        if ip in cache:
            logging.info("Usando resultado en caché para %s", ip)
            return ip, cache[ip]
        data = await fetch_ip_data(ip, session, headers)
        if data is not None:
            cache[ip] = data
        return ip, data

async def main_async(ips: list, headers: dict, vt_concurrency: int) -> list:
    cache = {}
    cache_file = "cache.json"
    if os.path.exists(cache_file):
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                cache = json.load(f)
        except Exception as e:
            logging.error("Error cargando caché: %s", e)
    semaphore = asyncio.Semaphore(vt_concurrency)
    async with aiohttp.ClientSession() as session:
        tasks = [process_ip(ip, session, headers, cache, semaphore) for ip in ips]
        results = await asyncio.gather(*tasks)
    try:
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(cache, f)
    except Exception as e:
        logging.error("Error guardando caché: %s", e)
    return results

def main() -> None:
    print_banner()
    parser = argparse.ArgumentParser(description="IPCheckVT - Consulta información de IPs usando la API de VirusTotal")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--ip", help="Una única dirección IP a consultar", type=str)
    group.add_argument("-f", "--ip-file", help="Archivo TXT con una lista de IPs (una por línea)", type=str)
    parser.add_argument("-o", "--output-file", help="Ruta completa al archivo de salida (ubicación, nombre y extensión). Ejemplo: /ruta/archivo.csv", type=str)
    parser.add_argument("-u", "--vt-url", action="store_true", help="Agrega URL de validación en VirusTotal a la salida (en pantalla y en archivo)")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Aumenta la verbosidad del output: -v, -vv, -vvv")
    args = parser.parse_args()
    if args.ip:
        ips = [args.ip.strip()]
        output_file = args.output_file if args.output_file else os.path.join(os.getcwd(), "resultados.csv")
    else:
        if not os.path.exists(args.ip_file):
            logging.error("No se encontró el archivo %s", args.ip_file)
            sys.exit(1)
        with open(args.ip_file, "r", encoding="utf-8") as f:
            ips = [line.strip() for line in f if line.strip()]
        output_file = args.output_file if args.output_file else os.path.join(os.path.dirname(args.ip_file), "resultados.csv")
    console.print("[yellow]---------------------------------------------------------------------------[/yellow]")
    console.print(f"Total de IPs a procesar: [bold green]{len(ips)}[/bold green] (Máximo 500 consultas/día para cuenta gratuita)")
    console.print("[yellow]---------------------------------------------------------------------------[/yellow]\n")
    headers = {"x-apikey": API_KEY}
    results = asyncio.run(main_async(ips, headers, VT_CONCURRENCY))
    console.print()
    output_results = []
    for idx, (ip, data) in enumerate(results, start=1):
        if data is None:
            console.print(f"[{idx:03d}] IP: {ip} - No se pudo obtener información.", style="bold red")
            continue
        attr = data.get("data", {}).get("attributes", {})
        network = attr.get("network", "N/A")
        asn = attr.get("asn", "N/A")
        as_owner = attr.get("as_owner", "N/A")
        country = attr.get("country", "N/A")
        tags = ", ".join(attr.get("tags", [])) if attr.get("tags") else "N/A"
        analysis_stats = attr.get("last_analysis_stats", {})
        malicious = analysis_stats.get("malicious", 0)
        total_engines = sum(analysis_stats.values())
        detections = f"{malicious} / {total_engines}"
        line = f"[{idx:03d}] IP: {ip} | Red: {network} | Asociación: {tags} | Detecciones: {detections} | ASN: {asn} ({as_owner}) | País: {country}"
        if args.vt_url:
            vt_url_value = GUI_URL.format(ip)
            line += f" | URL: {vt_url_value}"
        if malicious == 1:
            console.print(line, style="orange1")
        elif malicious >= 2:
            console.print(line, style="bold red")
        else:
            console.print(line)
        if args.verbose >= 2:
            console.print()
            print_analysis_stats_table(analysis_stats)
            vendor_results = attr.get("last_analysis_results", {})
            print_vendor_results_table(vendor_results)
        if args.verbose >= 3:
            print_additional_attributes_table(attr)
            print_general_info_table(attr)
            print_total_votes_table(attr)
            print_crowdsourced_context_table(attr)
            console.print()
        if args.vt_url:
            output_results.append([ip, network, tags, detections, f"{asn} ({as_owner})", country, vt_url_value])
        else:
            output_results.append([ip, network, tags, detections, f"{asn} ({as_owner})", country])
        if len(ips) > 1 and idx < len(ips):
            time.sleep(VT_SLEEP_INTERVAL)
    if output_results:
        guardar_resultados(output_results, output_file, args.vt_url)
        console.print(f"\n✅ Resultados guardados en {output_file}", style="bold green")

if __name__ == "__main__":
    main()
