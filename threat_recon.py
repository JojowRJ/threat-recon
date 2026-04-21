from dotenv import load_dotenv
import os
import whois
import dns.resolver
import requests
import socket
import base64

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

def print_banner():
    print("=" * 60)
    print("        OSINT TOOL — Domain & IP Investigation")
    print("=" * 60)

def get_whois(domain):
    print(f"\n[*] WHOIS — {domain}")
    print("-" * 40)
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        expiration = w.expiration_date
        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(expiration, list):
            expiration = expiration[0]
        print(f"Registrar     : {w.registrar}")
        print(f"Creation      : {creation.strftime('%d/%m/%Y') if creation else 'N/A'}")
        print(f"Expiration    : {expiration.strftime('%d/%m/%Y') if expiration else 'N/A'}")
        print(f"Organisation  : {w.org}")
        print(f"Pays          : {w.country}")
    except Exception as e:
        print(f"[!] Erreur WHOIS : {e}")

def get_dns(domain):
    print(f"\n[*] DNS Records — {domain}")
    print("-" * 40)
    for record in ["A", "MX", "NS", "TXT"]:
        try:
            answers = dns.resolver.resolve(domain, record)
            for r in answers:
                print(f"{record.ljust(5)} : {r}")
        except:
            print(f"{record.ljust(5)} : Aucun enregistrement")

def get_ip_info(domain):
    print(f"\n[*] IP & Geolocalisation — {domain}")
    print("-" * 40)
    try:
        ip = socket.gethostbyname(domain)
        print(f"IP            : {ip}")
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        data = response.json()
        print(f"Pays          : {data.get('country')}")
        print(f"Ville         : {data.get('city')}")
        print(f"FAI           : {data.get('isp')}")
        print(f"Organisation  : {data.get('org')}")
    except Exception as e:
        print(f"[!] Erreur IP : {e}")

def check_virustotal(domain):
    print(f"\n[*] VirusTotal — {domain}")
    print("-" * 40)
    if not VT_API_KEY:
        print("[!] Pas de cle API VirusTotal")
        return
    try:
        url_id = base64.urlsafe_b64encode(f"http://{domain}".encode()).decode().strip("=")
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=15
        )
        if response.status_code == 200:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            clean = stats.get("undetected", 0)
            total = malicious + suspicious + clean
            if malicious > 0:
                verdict = "MALVEILLANT"
            elif suspicious > 0:
                verdict = "SUSPECT"
            else:
                verdict = "CLEAN"
            print(f"Verdict       : {verdict}")
            print(f"Malveillant   : {malicious}/{total} moteurs")
            print(f"Suspect       : {suspicious}/{total} moteurs")
            print(f"Clean         : {clean}/{total} moteurs")
        else:
            print(f"[!] Erreur VirusTotal : {response.status_code}")
    except Exception as e:
        print(f"[!] Erreur : {e}")

# === MAIN ===
print_banner()
domain = input("\nEntrez un domaine a analyser : ").strip()
get_whois(domain)
get_dns(domain)
get_ip_info(domain)
check_virustotal(domain)
print("\n" + "=" * 60)
print("Analyse terminee.")
print("=" * 60)