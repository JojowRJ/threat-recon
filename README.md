# Threat Recon 🔎

Outil Python d'investigation de domaines et d'adresses IP — développé dans le cadre d'une montée en compétences en Cyber Threat Intelligence.

## Fonctionnalités

- **WHOIS** — registrar, dates de création/expiration, organisation, pays
- **DNS** — enregistrements A, MX, NS, TXT
- **Géolocalisation IP** — pays, ville, FAI, organisation

## Utilisation

```bash
pip install requests python-whois dnspython
python osint.py
"entrer un nom de domaine (exemple : google.com)"
