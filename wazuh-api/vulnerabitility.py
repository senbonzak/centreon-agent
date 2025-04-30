#!/usr/bin/env python3
import requests
from requests.auth import HTTPBasicAuth
import json
import argparse
import urllib3
import sys
from datetime import datetime

# Supprimer les warnings SSL (car verify=False)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def search_vulnerabilities(hostname, username, password, agent_id, exclude_cves=None, human_readable=False):
    url = f"https://{hostname}:9200/wazuh-states-vulnerabilities-*/_search?pretty"

    headers = {
        "Content-Type": "application/json"
    }

    query = {
        "query": {
            "match": {
                "agent.id": agent_id
            }
        }
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            data=json.dumps(query),
            auth=HTTPBasicAuth(username, password),
            verify=False  # Attention : désactive la vérification SSL
        )

        response.raise_for_status()
        result = response.json()

        hits = result.get("hits", {}).get("hits", [])
        
        # Variables pour suivre les niveaux de gravité
        has_critical = False
        has_high = False
        
        # Compteurs pour les statistiques (utilisés uniquement en mode human-readable)
        stats = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "None": 0
        }

        # Liste pour stocker toutes les vulnérabilités (y compris les données supplémentaires pour human-readable)
        all_vulnerabilities = []
        
        # Liste pour la sortie JSON (format exactement identique à l'original)
        json_output = {"vulnerabilities": []}

        # Si exclude_cves n'est pas défini, initialiser une liste vide
        if exclude_cves is None:
            exclude_cves = []

        for hit in hits:
            source = hit.get("_source", {})
            vuln = source.get("vulnerability", {})
            vuln_id = vuln.get("id")
            severity = vuln.get("severity", "None")
            
            # Mettre à jour les compteurs
            if severity in stats:
                stats[severity] += 1
            
            # Ne pas ajouter la vulnérabilité si son ID est dans la liste d'exclusion
            if vuln_id not in exclude_cves:
                # Format complet pour l'affichage en mode human-readable
                vuln_data = {
                    "id": vuln_id,
                    "score_base": vuln.get("score", {}).get("base"),
                    "severity": severity,
                    "package": vuln.get("package", {}).get("name"),
                    "title": vuln.get("title"),
                    "published": vuln.get("published")
                }
                all_vulnerabilities.append(vuln_data)
                
                # Format JSON identique à l'original
                json_output["vulnerabilities"].append({
                    "id": vuln_id,
                    "score_base": vuln.get("score", {}).get("base"),
                    "severity": severity
                })
                
                # Vérifier la gravité pour le code de sortie
                if severity == "Critical":
                    has_critical = True
                elif severity == "High":
                    has_high = True

        # Trier les vulnérabilités par gravité (Critical, High, Medium, Low, None)
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4}
        sorted_vulnerabilities = sorted(all_vulnerabilities, key=lambda x: (severity_order.get(x["severity"], 5), -1 * (x["score_base"] or 0)))

        # Déterminer le code de sortie
        exit_code = 0
        if has_critical:
            exit_code = 2
        elif has_high:
            exit_code = 1

        # Afficher les résultats
        if human_readable:
            display_human_readable(sorted_vulnerabilities, stats, agent_id, exclude_cves)
        else:
            if not json_output["vulnerabilities"]:
                print("Aucune vulnérabilité trouvée.")
            else:
                print(json.dumps(json_output, indent=2))

        return exit_code

    except requests.exceptions.RequestException as e:
        print(f"Erreur lors de la requête : {e}", file=sys.stderr)
        return 3  # Code d'erreur pour les problèmes de requête

def display_human_readable(vulnerabilities, stats, agent_id, exclude_cves):
    """Affiche les résultats dans un format lisible pour les humains"""
    
    print(f"\n==== Rapport de vulnérabilités pour l'agent {agent_id} ====")
    print(f"Nombre de vulnérabilités trouvées: {len(vulnerabilities)}")
    
    if exclude_cves:
        print(f"CVEs exclues: {', '.join(exclude_cves)}")
    
    print("\n=== Statistiques ===")
    print(f"Critical: {stats['Critical']}")
    print(f"High: {stats['High']}")
    print(f"Medium: {stats['Medium']}")
    print(f"Low: {stats['Low']}")
    
    print("\n=== Détails des vulnérabilités ===")
    if not vulnerabilities:
        print("Aucune vulnérabilité trouvée.")
        return
    
    current_severity = None
    for vuln in vulnerabilities:
        # Afficher un séparateur pour chaque niveau de gravité
        if current_severity != vuln["severity"]:
            current_severity = vuln["severity"]
            print(f"\n--- {current_severity} ---")
        
        # Formater la date si disponible
        published = vuln.get("published", "Date inconnue")
        if published and not isinstance(published, str):
            try:
                published = datetime.utcfromtimestamp(published / 1000).strftime('%Y-%m-%d')
            except:
                published = "Date invalide"
        
        # Afficher les détails de la vulnérabilité
        print(f"ID: {vuln['id']}")
        print(f"Score: {vuln['score_base']}")
        print(f"Severity: {vuln['severity']}")
        print("---")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="""
Recherche des vulnérabilités Wazuh par agent ID et applique des filtres.

Code de retour:
  0: Aucune vulnérabilité critique ou élevée trouvée (seulement Medium/Low ou aucune)
  1: Au moins une vulnérabilité High trouvée
  2: Au moins une vulnérabilité Critical trouvée
  3: Erreur lors de l'exécution du script
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("-H", "--hostname", required=True, help="Hostname ou IP du serveur Elasticsearch")
    parser.add_argument("-u", "--user", required=True, help="Nom d'utilisateur")
    parser.add_argument("-p", "--password", required=True, help="Mot de passe")
    parser.add_argument("-i", "--id", required=True, help="ID de l'agent Wazuh")
    parser.add_argument("-e", "--exclude", help="Liste de CVE à exclure, séparées par des virgules")
    parser.add_argument("--human", action="store_true", help="Afficher les résultats dans un format lisible")

    args = parser.parse_args()
    
    # Traitement du paramètre d'exclusion
    exclude_cves = []
    if args.exclude:
        exclude_cves = [cve.strip() for cve in args.exclude.split(",")]

    # Exécution de la recherche et récupération du code de sortie
    exit_code = search_vulnerabilities(
        args.hostname, 
        args.user, 
        args.password, 
        args.id, 
        exclude_cves,
        args.human
    )
    
    # Terminer avec le code de sortie approprié
    sys.exit(exit_code)
