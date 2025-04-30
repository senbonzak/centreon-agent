# Wazuh Vulnerability Scanner

Un outil en ligne de commande pour interroger et analyser les vulnérabilités détectées par Wazuh à partir d'Elasticsearch.

## Description

Ce script permet de rechercher les vulnérabilités associées à un agent Wazuh spécifique, filtrer les résultats en excluant certaines CVE, et présenter les résultats dans différents formats (JSON ou format lisible). Il fournit également des codes de retour basés sur la gravité des vulnérabilités détectées, ce qui le rend utile pour l'intégration dans des systèmes de monitoring ou des scripts d'automatisation.

## Fonctionnalités

- Recherche des vulnérabilités par ID d'agent Wazuh
- Filtrage par exclusion de CVE spécifiques
- Codes de retour basés sur la sévérité des vulnérabilités trouvées
- Deux formats de sortie : JSON et format lisible pour les humains
- Statistiques sur les vulnérabilités par niveau de gravité

## Prérequis

- Python 3.x
- Modules Python : `requests`, `json`, `argparse`, `urllib3`

## Installation

1. Cloner le dépôt ou télécharger le fichier `vulnerability2.py`
2. Installer les dépendances requises :

```bash
pip install requests
```

3. Rendre le script exécutable (sous Linux/macOS) :

```bash
chmod +x vulnerability2.py
```

## Utilisation

### Format de base

```bash
python3 vulnerability2.py -H <hostname> -u <username> -p <password> -i <agent_id> [options]
```

### Options disponibles

| Option | Description |
|--------|-------------|
| `-H`, `--hostname` | Hostname ou IP du serveur Elasticsearch (requis) |
| `-u`, `--user` | Nom d'utilisateur pour l'authentification (requis) |
| `-p`, `--password` | Mot de passe pour l'authentification (requis) |
| `-i`, `--id` | ID de l'agent Wazuh (requis) |
| `-e`, `--exclude` | Liste de CVE à exclure, séparées par des virgules |
| `--human` | Afficher les résultats dans un format lisible pour les humains |
| `-h`, `--help` | Afficher l'aide et quitter |

### Exemples d'utilisation

#### Sortie JSON standard

```bash
python3 vulnerability2.py -H 10.1.1.29 -u kibanaserver -p 'password' -i 004
```

#### Exclure certaines CVE

```bash
python3 vulnerability2.py -H 10.1.1.29 -u kibanaserver -p 'password' -i 004 -e CVE-2023-52500,CVE-2023-52518
```

#### Format de sortie lisible

```bash
python3 vulnerability2.py -H 10.1.1.29 -u kibanaserver -p 'password' -i 004 --human
```

### Codes de retour

Le script fournit des codes de retour qui peuvent être utilisés pour l'intégration dans des systèmes de surveillance :

| Code | Description |
|------|-------------|
| 0 | Aucune vulnérabilité critique ou élevée trouvée (seulement Medium/Low ou aucune) |
| 1 | Au moins une vulnérabilité High trouvée |
| 2 | Au moins une vulnérabilité Critical trouvée |
| 3 | Erreur lors de l'exécution du script |

Pour vérifier le code de retour après l'exécution sous Linux/macOS :

```bash
echo $?
```

## Format de sortie

### Format JSON

```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2023-52519",
      "score_base": 6.0,
      "severity": "Medium"
    },
    {
      "id": "CVE-2023-52570",
      "score_base": 4.1,
      "severity": "Medium"
    }
  ]
}
```

### Format lisible (avec option `--human`)

```
==== Rapport de vulnérabilités pour l'agent 004 ====
Nombre de vulnérabilités trouvées: 7
CVEs exclues: CVE-2023-52500, CVE-2023-52518, CVE-2024-26859

=== Statistiques ===
Critical: 0
High: 0
Medium: 9
Low: 1

=== Détails des vulnérabilités ===

--- Medium ---
ID: CVE-2023-52519
Score: 6.0
Severity: Medium
---
ID: CVE-2023-52570
Score: 4.1
Severity: Medium
---

--- Low ---
ID: CVE-2023-52569
Score: 3.3
Severity: Low
---
```

## Sécurité

Attention : Ce script désactive la vérification des certificats SSL (`verify=False`). Cela peut présenter un risque de sécurité dans les environnements de production. Utilisez cette option avec précaution.

## Contribuer

Les contributions sont les bienvenues ! N'hésitez pas à soumettre des pull requests ou à ouvrir des issues pour améliorer ce script.

## Licence

[Insérer ici votre licence]
