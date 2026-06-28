# -*- coding: utf-8 -*-
"""
DTLexplains - Analyse pédagogique des journaux Windows.

Objectif :
    Lire les événements des 30 derniers jours dans les principaux journaux
    Windows, regrouper les événements, les classer, expliquer les causes
    probables et proposer des actions concrètes.

Version : v1.0-4

Principes :
    - sortie console courte : uniquement le résumé ;
    - un rapport HTML complet ;
    - liens directs du résumé vers les détails ;
    - une section séparée par catégorie ;
    - catégorie 9 : NORMAL.

Usage :
    python -X utf8 DTLexplains.py
    python -X utf8 DTLexplains.py --days 7
    python -X utf8 DTLexplains.py --logs System Application Security
    python -X utf8 DTLexplains.py --html reports\rapport.html
    python -X utf8 DTLexplains.py --json reports\rapport.json

Notes :
    - Le journal Security exige souvent une console administrateur.
    - Aucun module Python externe requis.
"""

from __future__ import annotations

import argparse
import collections
import ctypes
import datetime as _dt
import html
import json
import locale
import os
import socket
import subprocess
import sys
import traceback
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

APP_NAME = "DTLexplains"
APP_VERSION = "v1.0-4"
APP_VERSION_NUMERIC = "1.0.4"

DEFAULT_LOGS = [
    "Application",
    "System",
    "Security",
    "Setup",
    "Windows PowerShell",
]

LEVEL_NAMES = {
    1: "Critical",
    2: "Error",
    3: "Warning",
    4: "Information",
    5: "Verbose",
}

CATEGORY_ORDER = [
    "hardware",
    "boot_power",
    "security",
    "network",
    "updates",
    "service",
    "application",
    "powershell",
    "normal",
]

CATEGORY_NUMBERS = {name: index + 1 for index, name in enumerate(CATEGORY_ORDER)}

CATEGORY_ICONS = {
    "hardware": "💽",
    "boot_power": "⏻",
    "security": "🛡",
    "network": "🌐",
    "updates": "🔄",
    "service": "⚙",
    "application": "🧩",
    "powershell": "⌁",
    "normal": "✓",
}

TEXT = {
    "fr": {
        "level.1": "Critique",
        "level.2": "Erreur",
        "level.3": "Avertissement",
        "level.4": "Information",
        "level.5": "Verbose",
        "category.hardware": "Matériel / disque / pilote",
        "category.boot_power": "Démarrage / alimentation",
        "category.security": "Sécurité / authentification",
        "category.network": "Réseau / DNS / DHCP / SMB",
        "category.updates": "Mises à jour Windows",
        "category.service": "Services Windows",
        "category.application": "Applications",
        "category.powershell": "PowerShell / scripts",
        "category.normal": "Normal / courant / généralement bénin",
        "category_short.hardware": "💽 Matériel",
        "category_short.boot_power": "⏻ Démarrage",
        "category_short.security": "🛡 Sécurité",
        "category_short.network": "🌐 Réseau",
        "category_short.updates": "🔄 Mises à jour",
        "category_short.service": "⚙ Services",
        "category_short.application": "🧩 Applications",
        "category_short.powershell": "⌁ PowerShell",
        "category_short.normal": "✓ Normal",
        "severity.urgent": "Urgent",
        "severity.important": "Important",
        "severity.watch": "À surveiller",
        "severity.plan": "À planifier",
        "severity.normal": "Normal",
        "badge.urgent": "URGENT",
        "badge.important": "IMPORTANT",
        "badge.watch": "SURVEILLER",
        "badge.plan": "PLANIFIER",
        "badge.normal": "NORMAL",
        "frequency.very_frequent": "Très fréquent",
        "frequency.frequent": "Fréquent",
        "frequency.occasional": "Occasionnel",
        "frequency.rare": "Rare",
        "occurrence.one": "occurrence",
        "occurrence.many": "occurrences",
        "console.machine": "Machine",
        "console.period": "Période analysée",
        "console.days": "derniers jours",
        "console.events_read": "Événements lus",
        "console.groups": "Groupes détectés",
        "console.html_report": "Rapport HTML",
        "console.warnings": "Avertissements",
        "console.warning_suffix": "journal(aux) non lu(s) ou partiellement lu(s)",
        "console.category_distribution": "Répartition par catégorie",
        "console.priority_actions": "Actions prioritaires",
        "console.severity": "Gravité",
        "console.category": "Catégorie",
        "console.event": "Événement",
        "console.occ": "Occ.",
        "console.no_priority": "Aucune action prioritaire détectée dans les événements lus.",
        "html.generated": "Rapport généré le",
        "html.period": "Période",
        "html.logs": "Journaux analysés",
        "html.summary": "Résumé des événements",
        "html.details": "Accès direct aux détails",
        "html.priority_actions": "Actions prioritaires",
        "html.action": "Action proposée",
        "html.severity": "Gravité",
        "html.category": "Catégorie",
        "html.event": "Événement",
        "html.no_category": "Aucun événement dans cette catégorie.",
        "html.back": "Retour au résumé",
        "html.warnings": "Avertissements",
        "html.read_full": "Lire le texte en entier",
        "html.log": "Journal",
        "html.level": "Niveau",
        "html.occurrences": "Occurrences",
        "html.frequency": "Fréquence",
        "html.score": "Score",
        "html.first": "Première occurrence",
        "html.last": "Dernière occurrence",
        "html.why": "Pourquoi",
        "html.no_priority": "Aucune action prioritaire détectée dans les événements lus.",
        "progress.start": "Analyse en cours ",
        "progress.done": " terminé.",
        "arg.description": "Analyse les journaux Windows récents, classe les événements et propose des actions.",
        "arg.days": "Nombre de jours à analyser. Défaut : 30.",
        "arg.max_events": "Nombre maximal d'événements lus au total. Défaut : 5000.",
        "arg.logs": "Journaux Windows à lire.",
        "arg.include_info": "Inclure aussi les événements Information, plus bavards.",
        "arg.message_limit": "Longueur maximale des exemples de message dans le HTML.",
        "arg.html": "Fichier HTML de sortie. Défaut : reports\\DTLexplains_<machine>_<date>.html",
        "arg.json": "Fichier JSON de sortie optionnel.",
        "arg.version": "Affiche la version et quitte.",
        "error.powershell_missing": "powershell.exe introuvable. DTLexplains doit être lancé sous Windows.",
        "error.powershell_timeout": "Timeout PowerShell après {timeout} secondes.",
        "error.powershell_code": "PowerShell a retourné le code {code}.",
        "error.invalid_json": "PowerShell n'a pas retourné un JSON valide : ",
        "error.log_unread": "Journal {log} non lu : {error}",
        "error.days": "%DTLexplains-E-SYNTAX, --days doit être >= 1",
        "error.max_events": "%DTLexplains-E-SYNTAX, --max-events doit être >= 1",
        "error.message_limit": "%DTLexplains-E-SYNTAX, --message-limit doit être >= 80",
        "error.platform": "%DTLexplains-E-PLATFORM, DTLexplains lit les journaux Windows : lance-le sur un poste Windows.",
        "interrupt": "%DTLexplains-I-INTERRUPT, Interrompu par l'utilisateur.",
        "unexpected": "%DTLexplains-F-UNEXPECTED, Erreur inattendue :",
    },
    "en": {
        "level.1": "Critical",
        "level.2": "Error",
        "level.3": "Warning",
        "level.4": "Information",
        "level.5": "Verbose",
        "category.hardware": "Hardware / disk / driver",
        "category.boot_power": "Startup / power",
        "category.security": "Security / authentication",
        "category.network": "Network / DNS / DHCP / SMB",
        "category.updates": "Windows updates",
        "category.service": "Windows services",
        "category.application": "Applications",
        "category.powershell": "PowerShell / scripts",
        "category.normal": "Normal / common / generally benign",
        "category_short.hardware": "💽 Hardware",
        "category_short.boot_power": "⏻ Startup",
        "category_short.security": "🛡 Security",
        "category_short.network": "🌐 Network",
        "category_short.updates": "🔄 Updates",
        "category_short.service": "⚙ Services",
        "category_short.application": "🧩 Applications",
        "category_short.powershell": "⌁ PowerShell",
        "category_short.normal": "✓ Normal",
        "severity.urgent": "Urgent",
        "severity.important": "Important",
        "severity.watch": "To watch",
        "severity.plan": "To plan",
        "severity.normal": "Normal",
        "badge.urgent": "URGENT",
        "badge.important": "IMPORTANT",
        "badge.watch": "WATCH",
        "badge.plan": "PLAN",
        "badge.normal": "NORMAL",
        "frequency.very_frequent": "Very frequent",
        "frequency.frequent": "Frequent",
        "frequency.occasional": "Occasional",
        "frequency.rare": "Rare",
        "occurrence.one": "occurrence",
        "occurrence.many": "occurrences",
        "console.machine": "Machine",
        "console.period": "Period analyzed",
        "console.days": "days",
        "console.events_read": "Events read",
        "console.groups": "Groups detected",
        "console.html_report": "HTML report",
        "console.warnings": "Warnings",
        "console.warning_suffix": "log(s) unread or partially read",
        "console.category_distribution": "Distribution by category",
        "console.priority_actions": "Priority actions",
        "console.severity": "Severity",
        "console.category": "Category",
        "console.event": "Event",
        "console.occ": "Occ.",
        "console.no_priority": "No priority action detected in the events read.",
        "html.generated": "Report generated on",
        "html.period": "Period",
        "html.logs": "Logs analyzed",
        "html.summary": "Event summary",
        "html.details": "Direct access to details",
        "html.priority_actions": "Priority actions",
        "html.action": "Suggested action",
        "html.severity": "Severity",
        "html.category": "Category",
        "html.event": "Event",
        "html.no_category": "No event in this category.",
        "html.back": "Back to summary",
        "html.warnings": "Warnings",
        "html.read_full": "Read full text",
        "html.log": "Log",
        "html.level": "Level",
        "html.occurrences": "Occurrences",
        "html.frequency": "Frequency",
        "html.score": "Score",
        "html.first": "First occurrence",
        "html.last": "Last occurrence",
        "html.why": "Why",
        "html.no_priority": "No priority action detected in the events read.",
        "progress.start": "Analysis in progress ",
        "progress.done": " done.",
        "arg.description": "Analyzes recent Windows logs, classifies events and suggests actions.",
        "arg.days": "Number of days to analyze. Default: 30.",
        "arg.max_events": "Maximum number of events read in total. Default: 5000.",
        "arg.logs": "Windows logs to read.",
        "arg.include_info": "Also include Information events, which are more verbose.",
        "arg.message_limit": "Maximum length of sample messages in HTML.",
        "arg.html": "Output HTML file. Default: reports\\DTLexplains_<machine>_<date>.html",
        "arg.json": "Optional output JSON file.",
        "arg.version": "Shows the version and exits.",
        "error.powershell_missing": "powershell.exe not found. DTLexplains must be run on Windows.",
        "error.powershell_timeout": "PowerShell timeout after {timeout} seconds.",
        "error.powershell_code": "PowerShell returned code {code}.",
        "error.invalid_json": "PowerShell did not return valid JSON: ",
        "error.log_unread": "Log {log} not read: {error}",
        "error.days": "%DTLexplains-E-SYNTAX, --days must be >= 1",
        "error.max_events": "%DTLexplains-E-SYNTAX, --max-events must be >= 1",
        "error.message_limit": "%DTLexplains-E-SYNTAX, --message-limit must be >= 80",
        "error.platform": "%DTLexplains-E-PLATFORM, DTLexplains reads Windows logs: run it on a Windows computer.",
        "interrupt": "%DTLexplains-I-INTERRUPT, Interrupted by user.",
        "unexpected": "%DTLexplains-F-UNEXPECTED, Unexpected error:",
    },
}

TEXT["fr"].update({
    "rule.security_4625.why": "Échecs d'ouverture de session. Cause fréquente : mot de passe enregistré obsolète, service mal configuré ou tentative répétée.",
    "rule.security_4625.action": "Identifier le compte, le type de connexion et l'adresse source. Corriger les identifiants enregistrés ou investiguer si la rafale est anormale.",
    "rule.security_account.why": "Modification de compte ou de groupe local. C'est normal après une intervention, suspect sinon.",
    "rule.security_account.action": "Vérifier qui a effectué l'action, à quelle heure, puis documenter ou révoquer si ce n'était pas prévu.",
    "rule.security_1102.why": "Le journal d'audit Security a été effacé. C'est rare et significatif.",
    "rule.security_1102.action": "Contrôler immédiatement le compte auteur, sauvegarder les journaux restants et rechercher d'autres traces au même horaire.",
    "rule.security_normal.why": "Ouverture, fermeture de session, privilèges ou création de processus. Utile pour la chronologie, rarement problématique seul.",
    "rule.security_normal.action": "Ne pas traiter isolément. Utiliser seulement pour corréler un incident ou une intervention.",
    "rule.security_generic.why": "Événement de sécurité connu de Windows, mais pas encore documenté par la base DTLexplains. Il n'est pas possible de conclure sur sa gravité à partir de ce seul événement.",
    "rule.security_generic.action": "Consulter le compte, le poste source, le type de connexion et l'heure, puis corréler avec les autres événements proches.",
    "rule.storage.why": "Windows signale un problème de stockage, de volume ou de pilote disque.",
    "rule.storage.action": "Sauvegarder avant tout. Contrôler l'état SMART constructeur, puis envisager chkdsk uniquement après sauvegarde.",
    "rule.whea.why": "Erreur matérielle signalée par WHEA : CPU, mémoire, bus PCIe, alimentation ou pilote bas niveau.",
    "rule.whea.action": "Vérifier température, RAM, BIOS/UEFI et pilotes chipset/GPU. Si répétitif, lancer un diagnostic matériel.",
    "rule.display.why": "Le pilote graphique ou l'affichage a signalé une erreur.",
    "rule.display.action": "Mettre à jour ou réinstaller proprement le pilote graphique. Vérifier le lien avec veille, jeux, vidéo ou écran externe.",
    "rule.kernel_power.why": "Arrêt brutal ou redémarrage sans extinction propre. Causes fréquentes : coupure, plantage, alimentation, surchauffe ou appui long sur Power.",
    "rule.kernel_power.action": "Rechercher ce qui s'est passé à l'heure indiquée. Vérifier alimentation, batterie/onduleur, surchauffe, écrans bleus et pilotes.",
    "rule.bugcheck.why": "Windows a enregistré un bugcheck, donc probablement un écran bleu.",
    "rule.bugcheck.action": "Conserver les minidumps, relever le code d'arrêt et chercher le pilote ou matériel fautif avant toute réinstallation.",
    "rule.eventlog_start_stop.why": "Démarrage ou arrêt normal du service journal d'événements.",
    "rule.eventlog_start_stop.action": "Aucune action, sauf pour reconstituer la chronologie.",
    "rule.eventlog_6008.why": "Windows indique que l'arrêt précédent était inattendu.",
    "rule.eventlog_6008.action": "Rechercher Kernel-Power 41 et les événements juste avant l'arrêt.",
    "rule.scm_7000_7009.why": "Échec de démarrage du service.",
    "rule.scm_common.action": "Identifier le service cité. Vérifier dépendances, compte de service, chemin exécutable, droits et événements voisins.",
    "rule.scm_failure.why": "Un service Windows ou applicatif n'a pas démarré, a expiré ou s'est arrêté anormalement.",
    "rule.scm_change.why": "Changement de configuration ou installation d'un service.",
    "rule.scm_change.action": "Vérifier que le service installé ou modifié correspond à une action attendue. Inspecter le chemin binaire si le nom est inconnu.",
    "rule.scm_generic.why": "Événement du gestionnaire de services.",
    "rule.scm_generic.action": "Lire le nom du service dans le message et vérifier s'il est attendu sur cette machine.",
    "rule.netwtw08_5011.why": "Le pilote Intel Wi-Fi signale un problème interne. Cela pointe plutôt vers le pilote, le firmware ou le BIOS que vers un paramètre Windows manquant.",
    "rule.netwtw08_5011.action": "Mettre à jour le pilote Intel Wi-Fi depuis le constructeur du PC ou Intel, puis vérifier les mises à jour BIOS/UEFI si l'erreur revient.",
    "rule.network.why": "Windows signale un problème réseau, DNS, DHCP, SMB ou pilote carte réseau.",
    "rule.network.action": "Comparer IP/passerelle/DNS avec un poste sain. Tester ping passerelle, résolution DNS, accès par IP puis par nom.",
    "rule.schannel.why": "Erreur TLS/SSL Schannel. Souvent liée à un serveur distant, un vieux protocole TLS, un certificat ou une application bavarde.",
    "rule.schannel.action": "Chercher l'application au même horaire. Surveiller si cela bloque réellement un usage ; ne pas corriger au hasard si tout fonctionne.",
    "rule.winreagent_4502.why": "La maintenance de l'environnement de récupération Windows a échoué.",
    "rule.winreagent_4502.action": "Consulter le message ci-dessous pour identifier le composant concerné.",
    "rule.store_0x80073d02.why": "Microsoft Store était ouvert pendant la mise à jour.",
    "rule.store_0x80073d02.action": "Fermer Store puis relancer Windows Update.",
    "rule.update_generic.why": "Installation, mise à jour ou maintenance Windows/applicative en erreur ou à contrôler.",
    "rule.update_generic.action": "Consulter l'historique Windows Update et relancer après redémarrage. Si répétitif : DISM puis sfc /scannow.",
    "rule.app_crash.why": "Une application plante ou ne répond plus.",
    "rule.app_crash.action": "Identifier l'exécutable fautif, mettre à jour l'application, tester un profil utilisateur propre si le crash est récurrent.",
    "rule.appx.why": "Événement lié aux applications Store/AppX. Très fréquent sur Windows.",
    "rule.appx.action": "Surveiller seulement si une application Windows ne se lance pas.",
    "rule.powershell_error.why": "Erreur ou avertissement PowerShell. Peut venir d'un script de maintenance, GLPI, sauvegarde ou tâche planifiée.",
    "rule.powershell_error.action": "Lire le script ou la commande dans le détail. Vérifier les tâches planifiées et les droits du compte d'exécution.",
    "rule.powershell_info.why": "Trace PowerShell informative.",
    "rule.powershell_info.action": "Utiliser seulement pour reconstituer la chronologie d'une intervention ou d'un script.",
    "rule.dcom.why": "DistributedCOM 10016/10010 est très fréquent sur Windows et rarement la cause première d'une panne.",
    "rule.dcom.action": "Ne pas modifier les permissions DCOM sans symptôme clair. Chercher plutôt les erreurs matérielles, services ou applications autour de la même heure.",
    "rule.restartmanager.why": "Restart Manager accompagne souvent installations et mises à jour.",
    "rule.restartmanager.action": "À utiliser comme indice chronologique, pas comme erreur principale.",
    "rule.critical_generic.why": "Événement critique connu de Windows, mais pas encore documenté par la base DTLexplains. Le niveau critique justifie une vérification, sans conclure sur la cause à partir de ce seul événement.",
    "rule.critical_generic.action": "Lire le message Windows et corréler avec les événements des 5 minutes avant/après.",
    "rule.error_generic.why": "Événement connu de Windows, mais pas encore documenté par la base DTLexplains. Il n'est pas possible de conclure sur sa gravité à partir de ce seul événement.",
    "rule.error_generic.action": "Surveiller si l'événement revient. S'il est fréquent ou lié à un symptôme utilisateur, rechercher la source et l'identifiant de l'événement.",
    "rule.warning_generic.why": "Avertissement connu de Windows, mais pas encore documenté par la base DTLexplains. Beaucoup d'avertissements Windows sont secondaires sans symptôme correspondant.",
    "rule.warning_generic.action": "Classer comme secondaire sauf répétition massive ou symptôme utilisateur au même horaire.",
    "rule.info_generic.why": "Information Windows conservée pour la chronologie.",
    "rule.info_generic.action": "Aucune action directe.",
})

TEXT["en"].update({
    "rule.security_4625.why": "Failed sign-in attempts. Common causes: stale saved password, misconfigured service, or repeated attempts.",
    "rule.security_4625.action": "Identify the account, logon type and source address. Fix saved credentials or investigate if the burst is abnormal.",
    "rule.security_account.why": "Local account or group modification. Normal after maintenance, suspicious otherwise.",
    "rule.security_account.action": "Check who performed the action and when, then document it or revert it if it was not expected.",
    "rule.security_1102.why": "The Security audit log was cleared. This is rare and meaningful.",
    "rule.security_1102.action": "Immediately check the account involved, preserve remaining logs and look for other traces around the same time.",
    "rule.security_normal.why": "Logon, logoff, privileges or process creation. Useful for timelines, rarely a problem on its own.",
    "rule.security_normal.action": "Do not handle in isolation. Use it only to correlate an incident or maintenance activity.",
    "rule.security_generic.why": "Windows security event known to Windows, but not yet documented by the DTLexplains knowledge base. Its severity cannot be concluded from this event alone.",
    "rule.security_generic.action": "Check the account, source computer, logon type and time, then correlate with nearby events.",
    "rule.storage.why": "Windows reports a storage, volume or disk driver problem.",
    "rule.storage.action": "Back up first. Check the manufacturer's SMART status, then consider chkdsk only after backup.",
    "rule.whea.why": "Hardware error reported by WHEA: CPU, memory, PCIe bus, power supply or low-level driver.",
    "rule.whea.action": "Check temperatures, RAM, BIOS/UEFI and chipset/GPU drivers. If repeated, run hardware diagnostics.",
    "rule.display.why": "The graphics driver or display subsystem reported an error.",
    "rule.display.action": "Update or cleanly reinstall the graphics driver. Check whether it relates to sleep, games, video or an external display.",
    "rule.kernel_power.why": "Abrupt shutdown or restart without a clean power-off. Common causes: power loss, crash, power supply, overheating or long press on Power.",
    "rule.kernel_power.action": "Find what happened at that time. Check power, battery/UPS, overheating, blue screens and drivers.",
    "rule.bugcheck.why": "Windows recorded a bugcheck, probably a blue screen.",
    "rule.bugcheck.action": "Keep minidumps, note the stop code and identify the faulty driver or hardware before reinstalling anything.",
    "rule.eventlog_start_stop.why": "Normal start or stop of the Windows Event Log service.",
    "rule.eventlog_start_stop.action": "No action, except to rebuild the timeline.",
    "rule.eventlog_6008.why": "Windows indicates that the previous shutdown was unexpected.",
    "rule.eventlog_6008.action": "Look for Kernel-Power 41 and events just before the shutdown.",
    "rule.scm_7000_7009.why": "Service startup failure.",
    "rule.scm_common.action": "Identify the service mentioned. Check dependencies, service account, executable path, permissions and nearby events.",
    "rule.scm_failure.why": "A Windows or application service did not start, timed out or stopped abnormally.",
    "rule.scm_change.why": "Service configuration change or service installation.",
    "rule.scm_change.action": "Check that the installed or modified service matches an expected action. Inspect the binary path if the name is unknown.",
    "rule.scm_generic.why": "Service Control Manager event.",
    "rule.scm_generic.action": "Read the service name in the message and check whether it is expected on this machine.",
    "rule.netwtw08_5011.why": "The Intel Wi-Fi driver reports an internal problem. This points more to the driver, firmware or BIOS than to a missing Windows setting.",
    "rule.netwtw08_5011.action": "Update the Intel Wi-Fi driver from the PC vendor or Intel, then check BIOS/UEFI updates if the error returns.",
    "rule.network.why": "Windows reports a network, DNS, DHCP, SMB or network adapter driver problem.",
    "rule.network.action": "Compare IP/gateway/DNS settings with a healthy machine. Test gateway ping, DNS resolution, access by IP and then by name.",
    "rule.schannel.why": "Schannel TLS/SSL error. Often related to a remote server, old TLS protocol, certificate or noisy application.",
    "rule.schannel.action": "Find the application at the same time. Monitor whether it actually blocks usage; do not change settings blindly if everything works.",
    "rule.winreagent_4502.why": "Windows Recovery Environment maintenance failed.",
    "rule.winreagent_4502.action": "Review the message below to identify the affected component.",
    "rule.store_0x80073d02.why": "Microsoft Store was open during the update.",
    "rule.store_0x80073d02.action": "Close Store, then run Windows Update again.",
    "rule.update_generic.why": "Windows or application installation, update or maintenance failed or needs review.",
    "rule.update_generic.action": "Check Windows Update history and retry after reboot. If repeated: run DISM, then sfc /scannow.",
    "rule.app_crash.why": "An application crashes or stops responding.",
    "rule.app_crash.action": "Identify the executable, update the application, and test a clean user profile if the crash recurs.",
    "rule.appx.why": "Store/AppX application event. Very common on Windows.",
    "rule.appx.action": "Monitor only if a Windows application does not start.",
    "rule.powershell_error.why": "PowerShell error or warning. It may come from a maintenance script, GLPI, backup or scheduled task.",
    "rule.powershell_error.action": "Read the script or command in the details. Check scheduled tasks and the execution account permissions.",
    "rule.powershell_info.why": "Informational PowerShell trace.",
    "rule.powershell_info.action": "Use only to rebuild the timeline of a maintenance action or script.",
    "rule.dcom.why": "DistributedCOM 10016/10010 is very common on Windows and is rarely the root cause of an outage.",
    "rule.dcom.action": "Do not change DCOM permissions without a clear symptom. Look instead for hardware, service or application errors around the same time.",
    "rule.restartmanager.why": "Restart Manager often accompanies installations and updates.",
    "rule.restartmanager.action": "Use it as a timeline clue, not as the main error.",
    "rule.critical_generic.why": "Critical Windows event known to Windows, but not yet documented by the DTLexplains knowledge base. The critical level deserves verification, without concluding the cause from this event alone.",
    "rule.critical_generic.action": "Read the Windows message and correlate with events from 5 minutes before and after.",
    "rule.error_generic.why": "Event known to Windows, but not yet documented by the DTLexplains knowledge base. Its severity cannot be concluded from this event alone.",
    "rule.error_generic.action": "Watch whether the event returns. If it is frequent or linked to a user symptom, search for the event source and ID.",
    "rule.warning_generic.why": "Windows warning known to Windows, but not yet documented by the DTLexplains knowledge base. Many Windows warnings are secondary when no matching symptom exists.",
    "rule.warning_generic.action": "Treat as secondary unless it repeats massively or matches a user symptom at the same time.",
    "rule.info_generic.why": "Windows information kept for the timeline.",
    "rule.info_generic.action": "No direct action.",
})

SEVERITY_ORDER = {
    "urgent": 0,
    "important": 1,
    "watch": 2,
    "plan": 3,
    "normal": 4,
}


@dataclass
class RawEvent:
    log: str
    provider: str
    event_id: int
    level: int
    level_name: str
    time_created: str
    record_id: Optional[int]
    machine: str
    user: str
    message: str


@dataclass
class EventGroup:
    log: str
    provider: str
    event_id: int
    level: int
    level_name: str
    count: int
    frequency: str
    first_seen: str
    last_seen: str
    machine: str
    sample_message: str
    full_message: str
    event_ids: List[int]
    category: str
    severity: str
    score: int
    why: str
    action: str


@dataclass
class PriorityAction:
    severity: str
    severity_label: str
    category: str
    category_label: str
    event_label: str
    count: int
    action: str


def detect_system_language() -> str:
    candidates: List[str] = []
    if os.name == "nt":
        try:
            lang_id = ctypes.windll.kernel32.GetUserDefaultUILanguage()
            windows_locale = locale.windows_locale.get(lang_id)
            if windows_locale:
                candidates.append(windows_locale)
        except (AttributeError, OSError, ValueError):
            pass
    try:
        candidates.extend(value for value in locale.getlocale() if value)
    except (TypeError, ValueError):
        pass
    candidates.extend(
        value
        for value in (
            os.environ.get("LANG"),
            os.environ.get("LANGUAGE"),
        )
        if value
    )
    for value in candidates:
        if str(value).strip().lower().startswith("fr"):
            return "fr"
    return "en"


LANG = detect_system_language()


def tr(key: str, **kwargs: Any) -> str:
    text = TEXT.get(LANG, TEXT["en"]).get(key, TEXT["fr"].get(key, key))
    return text.format(**kwargs) if kwargs else text


def level_name(level: int) -> str:
    return tr(f"level.{level}") if f"level.{level}" in TEXT.get(LANG, {}) else str(level)


def severity_badge(severity: str) -> str:
    return tr(f"badge.{severity}")


def configure_console() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def now_string() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def safe_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def shorten(text: str, limit: int = 260) -> str:
    one_line = " ".join(safe_str(text).split())
    if len(one_line) <= limit:
        return one_line
    return one_line[: max(0, limit - 3)] + "..."


def slug(text: str) -> str:
    return "".join(ch.lower() if ch.isalnum() else "-" for ch in text).strip("-")


def quote_ps_string(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def ps_json(script: str, timeout: int = 120) -> List[Dict[str, Any]]:
    command = [
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; " + script,
    ]

    try:
        result = subprocess.run(command, capture_output=True, timeout=timeout)
    except FileNotFoundError as exc:
        raise RuntimeError(tr("error.powershell_missing")) from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(tr("error.powershell_timeout", timeout=timeout)) from exc

    stdout = result.stdout.decode("utf-8", errors="replace").strip()
    stderr = result.stderr.decode("utf-8", errors="replace").strip()

    if result.returncode != 0 and not stdout:
        raise RuntimeError(stderr or tr("error.powershell_code", code=result.returncode))

    if not stdout:
        return []

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(tr("error.invalid_json") + shorten(stdout, 500)) from exc

    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return [row for row in data if isinstance(row, dict)]
    return []


def collect_events(
    logs: Sequence[str],
    days: int,
    max_events: int,
    include_info: bool,
    progress_callback: Optional[Callable[[str], None]] = None,
) -> Tuple[List[RawEvent], List[str]]:
    levels = "1,2,3" if not include_info else "1,2,3,4"
    start_iso = (_dt.datetime.now() - _dt.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
    events: List[RawEvent] = []
    warnings: List[str] = []
    per_log_limit = max(1, max_events // max(1, len(logs)))

    for log in logs:
        if progress_callback:
            progress_callback(log)
        script = f"""
$ErrorActionPreference = 'SilentlyContinue'
$logName = {quote_ps_string(log)}
$start = [datetime]{quote_ps_string(start_iso)}
$items = Get-WinEvent -FilterHashtable @{{LogName=$logName; StartTime=$start; Level={levels}}} -MaxEvents {per_log_limit} -ErrorAction SilentlyContinue |
    Select-Object LogName, ProviderName, Id, Level, LevelDisplayName, RecordId, MachineName, UserId,
        @{{Name='TimeCreated';Expression={{ $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') }}}},
        Message
if ($null -eq $items) {{ @() | ConvertTo-Json -Compress -Depth 4 }}
else {{ $items | ConvertTo-Json -Compress -Depth 4 }}
"""
        try:
            rows = ps_json(script)
        except RuntimeError as exc:
            warnings.append(tr("error.log_unread", log=log, error=exc))
            continue

        for row in rows:
            level = int(row.get("Level") or 0)
            event_id = int(row.get("Id") or 0)
            events.append(
                RawEvent(
                    log=safe_str(row.get("LogName"), log),
                    provider=safe_str(row.get("ProviderName"), "N/A"),
                    event_id=event_id,
                    level=level,
                    level_name=level_name(level),
                    time_created=safe_str(row.get("TimeCreated")),
                    record_id=row.get("RecordId"),
                    machine=safe_str(row.get("MachineName"), socket.gethostname()),
                    user=safe_str(row.get("UserId"), ""),
                    message=safe_str(row.get("Message")),
                )
            )

    return events, warnings


def provider_norm(provider: str) -> str:
    return safe_str(provider).lower().replace(" ", "").replace("-", "")


def message_norm(message: str) -> str:
    return safe_str(message).lower()


def frequency_for_count(count: int) -> str:
    if count >= 20:
        return tr("frequency.very_frequent")
    if count >= 5:
        return tr("frequency.frequent")
    if count >= 2:
        return tr("frequency.occasional")
    return tr("frequency.rare")


def rule_for_event(log: str, provider: str, event_id: int, level: int, message: str, count: int) -> Tuple[str, str, str, str]:
    p = provider_norm(provider)
    m = message_norm(message)
    log_l = log.lower()

    if log_l == "security":
        if event_id == 4625:
            return (
                "security", "important",
                tr("rule.security_4625.why"),
                tr("rule.security_4625.action"),
            )
        if event_id in (4720, 4722, 4723, 4724, 4725, 4726, 4732, 4733):
            return (
                "security", "urgent",
                tr("rule.security_account.why"),
                tr("rule.security_account.action"),
            )
        if event_id == 1102:
            return (
                "security", "urgent",
                tr("rule.security_1102.why"),
                tr("rule.security_1102.action"),
            )
        if event_id in (4624, 4634, 4672, 4688):
            return (
                "normal", "normal",
                tr("rule.security_normal.why"),
                tr("rule.security_normal.action"),
            )
        return (
            "security", "watch" if level <= 3 else "normal",
            tr("rule.security_generic.why"),
            tr("rule.security_generic.action"),
        )

    if any(x in p for x in ("disk", "ntfs", "storahci", "stornvme", "volmgr", "partmgr")):
        return (
            "hardware", "urgent" if level <= 2 else "important",
            tr("rule.storage.why"),
            tr("rule.storage.action"),
        )
    if any(x in p for x in ("whealogger", "whea")):
        return (
            "hardware", "urgent",
            tr("rule.whea.why"),
            tr("rule.whea.action"),
        )
    if "display" in p or "nvlddmkm" in p or "amdkmdag" in p or "igfx" in p:
        return (
            "hardware", "important",
            tr("rule.display.why"),
            tr("rule.display.action"),
        )

    if "kernelpower" in p or event_id == 41:
        return (
            "boot_power", "urgent",
            tr("rule.kernel_power.why"),
            tr("rule.kernel_power.action"),
        )
    if "bugcheck" in p or (event_id == 1001 and "bugcheck" in m):
        return (
            "boot_power", "urgent",
            tr("rule.bugcheck.why"),
            tr("rule.bugcheck.action"),
        )
    if "eventlog" in p and event_id in (6005, 6006):
        return (
            "normal", "normal",
            tr("rule.eventlog_start_stop.why"),
            tr("rule.eventlog_start_stop.action"),
        )
    if "eventlog" in p and event_id == 6008:
        return (
            "boot_power", "important",
            tr("rule.eventlog_6008.why"),
            tr("rule.eventlog_6008.action"),
        )

    if "servicecontrolmanager" in p:
        if event_id in (7000, 7009):
            return (
                "service", "important",
                tr("rule.scm_7000_7009.why"),
                tr("rule.scm_common.action"),
            )
        if event_id in (7001, 7011, 7022, 7023, 7024, 7031, 7034):
            return (
                "service", "important",
                tr("rule.scm_failure.why"),
                tr("rule.scm_common.action"),
            )
        if event_id in (7040, 7045):
            return (
                "service", "watch",
                tr("rule.scm_change.why"),
                tr("rule.scm_change.action"),
            )
        return (
            "service", "watch" if level <= 3 else "normal",
            tr("rule.scm_generic.why"),
            tr("rule.scm_generic.action"),
        )

    if "netwtw08" in p and event_id == 5011:
        return (
            "network", "important",
            tr("rule.netwtw08_5011.why"),
            tr("rule.netwtw08_5011.action"),
        )
    if any(x in p for x in ("dhcp", "dnsclient", "tcpip", "netwtw", "netlogon", "lanmanworkstation", "srv")):
        return (
            "network", "important" if level <= 2 else "watch",
            tr("rule.network.why"),
            tr("rule.network.action"),
        )
    if "schannel" in p:
        return (
            "network", "watch",
            tr("rule.schannel.why"),
            tr("rule.schannel.action"),
        )

    if "winreagent" in p and event_id == 4502:
        return (
            "updates", "important",
            tr("rule.winreagent_4502.why"),
            tr("rule.winreagent_4502.action"),
        )
    if "windowsupdate" in p and event_id == 20 and "0x80073d02" in m and "microsoft.windowsstore" in m:
        return (
            "updates", "plan",
            tr("rule.store_0x80073d02.why"),
            tr("rule.store_0x80073d02.action"),
        )
    if any(x in p for x in ("windowsupdateclient", "servicing", "setup", "msiinstaller", "wusa")) or log_l == "setup":
        return (
            "updates", "important" if level <= 2 else "plan",
            tr("rule.update_generic.why"),
            tr("rule.update_generic.action"),
        )

    if any(x in p for x in ("applicationerror", "applicationhang", "windowserrorreporting", "wer")):
        return (
            "application", "important" if count >= 3 else "watch",
            tr("rule.app_crash.why"),
            tr("rule.app_crash.action"),
        )
    if "appmodelruntime" in p or "appx" in p:
        return (
            "normal", "normal",
            tr("rule.appx.why"),
            tr("rule.appx.action"),
        )

    if "powershell" in p or log_l == "windows powershell":
        if level <= 3:
            return (
                "powershell", "watch",
                tr("rule.powershell_error.why"),
                tr("rule.powershell_error.action"),
            )
        return (
            "normal", "normal",
            tr("rule.powershell_info.why"),
            tr("rule.powershell_info.action"),
        )

    if "distributedcom" in p and event_id in (10016, 10010):
        return (
            "normal", "normal",
            tr("rule.dcom.why"),
            tr("rule.dcom.action"),
        )
    if "restartmanager" in p:
        return (
            "normal", "normal",
            tr("rule.restartmanager.why"),
            tr("rule.restartmanager.action"),
        )

    if level == 1:
        return (
            "boot_power", "urgent",
            tr("rule.critical_generic.why"),
            tr("rule.critical_generic.action"),
        )
    if level == 2:
        return (
            "application", "watch",
            tr("rule.error_generic.why"),
            tr("rule.error_generic.action"),
        )
    if level == 3:
        return (
            "normal", "normal" if count < 5 else "plan",
            tr("rule.warning_generic.why"),
            tr("rule.warning_generic.action"),
        )
    return (
        "normal", "normal",
        tr("rule.info_generic.why"),
        tr("rule.info_generic.action"),
    )


def score_event(severity: str, level: int, count: int, last_seen: str) -> int:
    base = {"urgent": 100, "important": 75, "watch": 50, "plan": 35, "normal": 5}.get(severity, 25)
    base += max(0, 5 - min(level or 5, 5)) * 5
    base += min(count, 20)
    try:
        last_dt = _dt.datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S")
        age_hours = (_dt.datetime.now() - last_dt).total_seconds() / 3600
        if age_hours <= 24:
            base += 15
        elif age_hours <= 72:
            base += 8
    except ValueError:
        pass
    return base


def summarize_events(events: Sequence[RawEvent]) -> List[EventGroup]:
    grouped: Dict[Tuple[Any, ...], Dict[str, Any]] = {}

    for event in events:
        p = provider_norm(event.provider)
        if "servicecontrolmanager" in p and event.event_id in (7000, 7009):
            key = (event.log, event.provider, "service-start-failure", event.level)
            normalized_event_id = 7000
        else:
            key = (event.log, event.provider, event.event_id, event.level)
            normalized_event_id = event.event_id
        item = grouped.setdefault(
            key,
            {
                "log": event.log,
                "provider": event.provider,
                "event_id": normalized_event_id,
                "event_ids": set(),
                "level": event.level,
                "level_name": event.level_name,
                "count": 0,
                "first_seen": event.time_created,
                "last_seen": event.time_created,
                "machine": event.machine,
                "sample_message": event.message,
                "messages": [],
            },
        )
        item["count"] += 1
        item["event_ids"].add(event.event_id)
        if event.time_created and (not item["first_seen"] or event.time_created < item["first_seen"]):
            item["first_seen"] = event.time_created
        if event.time_created and event.time_created > item["last_seen"]:
            item["last_seen"] = event.time_created
        if event.message:
            item["sample_message"] = event.message
            if event.message not in item["messages"] and len(item["messages"]) < 2:
                item["messages"].append(event.message)

    summaries: List[EventGroup] = []
    for item in grouped.values():
        sample_message = "\n\n---\n\n".join(item["messages"]) if item["messages"] else item["sample_message"]
        category, severity, why, action = rule_for_event(
            item["log"], item["provider"], item["event_id"], item["level"], sample_message, item["count"]
        )
        score = score_event(severity, item["level"], item["count"], item["last_seen"])
        summaries.append(
            EventGroup(
                log=item["log"],
                provider=item["provider"],
                event_id=item["event_id"],
                level=item["level"],
                level_name=item["level_name"],
                count=item["count"],
                frequency=frequency_for_count(item["count"]),
                first_seen=item["first_seen"],
                last_seen=item["last_seen"],
                machine=item["machine"],
                sample_message=shorten(sample_message, 800),
                full_message=sample_message,
                event_ids=sorted(item["event_ids"]),
                category=category,
                severity=severity,
                score=score,
                why=why,
                action=action,
            )
        )

    return sorted(
        summaries,
        key=lambda g: (
            CATEGORY_NUMBERS.get(g.category, 99),
            SEVERITY_ORDER.get(g.severity, 99),
            -g.score,
            -g.count,
            g.log,
            g.provider,
            g.event_id,
        ),
    )


def category_counts(groups: Sequence[EventGroup]) -> collections.Counter[str]:
    counts: collections.Counter[str] = collections.Counter()
    for group in groups:
        counts[group.category] += group.count
    return counts


def event_id_label(group: EventGroup) -> str:
    if len(group.event_ids) > 1:
        return "/".join(str(event_id) for event_id in group.event_ids)
    return str(group.event_id)


def provider_label(provider: str) -> str:
    p = provider_norm(provider)
    if "servicecontrolmanager" in p:
        return "SCM"
    if "windowsupdate" in p:
        return "WindowsUpdate"
    if provider.startswith("Microsoft-Windows-"):
        return provider.removeprefix("Microsoft-Windows-")
    return provider


def priority_event_label(group: EventGroup) -> str:
    return f"{provider_label(group.provider)} {event_id_label(group)}"


def occurrence_label(count: int) -> str:
    return tr("occurrence.one") if count == 1 else tr("occurrence.many")


def category_label(category: str, short: bool = False) -> str:
    if short:
        return tr(f"category_short.{category}")
    icon = CATEGORY_ICONS.get(category, "")
    title = tr(f"category.{category}")
    return f"{icon} {title}".strip()


def console_category_label(category: str, short: bool = False) -> str:
    title = tr(f"category_short.{category}") if short else tr(f"category.{category}")
    icon = CATEGORY_ICONS.get(category, "")
    if icon and title.startswith(icon):
        return title[len(icon):].strip()
    return title


def top_actions(groups: Sequence[EventGroup], limit: int = 8) -> List[PriorityAction]:
    actions: List[PriorityAction] = []
    seen = set()
    priority = sorted(
        groups,
        key=lambda g: (SEVERITY_ORDER.get(g.severity, 99), -g.score, -g.count),
    )
    for group in priority:
        if group.severity == "normal":
            continue
        key = (group.category, group.provider, group.event_id, group.action)
        if key in seen:
            continue
        seen.add(key)
        actions.append(
            PriorityAction(
                severity=group.severity,
                severity_label=severity_badge(group.severity),
                category=group.category,
                category_label=category_label(group.category, short=True),
                event_label=priority_event_label(group),
                count=group.count,
                action=group.action,
            )
        )
        if len(actions) >= limit:
            break
    return actions


def build_console_summary(groups: Sequence[EventGroup], raw_count: int, warnings: Sequence[str], args: argparse.Namespace, html_path: str) -> str:
    counts = category_counts(groups)
    actions = top_actions(groups)
    lines: List[str] = []

    lines.append(f"{APP_NAME} {APP_VERSION}")
    lines.append(f"{tr('console.machine'):<21}: {socket.gethostname()}")
    lines.append(f"{tr('console.period'):<21}: {args.days} {tr('console.days')}")
    lines.append(f"{tr('console.events_read'):<21}: {raw_count}")
    lines.append(f"{tr('console.groups'):<21}: {len(groups)}")
    lines.append(f"{tr('console.html_report'):<21}: {html_path}")
    if warnings:
        lines.append(f"{tr('console.warnings'):<21}: {len(warnings)} {tr('console.warning_suffix')}")
    lines.append("")
    lines.append(tr("console.category_distribution"))
    lines.append("-" * 72)
    for category in CATEGORY_ORDER:
        number = CATEGORY_NUMBERS[category]
        title = console_category_label(category)
        lines.append(f"{number}. {title:<40} {counts.get(category, 0)}")
    lines.append("")
    lines.append(tr("console.priority_actions"))
    lines.append("-" * 72)
    if actions:
        lines.append(f"{tr('console.severity'):<12} {tr('console.category'):<16} {tr('console.event'):<28} {tr('console.occ'):>5}")
        lines.append("-" * 72)
        for action in actions:
            lines.append(
                f"{action.severity_label:<12} "
                f"{console_category_label(action.category, short=True):<16} "
                f"{action.event_label:<28} "
                f"{action.count:>5}"
            )
    else:
        lines.append(tr("console.no_priority"))
    return "\n".join(lines)


def html_escape(text: Any) -> str:
    return html.escape(safe_str(text))


def build_html_report(groups: Sequence[EventGroup], raw_count: int, warnings: Sequence[str], args: argparse.Namespace) -> str:
    counts = category_counts(groups)
    actions = top_actions(groups)
    generated_at = now_string()
    host = socket.gethostname()
    logs_label = ", ".join(args.logs)
    html_lang = "fr" if LANG == "fr" else "en"

    css = """
:root{
  --bg:#0d0f14;
  --bg-alt:#0f1218;
  --panel:#16191f;
  --panel-hover:#1c202a;
  --panel2:#1f232d;
  --text:#e4e6eb;
  --text-secondary:#c0c5d0;
  --muted:#8b919e;
  --line:#2d3139;
  --line-light:#3a404d;
  --link:#5dade2;
  --link-hover:#85c1e9;
  --accent:#5dade2;
  --urgent:#c33c26;
  --important:#d97706;
  --watch:#c0a000;
  --plan:#0891b2;
  --normal:#059669;
}
html{scroll-behavior:smooth}
body{
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Helvetica Neue",sans-serif;
  background:var(--bg);
  color:var(--text);
  margin:0;
  padding:0;
  line-height:1.6;
}
main{max-width:1200px;margin:0 auto;padding:40px 28px}
h1{
  margin:0 0 12px 0;
  color:#fff;
  font-size:36px;
  font-weight:700;
  letter-spacing:-0.5px;
}
h2{
  margin:48px 0 16px 0;
  color:#fff;
  font-size:24px;
  font-weight:600;
  border-bottom:2px solid var(--line-light);
  padding-bottom:12px;
  position:relative;
}
h3{
  margin:0 0 12px 0;
  font-size:16px;
  font-weight:600;
  color:var(--text);
}
.meta-block{
  margin-bottom:28px;
  padding:12px 0;
}
.meta{
  color:var(--muted);
  font-size:14px;
  margin:0;
  padding:0;
}
.grid{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(240px,1fr));
  gap:16px;
  margin:24px 0;
}
.box{
  background:var(--panel);
  border:1px solid var(--line);
  border-radius:12px;
  padding:20px;
  transition:all 0.3s cubic-bezier(0.4,0,0.2,1);
  cursor:default;
}
.box:hover{
  background:var(--panel-hover);
  border-color:var(--line-light);
  transform:translateY(-2px);
}
.box strong{
  font-size:20px;
  display:block;
  margin-bottom:8px;
  color:#fff;
}
.box>div:last-child{
  font-size:32px;
  font-weight:300;
  color:var(--accent);
  font-variant-numeric:tabular-nums;
}
.event{
  background:var(--panel);
  border:1px solid var(--line);
  border-radius:12px;
  padding:20px;
  margin-bottom:16px;
  transition:border-color 0.2s ease;
}
.event:hover{
  border-color:var(--line-light);
}
.event h3{display:flex;align-items:center;gap:12px;margin:0 0 16px 0}
.toc{
  list-style:none;
  padding:0;
  margin:20px 0;
}
.toc li{
  margin:10px 0;
  padding-left:28px;
  position:relative;
}
.toc li::before{
  content:"▸";
  position:absolute;
  left:0;
  color:var(--accent);
}
.toc a{
  color:var(--link);
  text-decoration:none;
  font-weight:500;
  transition:color 0.2s ease;
}
.toc a:hover{color:var(--link-hover)}
.badge{
  display:inline-block;
  padding:4px 10px;
  border-radius:6px;
  color:#fff;
  font-size:11px;
  font-weight:600;
  letter-spacing:0.5px;
  white-space:nowrap;
  margin-right:8px;
  flex-shrink:0;
}
.urgent{background:var(--urgent)}
.important{background:var(--important)}
.watch{background:var(--watch)}
.plan{background:var(--plan)}
.normal{background:var(--normal)}
.small{
  color:var(--muted);
  font-size:13px;
  margin:8px 0;
  display:flex;
  flex-wrap:wrap;
  gap:16px;
}
.message{
  background:var(--panel2);
  border-left:3px solid var(--accent);
  border-radius:8px;
  padding:14px;
  white-space:pre-wrap;
  font-family:"IBM Plex Mono","JetBrains Mono","Fira Code","Consolas",monospace;
  font-size:12px;
  overflow:auto;
  word-break:break-word;
  margin-top:12px;
  line-height:1.5;
}
.full-message{
  margin:10px 0 12px 0;
}
.full-message summary{
  color:var(--link);
  cursor:pointer;
  font-weight:600;
  font-size:14px;
}
.full-message summary:hover{color:var(--link-hover)}
.full-message .message{margin-top:10px}
.warn{
  border-left:4px solid var(--important);
  background:rgba(217,119,6,0.08);
}
.warn h2{border-bottom-color:var(--important)}
.empty{
  color:var(--muted);
  font-style:italic;
  padding:20px;
}
.anchor{
  color:var(--muted);
  font-size:13px;
  font-weight:400;
}
.top{
  margin-top:20px;
  text-align:right;
}
.top a{
  color:var(--link);
  text-decoration:none;
  font-weight:500;
  font-size:14px;
  transition:color 0.2s ease;
}
.top a:hover{color:var(--link-hover)}
.priority-table{
  width:100%;
  border-collapse:collapse;
  margin:20px 0;
  background:var(--panel);
  border:1px solid var(--line);
  border-radius:8px;
  overflow:hidden;
}
.priority-table th,
.priority-table td{
  padding:10px 12px;
  border-bottom:1px solid var(--line);
  text-align:left;
  vertical-align:top;
}
.priority-table th{
  color:var(--muted);
  font-size:12px;
  text-transform:uppercase;
  letter-spacing:.04em;
  background:var(--panel2);
}
.priority-table tr:last-child td{border-bottom:0}
.priority-table .occ{text-align:right;white-space:nowrap}
.priority-table .event{white-space:nowrap}
.priority-table .action-cell{min-width:260px}
section{
  margin:32px 0;
}
p{margin:12px 0}
p strong{font-weight:600}
"""

    toc_items = []
    summary_boxes = []
    sections = []

    for category in CATEGORY_ORDER:
        number = CATEGORY_NUMBERS[category]
        title = category_label(category)
        anchor = f"cat-{number}-{slug(category)}"
        count = counts.get(category, 0)
        toc_items.append(f'<li><a href="#{anchor}">{html_escape(title)}</a> — {count} {occurrence_label(count)}</li>')
        summary_boxes.append(f'<div class="box"><strong>{number} - {html_escape(title)}</strong><div>{count} {occurrence_label(count)}</div></div>')

        items = [g for g in groups if g.category == category]
        event_cards = []
        for g in items:
            message_html = ""
            full_message = safe_str(g.full_message)
            if full_message:
                sample_message = shorten(full_message, args.message_limit)
                full_message_html = ""
                if sample_message != full_message:
                    full_message_html = f"""
  <details class="full-message">
    <summary>{html_escape(tr("html.read_full"))}</summary>
    <div class="message">{html_escape(full_message)}</div>
  </details>
"""
                message_html = f"""
  {full_message_html}
  <div class="message">{html_escape(sample_message)}</div>
"""
            event_cards.append(
                f"""
<div class="event">
  <h3><span class="badge {html_escape(g.severity)}">{html_escape(severity_badge(g.severity))}</span>{html_escape(g.provider)} {html_escape(event_id_label(g))}</h3>
  <div class="small">{html_escape(tr("html.log"))} : <strong>{html_escape(g.log)}</strong> — {html_escape(tr("html.level"))} : <strong>{html_escape(g.level_name)}</strong> — {html_escape(tr("html.occurrences"))} : <strong>{g.count}</strong> — {html_escape(tr("html.frequency"))} : <strong>{html_escape(g.frequency)}</strong> — {html_escape(tr("html.score"))} : <strong>{g.score}</strong></div>
  <div class="small">{html_escape(tr("html.first"))} : <strong>{html_escape(g.first_seen or 'N/A')}</strong> — {html_escape(tr("html.last"))} : <strong>{html_escape(g.last_seen or 'N/A')}</strong></div>
  <p><strong>{html_escape(tr("html.why"))} :</strong> {html_escape(g.why)}</p>
  <p><strong>{html_escape(tr("html.action"))} :</strong> {html_escape(g.action)}</p>
  {message_html}
</div>
"""
            )
        sections.append(
            f"""
<section id="{anchor}">
  <h2>{number} - {html_escape(title)} <span class="anchor">({count} {occurrence_label(count)})</span></h2>
  {''.join(event_cards) if event_cards else f'<p class="empty">{html_escape(tr("html.no_category"))}</p>'}
  <p class="top"><a href="#resume">{html_escape(tr("html.back"))}</a></p>
</section>
"""
        )

    warning_html = ""
    if warnings:
        warning_html = f'<div class="box warn"><h2>{html_escape(tr("html.warnings"))}</h2><ul>' + "".join(
            f"<li>{html_escape(warning)}</li>" for warning in warnings
        ) + "</ul></div>"

    actions_html = ""
    if actions:
        action_rows = "".join(
            f"""
<tr>
  <td><span class="badge {html_escape(action.severity)}">{html_escape(action.severity_label)}</span></td>
  <td>{html_escape(action.category_label)}</td>
  <td class="event">{html_escape(action.event_label)}</td>
  <td class="occ">{action.count}</td>
  <td class="action-cell">{html_escape(action.action)}</td>
</tr>
"""
            for action in actions
        )
        actions_html = f"""
<table class="priority-table">
  <thead>
    <tr>
      <th>{html_escape(tr("html.severity"))}</th>
      <th>{html_escape(tr("html.category"))}</th>
      <th>{html_escape(tr("html.event"))}</th>
      <th class="occ">{html_escape(tr("console.occ"))}</th>
      <th>{html_escape(tr("html.action"))}</th>
    </tr>
  </thead>
  <tbody>{action_rows}</tbody>
</table>
"""
    else:
        actions_html = f'<p class="empty">{html_escape(tr("html.no_priority"))}</p>'

    return f"""<!doctype html>
<html lang="{html_lang}">
<head>
  <meta charset="utf-8">
  <title>{APP_NAME} {APP_VERSION}</title>
  <style>{css}</style>
</head>
<body>
  <main>
    <h1 id="resume">{APP_NAME} {APP_VERSION}</h1>
    <div class="meta-block">
      <div class="meta">{html_escape(tr("console.machine"))} {html_escape(host)} — {html_escape(tr("html.generated"))} {html_escape(generated_at)} — {html_escape(tr("html.period"))} : {args.days} {html_escape(tr("console.days"))} — {html_escape(tr("console.events_read"))} : {raw_count} — {html_escape(tr("console.groups"))} : {len(groups)}</div>
      <div class="meta">{html_escape(tr("html.logs"))} : {html_escape(logs_label)}.</div>
    </div>

    <h2>{html_escape(tr("html.summary"))}</h2>
    <div class="grid">{''.join(summary_boxes)}</div>

    <h2>{html_escape(tr("html.details"))}</h2>
    <ol class="toc">{''.join(toc_items)}</ol>

    <h2>{html_escape(tr("html.priority_actions"))}</h2>
    {actions_html}

    {warning_html}

    {''.join(sections)}
  </main>
</body>
</html>
"""


def default_output_path(ext: str) -> str:
    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    folder = Path("reports")
    folder.mkdir(parents=True, exist_ok=True)
    return str((folder / f"DTLexplains_{socket.gethostname()}_{stamp}.{ext}").resolve())


def write_text(path: str, content: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        description=tr("arg.description"),
    )
    parser.add_argument("--days", type=int, default=30, help=tr("arg.days"))
    parser.add_argument("--max-events", type=int, default=5000, help=tr("arg.max_events"))
    parser.add_argument("--logs", nargs="+", default=DEFAULT_LOGS, help=tr("arg.logs"))
    parser.add_argument("--include-info", action="store_true", help=tr("arg.include_info"))
    parser.add_argument("--message-limit", type=int, default=420, help=tr("arg.message_limit"))
    parser.add_argument("--html", dest="html_path", help=tr("arg.html"))
    parser.add_argument("--json", dest="json_path", help=tr("arg.json"))
    parser.add_argument("--version", action="store_true", help=tr("arg.version"))
    return parser.parse_args(argv)


def validate_args(args: argparse.Namespace) -> Optional[str]:
    if args.days < 1:
        return tr("error.days")
    if args.max_events < 1:
        return tr("error.max_events")
    if args.message_limit < 80:
        return tr("error.message_limit")
    return None


def main(argv: Optional[Sequence[str]] = None) -> int:
    configure_console()
    args = parse_args(argv)

    if args.version:
        print(f"{APP_NAME} {APP_VERSION}")
        return 0

    error = validate_args(args)
    if error:
        print(error)
        return 2

    if os.name != "nt":
        print(tr("error.platform"))
        return 2

    print(tr("progress.start"), end="", flush=True)
    events, warnings = collect_events(
        args.logs,
        args.days,
        args.max_events,
        args.include_info,
        progress_callback=lambda _log: print("o", end="", flush=True),
    )
    print(tr("progress.done") + "\n")
    groups = summarize_events(events)

    html_path = os.path.abspath(args.html_path) if args.html_path else default_output_path("html")
    write_text(html_path, build_html_report(groups, len(events), warnings, args))

    if args.json_path:
        payload = {
            "app": APP_NAME,
            "version": APP_VERSION_NUMERIC,
            "display_version": APP_VERSION,
            "language": LANG,
            "machine": socket.gethostname(),
            "generated_at": now_string(),
            "days": args.days,
            "logs": args.logs,
            "events_read": len(events),
            "warnings": list(warnings),
            "groups": [asdict(g) for g in groups],
        }
        write_text(os.path.abspath(args.json_path), json.dumps(payload, ensure_ascii=False, indent=2))

    print(build_console_summary(groups, len(events), warnings, args, html_path))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n" + tr("interrupt"))
        raise SystemExit(130)
    except Exception:
        print("\n" + tr("unexpected"))
        traceback.print_exc()
        raise SystemExit(1)

