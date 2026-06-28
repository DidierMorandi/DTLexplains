# -*- coding: utf-8 -*-
"""
DTLexplains - Analyse pédagogique des journaux Windows.

Objectif :
    Lire les événements des 30 derniers jours dans les principaux journaux Windows,
    regrouper les événements, les classer, expliquer les causes probables et proposer
    des actions concrètes.

Origine :
    Le coeur de lecture PowerShell/Get-WinEvent + ConvertTo-Json est extrait et
    généralisé depuis la rubrique "events" de DTLsaysWhat.

Usage :
    python -X utf8 DTLexplains.py
    python -X utf8 DTLexplains.py --days 7 --max-events 3000
    python -X utf8 DTLexplains.py --logs System Application Security Setup "Windows PowerShell"
    python -X utf8 DTLexplains.py --output C:\\Temp\\DTLexplains.txt
    python -X utf8 DTLexplains.py --json C:\\Temp\\DTLexplains.json
    python -X utf8 DTLexplains.py --html C:\\Temp\\DTLexplains.html

Notes :
    - Le journal Security exige souvent une console administrateur.
    - Aucun module externe requis.
    - Compatible Windows PowerShell 5.x et PowerShell récent si powershell.exe existe.
"""

from __future__ import annotations

import argparse
import collections
import datetime as _dt
import html
import json
import os
import socket
import subprocess
import sys
import traceback
from dataclasses import dataclass, asdict
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

APP_NAME = "DTLexplains"
APP_VERSION = "v1.0.0"

DEFAULT_LOGS = [
    "Application",
    "System",
    "Security",
    "Setup",
    "Windows PowerShell",
]

LEVEL_NAMES = {
    1: "Critique",
    2: "Erreur",
    3: "Avertissement",
    4: "Information",
    5: "Verbose",
}

SEVERITY_ORDER = {
    "urgent": 0,
    "important": 1,
    "watch": 2,
    "plan": 3,
    "info": 4,
    "noise": 5,
    "unknown": 6,
}

SEVERITY_TITLES = {
    "urgent": "Urgent - à traiter en priorité",
    "important": "Important - action recommandée",
    "watch": "À surveiller",
    "plan": "À planifier",
    "info": "Information utile",
    "noise": "Bruit courant / généralement bénin",
    "unknown": "Non classé",
}

SEVERITY_BADGE = {
    "urgent": "URGENT",
    "important": "IMPORTANT",
    "watch": "SURVEILLER",
    "plan": "PLANIFIER",
    "info": "INFO",
    "noise": "BRUIT",
    "unknown": "INCONNU",
}

CATEGORY_TITLES = {
    "hardware": "Matériel / disque / pilote",
    "boot_power": "Démarrage / alimentation",
    "security": "Sécurité / authentification",
    "network": "Réseau / DNS / DHCP",
    "updates": "Mises à jour / installation",
    "service": "Services Windows",
    "application": "Applications",
    "powershell": "PowerShell / scripts",
    "system": "Système",
    "noise": "Bruit connu",
    "unknown": "Non classé",
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
    first_seen: str
    last_seen: str
    machine: str
    sample_message: str
    category: str
    severity: str
    score: int
    why: str
    action: str


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
    return one_line[: limit - 3] + "..."


def ps_json(script: str, timeout: int = 120) -> List[Dict[str, Any]]:
    """Exécute PowerShell en UTF-8 et retourne une liste de dictionnaires JSON."""
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
    except FileNotFoundError:
        raise RuntimeError("powershell.exe introuvable. DTLexplains doit être lancé sous Windows.")
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Timeout PowerShell après {timeout} secondes.") from exc

    stdout = result.stdout.decode("utf-8", errors="replace").strip()
    stderr = result.stderr.decode("utf-8", errors="replace").strip()

    if result.returncode != 0 and not stdout:
        raise RuntimeError(stderr or f"PowerShell a retourné le code {result.returncode}.")
    if not stdout:
        return []

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        preview = shorten(stdout, 500)
        raise RuntimeError(f"PowerShell n'a pas retourné un JSON valide : {preview}") from exc

    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    return []


def quote_ps_string(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def collect_events(logs: Sequence[str], days: int, max_events: int, include_info: bool) -> Tuple[List[RawEvent], List[str]]:
    """Collecte les événements Windows avec Get-WinEvent.

    On interroge journal par journal pour qu'un journal inaccessible, typiquement Security
    sans élévation, ne bloque pas tout le rapport.
    """
    levels = "1,2,3" if not include_info else "1,2,3,4"
    start_iso = (_dt.datetime.now() - _dt.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
    events: List[RawEvent] = []
    warnings: List[str] = []

    per_log_limit = max(1, max_events // max(1, len(logs)))

    for log in logs:
        script = f"""
$ErrorActionPreference = 'SilentlyContinue'
$logName = {quote_ps_string(log)}
$start = [datetime]{quote_ps_string(start_iso)}
$items = Get-WinEvent -FilterHashtable @{{LogName=$logName; StartTime=$start; Level={levels}}} -MaxEvents {per_log_limit} -ErrorAction SilentlyContinue |
    Select-Object `
        LogName, ProviderName, Id, Level, LevelDisplayName, RecordId, MachineName, UserId, `
        @{{Name='TimeCreated';Expression={{ $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') }}}}, `
        Message
if ($null -eq $items) {{ @() | ConvertTo-Json -Compress -Depth 4 }}
else {{ $items | ConvertTo-Json -Compress -Depth 4 }}
"""
        try:
            rows = ps_json(script)
        except RuntimeError as exc:
            warnings.append(f"Journal {log} non lu : {exc}")
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
                    level_name=safe_str(row.get("LevelDisplayName"), LEVEL_NAMES.get(level, str(level))),
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


def rule_for_event(log: str, provider: str, event_id: int, level: int, message: str, count: int) -> Tuple[str, str, str, str]:
    """Retourne category, severity, why, action."""
    p = provider_norm(provider)
    m = message_norm(message)
    log_l = log.lower()

    # Sécurité : événements très utiles quand on audite un poste.
    if log_l == "security":
        if event_id == 4625:
            return (
                "security", "important",
                "Échecs d'ouverture de session. Cela peut être un mot de passe enregistré obsolète, un service mal configuré ou une tentative répétée.",
                "Identifier le compte et l'adresse source dans le détail de l'événement. Corriger les identifiants enregistrés, puis vérifier qu'il n'y a pas de rafale anormale.",
            )
        if event_id in (4720, 4722, 4723, 4724, 4725, 4726, 4732, 4733):
            return (
                "security", "urgent",
                "Modification de compte ou de groupe local. C'est normal après une intervention, suspect sinon.",
                "Vérifier qui a effectué l'action, à quelle heure, et comparer avec les interventions prévues. Documenter ou révoquer si ce n'est pas attendu.",
            )
        if event_id == 1102:
            return (
                "security", "urgent",
                "Le journal d'audit Security a été effacé. C'est rare et très significatif.",
                "Contrôler immédiatement le compte auteur, sauvegarder les journaux restants et rechercher d'autres traces autour de la même heure.",
            )
        if event_id in (4624, 4634, 4672):
            return (
                "security", "info",
                "Ouverture/fermeture de session ou privilèges spéciaux. Utile pour corréler, rarement problématique seul.",
                "Ne pas traiter seul. Utiliser pour confirmer la chronologie d'un incident ou d'une intervention.",
            )
        return (
            "security", "watch" if level <= 3 else "info",
            "Événement de sécurité non spécialisé par la base DTLexplains.",
            "Lire le détail : compte, poste source, type d'ouverture de session et heure. Classer ensuite comme normal ou suspect.",
        )

    # Matériel, disque, corruption, pilotes.
    if any(x in p for x in ("disk", "ntfs", "storahci", "stornvme", "volmgr", "partmgr")):
        return (
            "hardware", "urgent" if level <= 2 else "important",
            "Windows signale un problème de stockage, de volume ou de pilote disque.",
            "Sauvegarder avant tout. Contrôler l'état SMART constructeur, l'Observateur d'événements autour de la même heure, puis lancer chkdsk uniquement après sauvegarde.",
        )
    if any(x in p for x in ("whealogger", "whea")):
        return (
            "hardware", "urgent",
            "Erreur matérielle signalée par WHEA : CPU, mémoire, bus PCIe, alimentation ou pilote bas niveau.",
            "Vérifier température, RAM, BIOS/UEFI, pilotes chipset/GPU. Si répétitif, considérer un diagnostic matériel.",
        )
    if "display" in p or "nvlddmkm" in p or "amdkmdag" in p or "igfx" in p:
        return (
            "hardware", "important",
            "Le pilote graphique ou l'affichage a signalé une erreur.",
            "Mettre à jour ou réinstaller proprement le pilote graphique. Vérifier si les erreurs coïncident avec veille, jeux, vidéo ou écran externe.",
        )

    # Boot, alimentation, crashs.
    if "kernelpower" in p or event_id == 41:
        return (
            "boot_power", "urgent",
            "Arrêt brutal ou redémarrage sans extinction propre. Souvent coupure, plantage, alimentation, surchauffe ou appui long sur Power.",
            "Demander ce qui s'est passé à l'heure indiquée. Vérifier alimentation, batterie/onduleur, surchauffe, écrans bleus et mises à jour de pilotes.",
        )
    if "bugcheck" in p or event_id == 1001 and "bugcheck" in m:
        return (
            "boot_power", "urgent",
            "Windows a enregistré un bugcheck, donc probablement un écran bleu.",
            "Conserver les minidumps, relever le code d'arrêt, puis chercher le pilote ou matériel fautif avant toute réinstallation sauvage.",
        )
    if "eventlog" in p and event_id in (6008, 6005, 6006):
        severity = "important" if event_id == 6008 else "info"
        return (
            "boot_power", severity,
            "Chronologie de démarrage/arrêt du journal système.",
            "Pour 6008, rechercher l'événement Kernel-Power 41 et les événements juste avant l'arrêt inattendu.",
        )

    # Services.
    if "servicecontrolmanager" in p:
        if event_id in (7000, 7001, 7009, 7011, 7022, 7023, 7024, 7031, 7034):
            return (
                "service", "important",
                "Un service Windows ou applicatif n'a pas démarré, a expiré ou s'est arrêté anormalement.",
                "Identifier le service cité dans le message. Vérifier dépendances, compte de service, chemin exécutable, droits et événements voisins.",
            )
        if event_id in (7040, 7045):
            return (
                "service", "watch",
                "Changement de configuration ou installation d'un service.",
                "Vérifier que le service installé ou modifié correspond à une action attendue. Inspecter le chemin binaire si le nom est inconnu.",
            )
        return (
            "service", "watch" if level <= 3 else "info",
            "Événement du gestionnaire de services.",
            "Lire le nom du service dans le message et vérifier s'il est attendu sur cette machine.",
        )

    # Réseau.
    if any(x in p for x in ("dhcp", "dnsclient", "tcpip", "netwtw", "netwtw10", "netlogon", "lanmanworkstation", "srv")):
        return (
            "network", "important" if level <= 2 else "watch",
            "Windows signale un problème réseau, DNS, DHCP, SMB ou pilote carte réseau.",
            "Comparer IP/passerelle/DNS avec un poste sain. Tester ping passerelle, résolution DNS, accès par IP puis par nom. Vérifier aussi le pilote réseau.",
        )
    if "schannel" in p:
        return (
            "network", "watch",
            "Erreur TLS/SSL Schannel. Souvent liée à un serveur distant, un vieux protocole TLS, un certificat ou une application bavarde.",
            "Chercher l'application au même horaire. Surveiller si cela bloque réellement un usage ; ne pas corriger au hasard si tout fonctionne.",
        )

    # Updates / setup.
    if any(x in p for x in ("windowsupdateclient", "servicing", "setup", "msiinstaller", "wusa")) or log_l == "setup":
        return (
            "updates", "important" if level <= 2 else "plan",
            "Installation, mise à jour ou maintenance Windows/applicative en erreur ou à contrôler.",
            "Consulter l'historique Windows Update et relancer après redémarrage. Si répétitif : DISM /Online /Cleanup-Image /RestoreHealth puis sfc /scannow.",
        )

    # Applications.
    if any(x in p for x in ("applicationerror", "applicationhang", "windows error reporting", "wer")):
        return (
            "application", "important" if count >= 3 else "watch",
            "Une application plante ou ne répond plus.",
            "Identifier l'exécutable fautif dans le message, mettre à jour l'application, tester un profil utilisateur propre si le crash est récurrent.",
        )
    if "appmodelruntime" in p or "appx" in p:
        return (
            "application", "watch",
            "Événement lié aux applications Store/AppX ou à leur modèle d'exécution.",
            "Surveiller seulement si une application Windows ne se lance pas. Sinon classer comme bruit courant.",
        )

    # PowerShell.
    if "powershell" in p or log_l == "windows powershell":
        if level <= 3:
            return (
                "powershell", "watch",
                "Erreur ou avertissement PowerShell. Peut être un script de maintenance, GLPI, sauvegarde, ou une tâche planifiée.",
                "Lire le script ou la commande dans le détail. Vérifier les tâches planifiées et les droits du compte d'exécution.",
            )
        return (
            "powershell", "info",
            "Trace PowerShell informative.",
            "Utiliser seulement pour reconstituer la chronologie d'une intervention ou d'un script.",
        )

    # Bruits Windows fréquents.
    if "distributedcom" in p and event_id in (10016, 10010):
        return (
            "noise", "noise",
            "DistributedCOM 10016/10010 est très fréquent sur Windows et rarement la cause première d'une panne.",
            "Ne pas modifier les permissions DCOM sans symptôme clair. Chercher plutôt les erreurs matérielles, services ou applications autour de la même heure.",
        )
    if "restartmanager" in p:
        return (
            "noise", "info",
            "Restart Manager accompagne souvent installations et mises à jour.",
            "À utiliser comme indice chronologique, pas comme erreur principale.",
        )

    # Règle générique.
    if level == 1:
        return (
            "system", "urgent",
            "Événement critique non reconnu par la base DTLexplains.",
            "Lire le détail complet, puis corréler avec les événements des 5 minutes avant/après.",
        )
    if level == 2:
        return (
            "unknown", "watch",
            "Erreur non reconnue par la base DTLexplains.",
            "Surveiller si elle revient. Si elle est fréquente ou liée à un symptôme utilisateur, chercher provider + ID dans la documentation Microsoft ou éditeur.",
        )
    if level == 3:
        return (
            "unknown", "plan",
            "Avertissement non reconnu par la base DTLexplains.",
            "Classer comme secondaire sauf répétition massive ou symptôme correspondant.",
        )
    return (
        "unknown", "info",
        "Information non reconnue par la base DTLexplains.",
        "Conserver pour la chronologie, pas d'action directe.",
    )


def score_event(severity: str, level: int, count: int, last_seen: str) -> int:
    base = {
        "urgent": 100,
        "important": 75,
        "watch": 50,
        "plan": 35,
        "info": 15,
        "noise": 5,
        "unknown": 25,
    }.get(severity, 25)
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
    grouped: Dict[Tuple[str, str, int, int], Dict[str, Any]] = {}
    for event in events:
        key = (event.log, event.provider, event.event_id, event.level)
        item = grouped.setdefault(
            key,
            {
                "log": event.log,
                "provider": event.provider,
                "event_id": event.event_id,
                "level": event.level,
                "level_name": event.level_name,
                "count": 0,
                "first_seen": event.time_created,
                "last_seen": event.time_created,
                "machine": event.machine,
                "sample_message": event.message,
            },
        )
        item["count"] += 1
        if event.time_created and (not item["first_seen"] or event.time_created < item["first_seen"]):
            item["first_seen"] = event.time_created
        if event.time_created and event.time_created > item["last_seen"]:
            item["last_seen"] = event.time_created
            if event.message:
                item["sample_message"] = event.message

    summaries: List[EventGroup] = []
    for item in grouped.values():
        category, severity, why, action = rule_for_event(
            item["log"], item["provider"], item["event_id"], item["level"], item["sample_message"], item["count"]
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
                first_seen=item["first_seen"],
                last_seen=item["last_seen"],
                machine=item["machine"],
                sample_message=shorten(item["sample_message"], 500),
                category=category,
                severity=severity,
                score=score,
                why=why,
                action=action,
            )
        )

    return sorted(
        summaries,
        key=lambda x: (SEVERITY_ORDER.get(x.severity, 99), -x.score, -x.count, x.log, x.provider, x.event_id),
    )


def top_actions(groups: Sequence[EventGroup], limit: int = 8) -> List[str]:
    actions: List[str] = []
    seen = set()
    for group in groups:
        if group.severity in ("noise", "info"):
            continue
        text = f"{SEVERITY_BADGE.get(group.severity, group.severity)} - {group.provider} {group.event_id} ({group.count}x) : {group.action}"
        key = (group.category, group.action)
        if key in seen:
            continue
        seen.add(key)
        actions.append(text)
        if len(actions) >= limit:
            break
    return actions


def build_text_report(groups: Sequence[EventGroup], raw_count: int, warnings: Sequence[str], args: argparse.Namespace) -> str:
    lines: List[str] = []
    hostname = socket.gethostname()
    lines.append(f"{APP_NAME} {APP_VERSION}")
    lines.append(f"Machine              : {hostname}")
    lines.append(f"Date du rapport      : {now_string()}")
    lines.append(f"Période analysée     : {args.days} derniers jours")
    lines.append(f"Journaux demandés    : {', '.join(args.logs)}")
    lines.append(f"Événements lus       : {raw_count}")
    lines.append(f"Groupes détectés     : {len(groups)}")
    lines.append("")

    if warnings:
        lines.append("JOURNAUX NON LUS / AVERTISSEMENTS")
        lines.append("-" * 72)
        for warning in warnings:
            lines.append(f"- {warning}")
        lines.append("")

    actions = top_actions(groups)
    lines.append("SYNTHÈSE DTL")
    lines.append("-" * 72)
    if actions:
        for idx, action in enumerate(actions, 1):
            lines.append(f"{idx}. {action}")
    else:
        lines.append("Aucune action urgente détectée dans les événements lus.")
    lines.append("")

    counters_sev = collections.Counter(g.severity for g in groups)
    counters_cat = collections.Counter(g.category for g in groups)
    lines.append("RÉPARTITION")
    lines.append("-" * 72)
    lines.append("Par gravité : " + ", ".join(f"{SEVERITY_BADGE.get(k, k)}={v}" for k, v in counters_sev.items()))
    lines.append("Par catégorie : " + ", ".join(f"{CATEGORY_TITLES.get(k, k)}={v}" for k, v in counters_cat.items()))
    lines.append("")

    by_sev: Dict[str, List[EventGroup]] = collections.defaultdict(list)
    for group in groups:
        by_sev[group.severity].append(group)

    for severity in sorted(by_sev, key=lambda s: SEVERITY_ORDER.get(s, 99)):
        items = by_sev[severity]
        if args.hide_noise and severity in ("noise", "info"):
            continue
        lines.append(SEVERITY_TITLES.get(severity, severity.upper()))
        lines.append("=" * 72)
        for group in items[: args.top_per_section]:
            lines.append(f"{group.provider} {group.event_id}  [{group.log}]  {group.level_name}")
            lines.append(f"Catégorie            : {CATEGORY_TITLES.get(group.category, group.category)}")
            lines.append(f"Score DTL            : {group.score}")
            lines.append(f"Occurrences          : {group.count}")
            lines.append(f"Première occurrence  : {group.first_seen or 'N/A'}")
            lines.append(f"Dernière occurrence  : {group.last_seen or 'N/A'}")
            lines.append(f"Pourquoi             : {group.why}")
            lines.append(f"Action proposée      : {group.action}")
            if group.sample_message:
                lines.append(f"Exemple              : {shorten(group.sample_message, args.message_limit)}")
            lines.append("")
        hidden = len(items) - min(len(items), args.top_per_section)
        if hidden > 0:
            lines.append(f"... {hidden} autre(s) groupe(s) non affiché(s) dans cette section.")
            lines.append("")

    return "\n".join(lines)


def build_html_report(groups: Sequence[EventGroup], raw_count: int, warnings: Sequence[str], args: argparse.Namespace) -> str:
    text_report = build_text_report(groups, raw_count, warnings, args)
    css = """
body{font-family:Segoe UI,Arial,sans-serif;background:#111;color:#ddd;margin:0;padding:28px;}
h1{color:#fff;margin-top:0}.meta{color:#aaa;margin-bottom:20px}.card{background:#1b1b1b;border:1px solid #333;border-radius:10px;padding:14px;margin:12px 0;}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;background:#333;color:#fff;font-size:12px;margin-right:8px}.urgent{background:#8b0000}.important{background:#9a5800}.watch{background:#5f5f00}.plan{background:#334}.info{background:#244}.noise{background:#333}.unknown{background:#444}
pre{white-space:pre-wrap;font-family:Consolas,monospace;font-size:13px;line-height:1.45}.small{color:#999;font-size:12px}a{color:#8ab4f8}
"""
    cards = []
    for g in groups:
        if args.hide_noise and g.severity in ("noise", "info"):
            continue
        cards.append(f"""
<div class="card">
  <div><span class="badge {html.escape(g.severity)}">{html.escape(SEVERITY_BADGE.get(g.severity, g.severity))}</span><b>{html.escape(g.provider)} {g.event_id}</b> <span class="small">[{html.escape(g.log)} - {html.escape(g.level_name)}]</span></div>
  <p><b>Occurrences :</b> {g.count} &nbsp; <b>Dernière :</b> {html.escape(g.last_seen or 'N/A')} &nbsp; <b>Score :</b> {g.score}</p>
  <p><b>Catégorie :</b> {html.escape(CATEGORY_TITLES.get(g.category, g.category))}</p>
  <p><b>Pourquoi :</b> {html.escape(g.why)}</p>
  <p><b>Action :</b> {html.escape(g.action)}</p>
  <p class="small"><b>Exemple :</b> {html.escape(shorten(g.sample_message, args.message_limit))}</p>
</div>""")
    return f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8"><title>{APP_NAME} {APP_VERSION}</title><style>{css}</style></head>
<body>
<h1>{APP_NAME} {APP_VERSION}</h1>
<div class="meta">Machine {html.escape(socket.gethostname())} - {html.escape(now_string())} - {args.days} derniers jours - {raw_count} événements lus - {len(groups)} groupes</div>
<h2>Synthèse texte</h2><pre>{html.escape(text_report)}</pre>
<h2>Détail classé</h2>
{''.join(cards) if cards else '<p>Aucun événement à afficher.</p>'}
</body></html>"""


def default_output_path(ext: str) -> str:
    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.abspath(f"DTLexplains_{socket.gethostname()}_{stamp}.{ext}")


def write_text(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="DTLexplains",
        description="Analyse les journaux Windows récents, classe les événements et propose des actions.",
    )
    parser.add_argument("--days", type=int, default=30, help="Nombre de jours à analyser. Défaut : 30.")
    parser.add_argument("--max-events", type=int, default=5000, help="Nombre maximal d'événements lus au total. Défaut : 5000.")
    parser.add_argument("--logs", nargs="+", default=DEFAULT_LOGS, help="Journaux Windows à lire.")
    parser.add_argument("--include-info", action="store_true", help="Inclure aussi les événements Information, plus bavards.")
    parser.add_argument("--hide-noise", action="store_true", help="Masquer les sections bruit/info dans le rapport texte.")
    parser.add_argument("--top-per-section", type=int, default=25, help="Nombre maximal d'éléments affichés par gravité.")
    parser.add_argument("--message-limit", type=int, default=320, help="Longueur maximale des exemples de message.")
    parser.add_argument("--output", "-o", help="Fichier texte de sortie. Défaut : nom automatique.")
    parser.add_argument("--json", dest="json_path", help="Fichier JSON de sortie.")
    parser.add_argument("--html", dest="html_path", help="Fichier HTML de sortie.")
    parser.add_argument("--no-console", action="store_true", help="N'affiche pas le rapport complet dans la console.")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    configure_console()
    args = parse_args(argv)

    if os.name != "nt":
        print("DTLexplains lit les journaux Windows : lance-le sur un poste Windows.")
        return 2

    if args.days < 1:
        print("--days doit être >= 1")
        return 2
    if args.max_events < 1:
        print("--max-events doit être >= 1")
        return 2

    print(f"{APP_NAME} {APP_VERSION} - lecture des journaux Windows...")
    events, warnings = collect_events(args.logs, args.days, args.max_events, args.include_info)
    groups = summarize_events(events)

    text_report = build_text_report(groups, len(events), warnings, args)
    output_path = os.path.abspath(args.output) if args.output else default_output_path("txt")
    write_text(output_path, text_report)

    if args.json_path:
        payload = {
            "app": APP_NAME,
            "version": APP_VERSION,
            "machine": socket.gethostname(),
            "generated_at": now_string(),
            "days": args.days,
            "logs": args.logs,
            "events_read": len(events),
            "warnings": list(warnings),
            "groups": [asdict(g) for g in groups],
        }
        write_text(os.path.abspath(args.json_path), json.dumps(payload, ensure_ascii=False, indent=2))

    if args.html_path:
        write_text(os.path.abspath(args.html_path), build_html_report(groups, len(events), warnings, args))

    if not args.no_console:
        print()
        print(text_report)

    print(f"Rapport texte sauvegardé : {output_path}")
    if args.json_path:
        print(f"Rapport JSON  sauvegardé : {os.path.abspath(args.json_path)}")
    if args.html_path:
        print(f"Rapport HTML  sauvegardé : {os.path.abspath(args.html_path)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrompu par l'utilisateur.")
        raise SystemExit(130)
    except Exception:
        print("\nErreur inattendue :")
        traceback.print_exc()
        raise SystemExit(1)
