# -*- coding: utf-8 -*-
"""
DTLexplains - Analyse pédagogique des journaux Windows.

Objectif :
    Lire les événements des 30 derniers jours dans les principaux journaux
    Windows, regrouper les événements, les classer, expliquer les causes
    probables et proposer des actions concrètes.

Version : v1.0-1

Principes :
    - sortie console courte : uniquement le résumé ;
    - un rapport HTML complet ;
    - liens directs du résumé vers les détails ;
    - une section séparée par catégorie ;
    - catégorie 9 : NORMAL.

Usage :
    python -X utf8 .\DTLexplains.py
    python -X utf8 .\DTLexplains.py --days 7
    python -X utf8 .\DTLexplains.py --logs System Application Security
    python -X utf8 .\DTLexplains.py --html reports\rapport.html
    python -X utf8 .\DTLexplains.py --json reports\rapport.json

Notes :
    - Le journal Security exige souvent une console administrateur.
    - Aucun module Python externe requis.
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
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

APP_NAME = "DTLexplains"
APP_VERSION = "v1.0-1"
APP_VERSION_NUMERIC = "1.0.1"

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

CATEGORY_TITLES = {
    "hardware": "Matériel / disque / pilote",
    "boot_power": "Démarrage / alimentation",
    "security": "Sécurité / authentification",
    "network": "Réseau / DNS / DHCP / SMB",
    "updates": "Mises à jour / installation",
    "service": "Services Windows",
    "application": "Applications",
    "powershell": "PowerShell / scripts",
    "normal": "Normal / courant / généralement bénin",
}

SEVERITY_ORDER = {
    "urgent": 0,
    "important": 1,
    "watch": 2,
    "plan": 3,
    "normal": 4,
}

SEVERITY_TITLES = {
    "urgent": "Urgent",
    "important": "Important",
    "watch": "À surveiller",
    "plan": "À planifier",
    "normal": "Normal",
}

SEVERITY_BADGE = {
    "urgent": "URGENT",
    "important": "IMPORTANT",
    "watch": "SURVEILLER",
    "plan": "PLANIFIER",
    "normal": "NORMAL",
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
        raise RuntimeError("powershell.exe introuvable. DTLexplains doit être lancé sous Windows.") from exc
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
        raise RuntimeError("PowerShell n'a pas retourné un JSON valide : " + shorten(stdout, 500)) from exc

    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return [row for row in data if isinstance(row, dict)]
    return []


def collect_events(logs: Sequence[str], days: int, max_events: int, include_info: bool) -> Tuple[List[RawEvent], List[str]]:
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
    Select-Object LogName, ProviderName, Id, Level, LevelDisplayName, RecordId, MachineName, UserId,
        @{{Name='TimeCreated';Expression={{ $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') }}}},
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
    p = provider_norm(provider)
    m = message_norm(message)
    log_l = log.lower()

    if log_l == "security":
        if event_id == 4625:
            return (
                "security", "important",
                "Échecs d'ouverture de session. Cause fréquente : mot de passe enregistré obsolète, service mal configuré ou tentative répétée.",
                "Identifier le compte, le type de connexion et l'adresse source. Corriger les identifiants enregistrés ou investiguer si la rafale est anormale.",
            )
        if event_id in (4720, 4722, 4723, 4724, 4725, 4726, 4732, 4733):
            return (
                "security", "urgent",
                "Modification de compte ou de groupe local. C'est normal après une intervention, suspect sinon.",
                "Vérifier qui a effectué l'action, à quelle heure, puis documenter ou révoquer si ce n'était pas prévu.",
            )
        if event_id == 1102:
            return (
                "security", "urgent",
                "Le journal d'audit Security a été effacé. C'est rare et significatif.",
                "Contrôler immédiatement le compte auteur, sauvegarder les journaux restants et rechercher d'autres traces au même horaire.",
            )
        if event_id in (4624, 4634, 4672, 4688):
            return (
                "normal", "normal",
                "Ouverture, fermeture de session, privilèges ou création de processus. Utile pour la chronologie, rarement problématique seul.",
                "Ne pas traiter isolément. Utiliser seulement pour corréler un incident ou une intervention.",
            )
        return (
            "security", "watch" if level <= 3 else "normal",
            "Événement de sécurité non spécialisé par la base DTLexplains.",
            "Lire le détail : compte, poste source, type de connexion et heure. Classer ensuite comme normal ou suspect.",
        )

    if any(x in p for x in ("disk", "ntfs", "storahci", "stornvme", "volmgr", "partmgr")):
        return (
            "hardware", "urgent" if level <= 2 else "important",
            "Windows signale un problème de stockage, de volume ou de pilote disque.",
            "Sauvegarder avant tout. Contrôler l'état SMART constructeur, puis envisager chkdsk uniquement après sauvegarde.",
        )
    if any(x in p for x in ("whealogger", "whea")):
        return (
            "hardware", "urgent",
            "Erreur matérielle signalée par WHEA : CPU, mémoire, bus PCIe, alimentation ou pilote bas niveau.",
            "Vérifier température, RAM, BIOS/UEFI et pilotes chipset/GPU. Si répétitif, lancer un diagnostic matériel.",
        )
    if "display" in p or "nvlddmkm" in p or "amdkmdag" in p or "igfx" in p:
        return (
            "hardware", "important",
            "Le pilote graphique ou l'affichage a signalé une erreur.",
            "Mettre à jour ou réinstaller proprement le pilote graphique. Vérifier le lien avec veille, jeux, vidéo ou écran externe.",
        )

    if "kernelpower" in p or event_id == 41:
        return (
            "boot_power", "urgent",
            "Arrêt brutal ou redémarrage sans extinction propre. Causes fréquentes : coupure, plantage, alimentation, surchauffe ou appui long sur Power.",
            "Rechercher ce qui s'est passé à l'heure indiquée. Vérifier alimentation, batterie/onduleur, surchauffe, écrans bleus et pilotes.",
        )
    if "bugcheck" in p or (event_id == 1001 and "bugcheck" in m):
        return (
            "boot_power", "urgent",
            "Windows a enregistré un bugcheck, donc probablement un écran bleu.",
            "Conserver les minidumps, relever le code d'arrêt et chercher le pilote ou matériel fautif avant toute réinstallation.",
        )
    if "eventlog" in p and event_id in (6005, 6006):
        return (
            "normal", "normal",
            "Démarrage ou arrêt normal du service journal d'événements.",
            "Aucune action, sauf pour reconstituer la chronologie.",
        )
    if "eventlog" in p and event_id == 6008:
        return (
            "boot_power", "important",
            "Windows indique que l'arrêt précédent était inattendu.",
            "Rechercher Kernel-Power 41 et les événements juste avant l'arrêt.",
        )

    if "servicecontrolmanager" in p:
        if event_id in (7000, 7001, 7009, 7011, 7022, 7023, 7024, 7031, 7034):
            return (
                "service", "important",
                "Un service Windows ou applicatif n'a pas démarré, a expiré ou s'est arrêté anormalement.",
                "Identifier le service cité. Vérifier dépendances, compte de service, chemin exécutable, droits et événements voisins.",
            )
        if event_id in (7040, 7045):
            return (
                "service", "watch",
                "Changement de configuration ou installation d'un service.",
                "Vérifier que le service installé ou modifié correspond à une action attendue. Inspecter le chemin binaire si le nom est inconnu.",
            )
        return (
            "service", "watch" if level <= 3 else "normal",
            "Événement du gestionnaire de services.",
            "Lire le nom du service dans le message et vérifier s'il est attendu sur cette machine.",
        )

    if any(x in p for x in ("dhcp", "dnsclient", "tcpip", "netwtw", "netlogon", "lanmanworkstation", "srv")):
        return (
            "network", "important" if level <= 2 else "watch",
            "Windows signale un problème réseau, DNS, DHCP, SMB ou pilote carte réseau.",
            "Comparer IP/passerelle/DNS avec un poste sain. Tester ping passerelle, résolution DNS, accès par IP puis par nom.",
        )
    if "schannel" in p:
        return (
            "network", "watch",
            "Erreur TLS/SSL Schannel. Souvent liée à un serveur distant, un vieux protocole TLS, un certificat ou une application bavarde.",
            "Chercher l'application au même horaire. Surveiller si cela bloque réellement un usage ; ne pas corriger au hasard si tout fonctionne.",
        )

    if any(x in p for x in ("windowsupdateclient", "servicing", "setup", "msiinstaller", "wusa")) or log_l == "setup":
        return (
            "updates", "important" if level <= 2 else "plan",
            "Installation, mise à jour ou maintenance Windows/applicative en erreur ou à contrôler.",
            "Consulter l'historique Windows Update et relancer après redémarrage. Si répétitif : DISM puis sfc /scannow.",
        )

    if any(x in p for x in ("applicationerror", "applicationhang", "windowserrorreporting", "wer")):
        return (
            "application", "important" if count >= 3 else "watch",
            "Une application plante ou ne répond plus.",
            "Identifier l'exécutable fautif, mettre à jour l'application, tester un profil utilisateur propre si le crash est récurrent.",
        )
    if "appmodelruntime" in p or "appx" in p:
        return (
            "normal", "normal",
            "Événement lié aux applications Store/AppX. Très fréquent sur Windows.",
            "Surveiller seulement si une application Windows ne se lance pas.",
        )

    if "powershell" in p or log_l == "windows powershell":
        if level <= 3:
            return (
                "powershell", "watch",
                "Erreur ou avertissement PowerShell. Peut venir d'un script de maintenance, GLPI, sauvegarde ou tâche planifiée.",
                "Lire le script ou la commande dans le détail. Vérifier les tâches planifiées et les droits du compte d'exécution.",
            )
        return (
            "normal", "normal",
            "Trace PowerShell informative.",
            "Utiliser seulement pour reconstituer la chronologie d'une intervention ou d'un script.",
        )

    if "distributedcom" in p and event_id in (10016, 10010):
        return (
            "normal", "normal",
            "DistributedCOM 10016/10010 est très fréquent sur Windows et rarement la cause première d'une panne.",
            "Ne pas modifier les permissions DCOM sans symptôme clair. Chercher plutôt les erreurs matérielles, services ou applications autour de la même heure.",
        )
    if "restartmanager" in p:
        return (
            "normal", "normal",
            "Restart Manager accompagne souvent installations et mises à jour.",
            "À utiliser comme indice chronologique, pas comme erreur principale.",
        )

    if level == 1:
        return (
            "boot_power", "urgent",
            "Événement critique non reconnu par la base DTLexplains.",
            "Lire le détail complet et corréler avec les événements des 5 minutes avant/après.",
        )
    if level == 2:
        return (
            "application", "watch",
            "Erreur non reconnue par la base DTLexplains.",
            "Surveiller si elle revient. Si elle est fréquente ou liée à un symptôme utilisateur, chercher provider + ID.",
        )
    if level == 3:
        return (
            "normal", "normal" if count < 5 else "plan",
            "Avertissement non reconnu. Beaucoup d'avertissements Windows sont secondaires sans symptôme correspondant.",
            "Classer comme secondaire sauf répétition massive ou symptôme utilisateur au même horaire.",
        )
    return (
        "normal", "normal",
        "Information Windows conservée pour la chronologie.",
        "Aucune action directe.",
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
                sample_message=shorten(item["sample_message"], 800),
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
    return collections.Counter(group.category for group in groups)


def top_actions(groups: Sequence[EventGroup], limit: int = 8) -> List[str]:
    actions: List[str] = []
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
            f"{SEVERITY_BADGE.get(group.severity, group.severity)} - "
            f"catégorie {CATEGORY_NUMBERS.get(group.category, '?')} {CATEGORY_TITLES.get(group.category, group.category)} - "
            f"{group.provider} {group.event_id} ({group.count}x) : {group.action}"
        )
        if len(actions) >= limit:
            break
    return actions


def build_console_summary(groups: Sequence[EventGroup], raw_count: int, warnings: Sequence[str], args: argparse.Namespace, html_path: str) -> str:
    counts = category_counts(groups)
    actions = top_actions(groups)
    lines: List[str] = []

    lines.append(f"{APP_NAME} {APP_VERSION}")
    lines.append(f"Machine              : {socket.gethostname()}")
    lines.append(f"Période analysée     : {args.days} derniers jours")
    lines.append(f"Événements lus       : {raw_count}")
    lines.append(f"Groupes détectés     : {len(groups)}")
    lines.append(f"Rapport HTML         : {html_path}")
    if warnings:
        lines.append(f"Avertissements       : {len(warnings)} journal(aux) non lu(s) ou partiellement lu(s)")
    lines.append("")
    lines.append("Répartition par catégorie")
    lines.append("-" * 72)
    for category in CATEGORY_ORDER:
        number = CATEGORY_NUMBERS[category]
        title = CATEGORY_TITLES[category]
        lines.append(f"{number}. {title:<40} {counts.get(category, 0)}")
    lines.append("")
    lines.append("Actions prioritaires")
    lines.append("-" * 72)
    if actions:
        for index, action in enumerate(actions, 1):
            lines.append(f"{index}. {action}")
    else:
        lines.append("Aucune action prioritaire détectée dans les événements lus.")
    return "\n".join(lines)


def html_escape(text: Any) -> str:
    return html.escape(safe_str(text))


def build_html_report(groups: Sequence[EventGroup], raw_count: int, warnings: Sequence[str], args: argparse.Namespace) -> str:
    counts = category_counts(groups)
    actions = top_actions(groups)
    generated_at = now_string()
    host = socket.gethostname()

    css = """
:root{--bg:#0f1115;--panel:#181b22;--panel2:#20242d;--text:#e8e8e8;--muted:#a9b0bd;--line:#333a46;--link:#8ab4f8;}
body{font-family:Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--text);margin:0;padding:28px;line-height:1.45;}
h1{margin:0 0 6px 0;color:#fff;font-size:30px} h2{margin-top:32px;border-bottom:1px solid var(--line);padding-bottom:8px} h3{margin:0 0 8px 0}.meta{color:var(--muted);margin-bottom:20px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin:18px 0}.box,.event{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}.box strong{font-size:24px;display:block}.toc a,.top a{color:var(--link);text-decoration:none}.toc li{margin:5px 0}.badge{display:inline-block;padding:2px 8px;border-radius:999px;color:#fff;font-size:12px;margin-right:8px}.urgent{background:#8b0000}.important{background:#9a5800}.watch{background:#5f5f00}.plan{background:#334}.normal{background:#34513a}.small{color:var(--muted);font-size:13px}.message{background:var(--panel2);border-radius:8px;padding:10px;white-space:pre-wrap;font-family:Consolas,monospace;font-size:13px;overflow:auto}.warn{border-left:4px solid #9a5800}.empty{color:var(--muted);font-style:italic}.anchor{color:var(--muted);font-size:13px}.top{margin-top:10px}.action li{margin:8px 0}
"""

    toc_items = []
    summary_boxes = []
    sections = []

    for category in CATEGORY_ORDER:
        number = CATEGORY_NUMBERS[category]
        title = CATEGORY_TITLES[category]
        anchor = f"cat-{number}-{slug(category)}"
        count = counts.get(category, 0)
        toc_items.append(f'<li><a href="#{anchor}">{number}. {html_escape(title)}</a> — {count} groupe(s)</li>')
        summary_boxes.append(f'<div class="box"><strong>{count}</strong>{number}. {html_escape(title)}</div>')

        items = [g for g in groups if g.category == category]
        event_cards = []
        for g in items:
            event_cards.append(
                f"""
<div class="event">
  <h3><span class="badge {html_escape(g.severity)}">{html_escape(SEVERITY_BADGE.get(g.severity, g.severity))}</span>{html_escape(g.provider)} {g.event_id}</h3>
  <div class="small">Journal : {html_escape(g.log)} — Niveau : {html_escape(g.level_name)} — Occurrences : {g.count} — Score : {g.score}</div>
  <div class="small">Première occurrence : {html_escape(g.first_seen or 'N/A')} — Dernière occurrence : {html_escape(g.last_seen or 'N/A')}</div>
  <p><strong>Pourquoi :</strong> {html_escape(g.why)}</p>
  <p><strong>Action proposée :</strong> {html_escape(g.action)}</p>
  <div class="message">{html_escape(shorten(g.sample_message, args.message_limit))}</div>
</div>
"""
            )
        sections.append(
            f"""
<section id="{anchor}">
  <h2>{number}. {html_escape(title)} <span class="anchor">({len(items)} groupe(s))</span></h2>
  {''.join(event_cards) if event_cards else '<p class="empty">Aucun événement dans cette catégorie.</p>'}
  <p class="top"><a href="#resume">Retour au résumé</a></p>
</section>
"""
        )

    warning_html = ""
    if warnings:
        warning_html = '<div class="box warn"><h2>Avertissements</h2><ul>' + "".join(
            f"<li>{html_escape(warning)}</li>" for warning in warnings
        ) + "</ul></div>"

    actions_html = ""
    if actions:
        actions_html = '<ol class="action">' + "".join(f"<li>{html_escape(action)}</li>" for action in actions) + "</ol>"
    else:
        actions_html = '<p class="empty">Aucune action prioritaire détectée dans les événements lus.</p>'

    return f"""<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <title>{APP_NAME} {APP_VERSION}</title>
  <style>{css}</style>
</head>
<body>
  <main>
    <h1 id="resume">{APP_NAME} {APP_VERSION}</h1>
    <div class="meta">Machine {html_escape(host)} — Rapport généré le {html_escape(generated_at)} — Période : {args.days} derniers jours — Événements lus : {raw_count} — Groupes : {len(groups)}</div>

    <h2>Résumé</h2>
    <div class="grid">{''.join(summary_boxes)}</div>

    <h2>Accès direct aux détails</h2>
    <ol class="toc">{''.join(toc_items)}</ol>

    <h2>Actions prioritaires</h2>
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
        description="Analyse les journaux Windows récents, classe les événements et propose des actions.",
    )
    parser.add_argument("--days", type=int, default=30, help="Nombre de jours à analyser. Défaut : 30.")
    parser.add_argument("--max-events", type=int, default=5000, help="Nombre maximal d'événements lus au total. Défaut : 5000.")
    parser.add_argument("--logs", nargs="+", default=DEFAULT_LOGS, help="Journaux Windows à lire.")
    parser.add_argument("--include-info", action="store_true", help="Inclure aussi les événements Information, plus bavards.")
    parser.add_argument("--message-limit", type=int, default=420, help="Longueur maximale des exemples de message dans le HTML.")
    parser.add_argument("--html", dest="html_path", help="Fichier HTML de sortie. Défaut : reports\\DTLexplains_<machine>_<date>.html")
    parser.add_argument("--json", dest="json_path", help="Fichier JSON de sortie optionnel.")
    parser.add_argument("--version", action="store_true", help="Affiche la version et quitte.")
    return parser.parse_args(argv)


def validate_args(args: argparse.Namespace) -> Optional[str]:
    if args.days < 1:
        return "%DTLexplains-E-SYNTAX, --days doit être >= 1"
    if args.max_events < 1:
        return "%DTLexplains-E-SYNTAX, --max-events doit être >= 1"
    if args.message_limit < 80:
        return "%DTLexplains-E-SYNTAX, --message-limit doit être >= 80"
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
        print("%DTLexplains-E-PLATFORM, DTLexplains lit les journaux Windows : lance-le sur un poste Windows.")
        return 2

    events, warnings = collect_events(args.logs, args.days, args.max_events, args.include_info)
    groups = summarize_events(events)

    html_path = os.path.abspath(args.html_path) if args.html_path else default_output_path("html")
    write_text(html_path, build_html_report(groups, len(events), warnings, args))

    if args.json_path:
        payload = {
            "app": APP_NAME,
            "version": APP_VERSION_NUMERIC,
            "display_version": APP_VERSION,
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
        print("\n%DTLexplains-I-INTERRUPT, Interrompu par l'utilisateur.")
        raise SystemExit(130)
    except Exception:
        print("\n%DTLexplains-F-UNEXPECTED, Erreur inattendue :")
        traceback.print_exc()
        raise SystemExit(1)
