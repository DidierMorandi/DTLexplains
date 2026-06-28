# DTLexplains

**DTLexplains** analyse les journaux Windows récents, classe les événements par catégories pédagogiques et produit un rapport HTML simple à parcourir.
Didier DTL Morandi - www.netdtl.com

L'objectif n'est pas de remplacer l'Observateur d'événements Windows, mais de répondre rapidement à trois questions :

- **Quoi ?** Quels événements reviennent dans les journaux principaux ?
- **Pourquoi ?** Que signifient probablement ces événements ?
- **Comment ?** Quelles actions concrètes peut-on tenter ?

## Version

Version courante : **v1.0-1**  
Fichier de version : `.dtl_version`

## Journaux analysés par défaut

DTLexplains lit les cinq journaux principaux suivants :

- `Application`
- `System`
- `Security`
- `Setup`
- `Windows PowerShell`

Le journal `Security` peut nécessiter une console ouverte en administrateur.

## Catégories

Les événements sont regroupés dans neuf catégories :

1. `MATERIEL`
2. `DEMARRAGE_ALIMENTATION`
3. `SECURITE`
4. `RESEAU`
5. `MISES_A_JOUR`
6. `SERVICES`
7. `APPLICATIONS`
8. `POWERSHELL`
9. `NORMAL`

La catégorie **NORMAL** regroupe les événements fréquents, informatifs ou généralement bénins.

## Utilisation rapide

```powershell
python -X utf8 .\DTLexplains.py
```

Par défaut, le programme :

- analyse les **30 derniers jours** ;
- lit au maximum **5000 événements** ;
- affiche uniquement un résumé dans la console ;
- crée un rapport HTML complet dans le dossier `reports`.

## Exemples

Analyser les 7 derniers jours :

```powershell
python -X utf8 .\DTLexplains.py --days 7
```

Choisir les journaux :

```powershell
python -X utf8 .\DTLexplains.py --logs System Application Security
```

Inclure les événements Information :

```powershell
python -X utf8 .\DTLexplains.py --include-info
```

Créer aussi un JSON :

```powershell
python -X utf8 .\DTLexplains.py --json reports\dtlexplains.json
```

Choisir le rapport HTML :

```powershell
python -X utf8 .\DTLexplains.py --html reports\rapport.html
```

## Rapport HTML

Le rapport HTML contient :

- une synthèse générale ;
- des liens directs vers chaque catégorie ;
- une section séparée par catégorie ;
- les événements regroupés par journal, source, identifiant et niveau ;
- une explication probable ;
- une action proposée ;
- un exemple de message Windows.

## Sortie console

La console reste volontairement courte. Elle affiche :

- la période analysée ;
- le nombre d'événements lus ;
- le nombre de groupes détectés ;
- la répartition par catégorie ;
- les actions prioritaires ;
- le chemin du rapport HTML.

## Pré-requis

- Windows 10 ou Windows 11
- Python 3.9 ou supérieur
- PowerShell disponible sous le nom `powershell.exe`
- Aucun module Python externe requis

## Notes importantes

DTLexplains exécute `Get-WinEvent` via PowerShell et convertit les résultats en JSON. Un journal inaccessible n'arrête pas l'analyse : un avertissement est ajouté au rapport.

Certaines erreurs Windows, comme `DistributedCOM 10016`, peuvent être très fréquentes sans indiquer une panne réelle. DTLexplains les classe généralement en **NORMAL** pour éviter les fausses alertes.

## Structure recommandée du dépôt

```text
DTLexplains/
├── DTLexplains.py
├── .dtl_version
├── README.md
├── .gitignore
└── reports/          # généré localement, non versionné
```

## Auteur et crédits

Projet de la suite DTL / NetDTL.

- Conception, architecture, tests et documentation : Didier Morandi
- Aide au codage et à la structuration : ChatGPT
