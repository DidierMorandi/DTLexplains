# DTLexplains

DTLexplains analyse les journaux Windows récents, regroupe les événements, les classe par catégorie et propose des explications en français avec des actions concrètes.

## Version

Version courante : **v1.0-4**.

## Usage

```powershell
python -X utf8 DTLexplains.py
python -X utf8 DTLexplains.py --days 7
python -X utf8 DTLexplains.py --logs System Application Security
python -X utf8 DTLexplains.py --html reports\rapport.html
python -X utf8 DTLexplains.py --json reports\rapport.json
```

## Principes

- Console courte : résumé uniquement.
- Rapport HTML complet.
- Accès direct aux détails par catégorie.
- Une section HTML séparée par catégorie.
- Catégorie 9 : normal / courant / généralement bénin.
- Aucun module Python externe requis.

## Modifications v1.0-4

- En-tête HTML des catégories revu : `Catégorie N — Nom (occurrences, groupes)`.
- Résumé HTML : affichage du nombre d'occurrences avant le nombre de groupes.
- Accès direct aux détails : suppression de la présentation ambiguë avec numérotation redondante.
- Fusion logique des événements Service Control Manager 7000 et 7009 lorsqu'ils décrivent le même échec de démarrage.
- Conservation de deux messages représentatifs lors d'une fusion 7000/7009.
- Règle WinREAgent spécialisée : suppression du vague « lire le détail complet ».
- Règle Netwtw08 5011 spécialisée : le paramètre manquant est interne au pilote/firmware, pas un réglage utilisateur.
- Règle Windows Store / 0x80073D02 spécialisée : application probablement ouverte ou utilisée pendant sa mise à jour, généralement sans gravité.
- Règles complémentaires : TPM-WMI, DeviceAssociationService, ESENT, Perflib, Windows Backup, Security-SPP 0x80070070.

## Sorties

Par défaut, le rapport HTML est créé dans :

```text
reports\DTLexplains_<machine>_<date>.html
```

Un JSON optionnel peut être généré avec `--json`.

## Notes

Le journal Security exige souvent une console administrateur.
