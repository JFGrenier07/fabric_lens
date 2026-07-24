# Fabric Lens

Analyseur hors ligne de configurations Cisco ACI. Cherche un VLAN, un subnet ou
une IP et montre, à travers toutes les fabriques, la chaîne d'objets qui le porte
— de l'encap block jusqu'aux ports physiques, et du tenant jusqu'aux contrats.

Ne se connecte à aucun APIC : lit les **backups de configuration**.

```
   RHEL (ou Linux)                         Windows
   python3 fl_extract.py                   fabric-lens.bat  (plink/pscp)
        │  sans option                          │
        ▼                                        ▼
   fabriclens-data.json  ──────────────▶  data\fabriclens-data.json
        │                                        │
        └── on pointe le dossier ───┐   ┌── bouton « Fichier » ──┘
                                    ▼   ▼
                              fabric-lens.html   (le webui, ouvert en local)
```

Aucun Python sur Windows, aucun serveur, aucun réseau côté navigateur.

## Utilisation

Voir **[docs/DEMARRAGE-SIMPLE.txt](docs/DEMARRAGE-SIMPLE.txt)**.

1. Lister tes fabriques dans `scripts/remote/fabric_path`
   (une ligne `nom  chemin`) et, sous Windows, régler le nom de session
   dans `scripts/fabric-lens.bat`.
2. **Linux** : `python3 fl_extract.py` → produit `fabriclens-data.json`.
   **Windows** : double-clic `fabric-lens.bat` → le rapatrie dans `data\`.
3. Ouvrir `fabric-lens.html`, bouton « Charger », pointer le fichier ou le dossier.

## Les pièces

| | |
| --- | --- |
| `scripts/remote/fl_extract.py` | le script, lancé **sans option** : distille les backups → `fabriclens-data.json` |
| `scripts/remote/fabric_path` | la liste de tes fabriques (`nom  chemin`), une par ligne |
| `fabriclens/resolve.py` | le résolveur (référence) ; posé à côté du script, jamais lancé seul |
| `web/gabarit.html` | le webui — source unique, vide de données |
| `web/resolve.js` / `web/selfcheck.js` | résolveur JS + auto-vérification, inlinés dans le webui |
| `scripts/fabric-lens.bat` | le lanceur Windows (3 étapes) |
| `fabriclens/build_page.py` | **outil dev** : `--shell` fabrique le webui vide |

Le dossier `_ancien/` garde le flux précédent (page assemblée sur la RHEL), qui
fonctionne toujours mais n'est plus le flux recommandé.

## Ce qui a coûté cher à découvrir

Ce que les vrais backups ont imposé, et qu'aucune documentation ne disait :

- **Un export APIC ne porte ni `dn` ni `rn` sur les objets enfants.** Mesuré :
  64 objets sur 4 068. Tout est reconstruit depuis les règles de nommage ACI,
  vérifiées par round-trip.
- **`format=json|xml` ne change que l'extension** — ne lire que le JSON
  ignorerait un backup entier.
- **Un export embarque des annexes sensibles** (numéros de série, TEP pool) ;
  seuls les objets issus de `polUni` sont retenus.
- **Un EPG peut être déployé par static path ET par AAEP à la fois** — l'écran
  le signale au lieu de n'en montrer qu'un.
- **Un VLAN peut être un transit** : sous-interface de L3Out avec peering BGP.

## Vérification

En bas à droite de l'app, « vérifié 78/78 » signifie que le résolveur du
navigateur donne exactement les mêmes réponses que le résolveur Python, sur
tes données. Le contrôle tourne chez toi, rien n'en sort — une empreinte ne
permet de reconstituer ni DN, ni IP, ni nom de tenant.
