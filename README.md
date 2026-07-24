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

1. Régler le bloc `FABRICS` en tête de `scripts/remote/fl_extract.py`
   (une ligne par fabrique) et, sous Windows, le nom de session dans
   `scripts/fabric-lens.bat`.
2. **Linux** : `python3 fl_extract.py` → produit `fabriclens-data.json`.
   **Windows** : double-clic `fabric-lens.bat` → le rapatrie dans `data\`.
3. Ouvrir `fabric-lens.html`, bouton « Charger », pointer le fichier ou le dossier.

## Les pièces

| | |
| --- | --- |
| `scripts/remote/fl_extract.py` | le script, lancé **sans option** : distille les backups → `fabriclens-data.json` |
| `fabriclens/resolve.py` | le résolveur (référence) ; posé à côté du script, jamais lancé seul |
| `web/gabarit.html` | le webui — source unique, vide de données |
| `web/resolve.js` / `web/selfcheck.js` | résolveur JS + auto-vérification, inlinés dans le webui |
| `scripts/fabric-lens.bat` | le lanceur Windows (3 étapes) |
| `fabriclens/build_page.py` | **outil dev** : `--shell` fabrique le webui vide |

Le dossier `_ancien/` garde le flux précédent (page assemblée sur la RHEL), qui
fonctionne toujours mais n'est plus le flux recommandé.

## Ce qui a coûté cher à découvrir

Consigné dans les fichiers, mais résumé ici — ce sont des pièges qui reviendront.

**Un export APIC ne porte ni `dn` ni `rn` sur les objets enfants.** Mesuré sur un
backup réel : **64 objets sur 4 068** ont un `dn`. Tout le reste est reconstruit
depuis les règles de nommage ACI (`RN_TEMPLATES`), dérivées automatiquement de
vrais DN puis vérifiées par round-trip 467/467.

**`format=json|xml` ne change que l'extension des membres**, pas leur structure.
Un extracteur qui ne lirait que le JSON ignorerait silencieusement un backup entier.

**Un export contient des annexes sensibles** — `idconfig/` (numéros de série),
`dhcpconfig/` (TEP pool). Seuls les membres dont la racine est `polUni` ou l'un de
ses enfants sont retenus ; le reste est écarté et compté.

**Un EPG peut être déployé des deux façons à la fois** — static path *et* AAEP.
Sur 5 backups réels, 3 étaient dans ce cas pour un même VLAN. Ne retenir que le
premier mode rencontré était un mensonge.

**Un VLAN n'est pas toujours un VLAN client.** Il peut porter une interface de
L3Out avec un peering BGP/OSPF vers un équipement externe. La recherche le dit.

**`crypto.subtle` n'existe qu'en contexte sécurisé** (HTTPS ou localhost). Une
application ouverte en `file://` ne peut pas en dépendre — d'où le SHA-256 en JS pur.

**Les noms de classes CSS génériques entrent en collision.** L'animation
d'ouverture utilisait `.row`, que l'application définit déjà à `height: 17px` —
les étages étaient écrasés. Tout le CSS de l'intro est préfixé `f*`.

## Vérification

Le résolveur JavaScript est une réécriture du Python. Les deux doivent donner
**exactement** le même graphe.

```bash
node tests/diff_resolveur.mjs    # 56 requêtes sur données réelles
node tests/diff_ipv6.mjs         # 16 requêtes IPv6 + bornes IPv4
```

Au total **5 782 nœuds et 5 597 arêtes** comparés, 0 écart.

L'application se vérifie aussi elle-même, chez l'utilisateur : `resolve.py --digests`
calcule l'empreinte de chaque requête possible, la page recalcule et compare. Le
résultat s'affiche en bas à droite (« vérifié 78/78 »). Tout se passe sur la machine
du client, rien n'en sort — une empreinte ne permet de reconstituer ni DN, ni IP,
ni nom de tenant.

Les jeux de données et les références ne sont pas versionnés (voir `.gitignore`) :
ils se régénèrent avec `fl_extract.py` puis `resolve.py --digests`.

## Design

Design system **Nocturne**, importé de Claude Design. `design/nocturne.css` est la
source de vérité : toutes les couleurs, espacements et rayons viennent de ses
variables. Voir `docs/design-spec.md`.
