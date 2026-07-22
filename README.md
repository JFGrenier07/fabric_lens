# Fabric Lens

Analyseur hors ligne de configurations Cisco ACI. Cherche un VLAN, un subnet ou
une IP et montre, à travers toutes les fabriques, la chaîne d'objets qui le porte
— de l'encap block jusqu'aux ports physiques, et du tenant jusqu'aux contrats.

Ne se connecte à aucun APIC : lit les **backups de configuration** du jour.

```
       la RHEL                                        le poste Windows
  ┌──────────────────┐                           ┌──────────────────────┐
  │ ce2_*.tar.gz     │   fl_extract.py           │ fabric-lens-fetch.bat│
  │ (17 fabriques)   │──▶ distille               │   plink / pscp       │
  └──────────────────┘   build_page.py           └──────────┬───────────┘
                         assemble                           │
                              │                             ▼
                              └──────────────▶  data\fabric-lens.html
                                                 UN fichier, double-clic
```

Aucun Python, aucun serveur, aucun réseau côté Windows.

## Installation

```bash
python3 make_deploy.py      # -> deploy/FabricLens/ + FabricLens.zip
```

Puis voir **[docs/LISEZ-MOI.txt](docs/LISEZ-MOI.txt)**.
En bref : copier `deploy/FabricLens/` sur le poste, régler deux valeurs
(le nom de la session PuTTY, et le bloc `FABRICS` en tête de `fl_extract.py`),
puis lancer `fabric-lens-fetch.bat test`.

## Les pièces

| | |
| --- | --- |
| `scripts/remote/fl_extract.py` | lit les `.tar.gz`, aplatit l'arbre MIT, distille |
| `fabriclens/resolve.py` | le résolveur — **la référence** |
| `fabriclens/build_page.py` | assemble la page d'un seul fichier |
| `web/resolve.js` | portage JavaScript du résolveur |
| `web/selfcheck.js` | SHA-256 en JS pur + rejeu des empreintes |
| `web/gabarit.html` | l'application (vue Orbitale + vue Carte) — **source unique**, vide de données |
| `make_deploy.py` | fabrique le paquet à copier sur le poste |
| `scripts/fabric-lens-fetch.bat` | le lanceur Windows |

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
