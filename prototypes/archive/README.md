# Prototypes écartés

Retirés sur demande, **pas détruits** — il n'y a pas de git ici.

- `concept-c-strates.html` — strates 3D en perspective. Jury : enterre le conflit
  de VRF au fond de la pile sous 1,6 px de flou.
- `concept-d-graphe.html` — graphe force-directed. Jury : se réduit à un blob
  dont le rail latéral fait tout le travail.

Retenu : `../concept-a-orbite.html` pour la recherche de **subnet** (choix de
Jean-François, contre l'avis du jury qui préférait B).
`../concept-b-flux.html` est conservé comme réservoir d'idées : c'est lui qui
porte la lecture correcte des scopes `import-security` / `export-rtctrl`.

## app-prise-1.html — écartée le 2026-07-21

Gagnante du jury, mais **cassée à l'usage** : la mise à l'échelle du graphe
partait dans le décor (il fallait descendre à 20 % de zoom navigateur pour voir
quelque chose) et l'orbite n'affichait plus aucune capsule.

Deux de mes correctifs en sont la cause, et c'est instructif :
- `zoomMode = "loupe"` à l'atterrissage → arrivée à ~2× ;
- le plancher `MIN_SCALE` sur `overviewVB()` → impossible de dézoomer assez
  pour reprendre une vue d'ensemble.

Corriger une taille de police en cassant l'échelle du graphe : le remède était
pire que le mal. La leçon retenue — mesurer dans le navigateur AVANT de toucher
à la géométrie, pas seulement après.

**Ce qui a été sauvé** : sa plongée (la carte naît à la position et à la taille
exactes de la capsule cliquée, puis grandit pendant qu'on traverse l'orbite).
Elle est greffée dans `../app-prise-2.html`, qui devient l'application.

## app-prise-2-avec-donnees-labo.html

**Non versionne** (voir `.gitignore`) : ce fichier embarque la configuration
complete des fabriques de labo — tenants, VRF, subnets, VLAN pools. Le depot
etant public, la config d'un parc ACI n'y a pas sa place.

Il reste present en local comme temoin de la version validee dans le navigateur
(tailles, plongee, animation d'ouverture). Pour le reconstruire :

    python3 fabriclens/build_page.py --distilled <dir> --template web/gabarit.html

**La version vivante est `web/gabarit.html`** — le meme fichier, vide de donnees.
`build_page.py` y injecte les donnees du jour. Ne pas editer deux fichiers :
le gabarit est la source unique.
