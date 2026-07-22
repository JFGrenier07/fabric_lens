# Fabric Lens — spécification visuelle

Source : projet Claude Design **Cisco ACI Policy Analyzer**
(`9f80512e-24ea-470c-9c8c-6c30f77c0b79`), écrans `Fabric Lens.dc.html` et
`ACI Policy Analyzer.dc.html`. Design system : **Nocturne** → `design/nocturne.css`.

## Identité

- Fond `--color-bg` `#161826`, surfaces `#232532`, texte `#e9e9ed`.
- Accent unique **blurple** `#9184d9`, utilisé **en trait et en lueur**, jamais en aplat large.
- Inter 400/500/600, densité 0.70×, rayons 8px.
- Chiffres, DN, noms d'objets ACI : toujours en **monospace** (`.mono`).
- Interface **française**, termes ACI **en anglais** (EPG, Bridge Domain, AAEP, contract…).
- Icônes : Phosphor.

## Séquence d'ouverture (« intro »)

Overlay plein écran, ~2.85 s puis fondu vers l'app (~3.35 s), rejouable via `↻ Rejouer l'intro`.

1. **0 – 1.4 s** — constellation de 20 nœuds disposés sur 3 anneaux elliptiques
   (rayon `118 + ring*42`, aplatissement `y*0.72`), apparition en `fl-pop`
   cubic-bezier(.34,1.56,.64,1), décalage 40 ms par nœud.
   Les nœuds de l'anneau 0 sont des « hubs » (11px, halo accent) ; les autres 7px.
   Arêtes tracées en `fl-draw` (stroke-dashoffset 1→0) : anneau complet + rayon
   vers le centre 1 nœud sur 4. Trois labels : `DC-PARIS-01`, `DC-LYON-02`, `DC-FRA-03`.
   Légende : « Connexion aux 20 fabrics APIC… »
2. **0.95 s** — le logo `FL` apparaît au centre (`fl-logo`) et pulse une fois (`fl-pulse`).
3. **1.45 s** — toute la constellation converge vers le centre (`fl-converge`, scale .55, opacity 0).
4. **1.55 s** — la **chaîne de policy** se construit de bas en haut, 7 étages,
   120 ms d'écart, reliés par une barre verticale en dégradé accent qui pousse (`fl-grow`) :
   `LEAF PORT` → `IPG` → `AAEP` → `PHYSICAL DOMAIN` → `VLAN POOL` → `BRIDGE DOMAIN` → `EPG`.
   Le dernier étage (EPG) est cerclé d'accent et pulse.
   Légende : « Résolution des chaînes de policy… »
5. **2.85 s** — fondu de l'overlay, l'app entre en `fl-appin` (scale .99 → 1).

## Chrome de l'app

Barre supérieure : pastille `FL` (accent-900 / accent-300) · « Fabric Lens · ACI Policy
Analyzer » · champ de recherche `⌕` avec hint `VLAN · subnet · IP` · segmented control
**Explorateur / Comparaison** (option active = trait accent en `inset box-shadow`) ·
tag `20 fabrics` · bouton fantôme `↻ Rejouer l'intro`.

## Vue 1 — Explorateur (`grid 230px / 1fr / 290px`)

- **Gauche — Résultats.** Une carte par fabric qui matche. Carte sélectionnée : bordure
  accent + halo `0 0 0 3px accent@14%`. Sous-titre = pourquoi ça matche
  (« Tenant PROD · encap statique », « VLAN présent dans un pool, non déployé »).
  Ligne de synthèse « N fabrics sans correspondance ». Pied : fraîcheur des données.
- **Centre — deux colonnes de 300px**, cartes empilées reliées par un trait de 2px :
  - *Chaîne access policies* : VLAN Pool → Physical Domain → AAEP → Interface Policy
    Group → paire de leaves/ports (côte à côte pour un vPC).
  - *Chaîne logique* : Tenant → Bridge Domain → **EPG (sélectionné, accent + halo)** →
    contrats, `Provide` sur fond accent-900, `Consume` sur fond neutral-900.
  - Chaque carte : kicker uppercase 9.5px letter-spacing .08em, nom en mono 12.5px/600,
    ligne de détail neutral-400.
- **Droite — Détail** (fond `--color-surface`) : paires libellé/valeur, bloc Contrats
  (subject + filtres + qui consomme/fournit), et en pied le **DN complet** en mono 10px.

## Vue 2 — Comparaison multi-fabric

Bandeau : la requête en mono + tag `Subnet présent dans 2 fabrics`.
Deux colonnes 1fr/1fr séparées par un filet. Par fabric : nom + tag de qualification
(`primaire`, `encap différent`), mini-hiérarchie BD → EPG, puis **flux de contrats**
lus horizontalement : `ext-EPG (pointillés)` —CONSUME→ `Contrat (accent)` ←PROVIDE— `EPG`.
Encadré **Analyse** en bas : le diagnostic en une phrase, préfixé « Analyse : » en accent-300.

## Vue 3 — Scène 3D (option `1b`, backlog)

`perspective: 1600px`, 7 plans `translateZ(0…384px)` de 440×280, `rotateX(58deg)
rotateZ(-32deg)`, rotation au drag (rotX clampé 20–85°). Clic sur un plan = isolation
(les autres tombent à `opacity .28`). Panneau latéral « Chemin résolu · 7 couches »
synchronisé avec le plan sélectionné. Chips accent pour les objets du chemin,
chips fantômes (bordure accent-800) pour les objets voisins non retenus.

## Règles Nocturne à respecter

- Jamais d'aplat saturé ; l'accent est une ligne, une bordure, une lueur.
- Boutons primaires **outline**, jamais remplis.
- Filets libres en dégradé qui s'efface sur 48px aux extrémités (`.hr`, lignes de `.table`).
- Élévation = bordure fine + ombre ambiante (`--shadow-sm/md/lg`), jamais empilée.
- Focus clavier : `outline: 2px solid var(--color-accent); outline-offset: 2px`.
- Texte accent en taille paragraphe → utiliser `--color-accent-300`, pas l'accent brut.

## Données affichées qui ne viennent PAS d'un backup

À arbitrer (cf. `docs/` et la discussion de cadrage) : `42 endpoints actifs`,
« Dernier sync APIC : il y a 4 min », `0 EP` côté Lyon. Ce sont des données
**opérationnelles** (`fvCEp`, faults, état de déploiement) absentes d'un export de
configuration. Soit on les retire, soit on ajoute une source APIC live optionnelle.
