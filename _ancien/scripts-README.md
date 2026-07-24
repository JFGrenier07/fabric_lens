# Récupération des backups — mode d'emploi

## Le principe

L'extraction se fait **sur le serveur RHEL**, pas sur le poste Windows.

```
  Poste Windows                          Serveur RHEL
  ─────────────                          ────────────
  fabric-lens-fetch.bat
        │
        │  1. pscp  ──────────────────►  fl_extract.py          (quelques Ko)
        │  2. plink ──────────────────►  execution
        │                                   │
        │                                   ├─ lit  ce2_*.tar.gz   (des Go)
        │                                   ├─ aplatit l'arbre MIT
        │                                   ├─ filtre 90 classes utiles
        │                                   └─ ecrit <fabric>.fl.json.gz
        │  3. pscp  ◄──────────────────  fichiers distilles       (des Ko)
        ▼
  data\distilled\
```

Un export APIC complet est massif et **43 % de son contenu est du bruit de
monitoring** (`statsColl`, `statsReportable`, `statsThrDoubleP`…). Après filtrage
il reste **~13 % des objets**, et une fois gzippé c'est négligeable. On transfère
donc des kilo-octets au lieu de giga-octets, et le poste Windows n'ouvre jamais
une archive tar.

### JSON ou XML — les deux

Sur `configExportP`, l'attribut `format=json|xml` **ne change que l'extension des
membres**, pas leur structure. Un extracteur qui ne lirait que le JSON ignorerait
silencieusement un backup entier. `fl_extract.py` lit les deux et produit un
résultat **identique au DN près** — c'est vérifié par l'autotest.

### Ce qui est délibérément écarté

Un export réel ne contient pas que l'arbre de politiques. Il embarque aussi
`idconfig/` (numéros de série des switches), `dhcpconfig/` (TEP pool, IP
d'infrastructure) et `packages/` (device packages L4-L7).

L'extracteur ne retient un membre d'archive que si sa **racine** est `polUni` ou
l'un de ses enfants directs connus. Les annexes sont donc écartées d'office — et
comptées, pas oubliées : la ligne `racines ecartees` du journal dit exactement ce
qui a été ignoré.

Ajouté aux attributs sensibles (mots de passe, communautés SNMP, clés) qui sont
jetés sans être lus, les fichiers qui atterrissent sur le portable ne contiennent
**aucun secret et aucune donnée d'infrastructure**, même chiffrée.

## Mise en route

1. Ouvrir [fabric-lens-fetch.bat](fabric-lens-fetch.bat) et régler le bloc
   `CONFIGURATION` en tête :
   - `PUTTY_SESSION` — le nom **exact** de la session PuTTY qui fonctionne déjà
     (celle avec Kerberos). Aucun mot de passe, aucune clé n'est stockée ici.
   - `REMOTE_BACKUP_ROOT` — où vivent les `ce2_*.tar.gz` sur le RHEL.
   - `PUTTY_DIR` — seulement si `plink.exe`/`pscp.exe` ne sont pas dans le `PATH`.
2. Déclarer où sont les fabrics — voir la section suivante.
3. **Lancer d'abord le mode test** : `fabric-lens-fetch.bat test`
4. Si la liste affichée est juste, lancer sans argument : `fabric-lens-fetch.bat`

Le script s'arrête au premier problème et **ne touche à rien localement** en cas
d'échec. Chaque étape est annoncée, et l'erreur dit quoi vérifier.

---

## Où sont mes fabrics ? — un seul endroit

Tout se déclare dans le **bloc `FABRICS` en tête de
[remote/fl_extract.py](remote/fl_extract.py)**. Une ligne par fabric, c'est tout.

```python
FABRICS = [
    ("DC-PARIS-01",  "/data/backups/aci/paris"),
    ("DC-LYON-02",   "/data/backups/aci/lyon"),
    ("DC-FRA-03",    "/data/backups/aci/francfort/ce2_*.tar.gz"),
    ("DC-MTL-04",    "montreal"),
]
```

Tu édites ce fichier **côté Windows**. Le `.bat` le repousse sur le RHEL à chaque
exécution, donc le serveur suit tout seul — rien à maintenir des deux côtés.

**Le premier élément** est le nom affiché dans Fabric Lens. Pas d'espaces.

**Le second** accepte trois formes, mélangeables librement :

| Forme | Exemple | Effet |
| --- | --- | --- |
| un répertoire | `/data/backups/aci/paris` | prend le `*.tar.gz` le plus récent dedans |
| un motif | `/data/backups/aci/paris/ce2_*.tar.gz` | prend le plus récent qui correspond |
| un chemin relatif | `paris` | relatif à `REMOTE_BACKUP_ROOT` du `.bat` |

Si tu n'utilises que des chemins **absolus**, `REMOTE_BACKUP_ROOT` devient inutile.

Un chemin qui ne correspond à rien produit un **avertissement, pas un échec** :
les autres fabrics sont traités normalement, et le mode test te dit lequel cloche.

### Le backup le plus récent gagne

Quand plusieurs archives correspondent, l'extracteur retient la plus récente —
d'abord par le **timestamp dans le nom** (format APIC `2026-07-20T17-00-24`), et
à défaut par la date de modification. La colonne `CANDIDATS` du mode test indique
combien d'archives ont été vues par fabric.

### Les deux replis, si tu laisses `FABRICS` vide

1. **Un sous-répertoire par fabric** sous `REMOTE_BACKUP_ROOT` — le nom du
   répertoire devient le nom du fabric. Pratique si ton rangement est déjà
   uniforme : il n'y a alors rien du tout à déclarer.
2. **Tout à plat** — l'extracteur devine le fabric depuis le nom de fichier, en
   retirant le préfixe `ce_`/`ce2_` et le timestamp. Filet de sécurité, pas un
   mode recommandé : si tes noms ne distinguent pas les fabrics, tout se
   retrouvera fusionné sous un seul identifiant.

Un `fabrics.csv` (voir `fabrics.example.csv`) reste accepté pour qui préfère,
mais le bloc `FABRICS` le remplace avantageusement et **prend le dessus** s'il est
rempli. Le journal annonce toujours la source retenue :

```
source de configuration : bloc FABRICS en tete de fl_extract.py (17 entree(s))
```

---

## Tester sans rien casser

### Le mode test — à faire en premier

```bat
fabric-lens-fetch.bat test
```

Il vérifie la connexion, **teste l'extracteur sur une archive synthétique**, puis
liste ce qu'il a repéré. Il n'ouvre aucun backup, n'écrit rien, ne télécharge
rien.

```
[5/6] Autotest de l'extracteur sur le serveur...

  mise en page monolithique   1 fichier(s) -> 41 objets
  mise en page eclatee        3 fichier(s) -> 41 objets
  les deux mises en page produisent des DN identiques  [OK]

  Verification des maillons de chaine :
    [OK]   VLAN pool
    [OK]   encap block
    ...
    [OK]   l3extSubnet (scopes)

  26/26 maillons reconstruits
FL-SELFTEST-OK

[6/6] Reperage des backups (aucune archive n'est ouverte)...

  FABRIC                 BACKUP RETENU                              TAILLE  CANDIDATS
  ------------------------------------------------------------------------------------
  DC-PARIS-01            ce2_DailyAutoBackup-2026-07-20T01-00-14...  1.2 Go  14
  DC-LYON-02             ce2_DailyAutoBackup-2026-07-20T01-04-02...  980 Mo  14
```

L'autotest fabrique un mini-MIT couvrant **les deux chaînes complètes**
(VLAN pool → encap block → domain → AAEP → IPG → ports, et tenant → VRF → BD →
subnet → EPG → contrats → L3Out → ext-EPG → `l3extSubnet` avec ses scopes),
volontairement **sans aucun `dn` ni `rn`** — le cas difficile — puis vérifie que
chaque maillon est reconstruit avec le bon DN. C'est ce qui prouve que le
`python3` de *ton* serveur fait le travail correctement, avant de toucher aux
vraies données.

### Tester directement sur le RHEL

```bash
python3 ~/.fabric-lens/fl_extract.py --selftest
python3 ~/.fabric-lens/fl_extract.py --root /data/backups/aci --dry-run
python3 ~/.fabric-lens/fl_extract.py --root /data/backups/aci --out /tmp/fl --only DC-PARIS-01
```

`--dry-run` est la boucle rapide pour ajuster les chemins : il ne fait que
repérer, tu peux l'enchaîner autant de fois que nécessaire sans coût.
`--only` limite à un seul fabric — c'est la bonne façon de faire un premier
essai réel sur un gros backup.

### Tester sur les backups réels déjà présents sur la VM Ubuntu

Sept vrais exports APIC traînent déjà dans `~/ai` — c'est le corpus de test, aucune
prod n'est touchée :

```
/home/jfg/ai/aci-as-code/ce2_defaultOneTime-*.tar.gz          (3 dates)
/home/jfg/ai/dafe_py3/ce2_defaultOneTime-*.tar.gz             (2 dates)
/home/jfg/ai/nac_tool/ce2_defaultOneTime-*.tar.gz
/home/jfg/ai/fabric_reconstruction/ce2_defaultOneTime-*.tar.gz
/home/jfg/ai/cicd/aci-fabric-as-code/tests/fixtures/backups/ce2_*.tar.gz
```

Remplis le bloc `FABRICS` avec ces chemins et lance :

```bash
python3 scripts/remote/fl_extract.py --dry-run
python3 scripts/remote/fl_extract.py --out /tmp/fl-out
```

Ce corpus a servi à valider l'extracteur. Ce qu'il a appris :

- La structure réelle d'un export est `ce2_<policy>-<ts>_1.json` (l'arbre `uni`
  entier) + un `.md5` + 33 `idconfig/*_idfile.json` de racine `topRoot` + parfois
  `packages/`. Le filtre par classe racine écarte les annexes proprement.
- **Sur 4 068 objets du fichier principal, 64 portent un `dn`. 4 004 n'ont ni
  `dn` ni `rn`.** Sans la reconstruction depuis `RN_TEMPLATES`, 98 % d'un backup
  réel serait inexploitable.
- La métrique « objets utiles perdus » a immédiatement révélé un trou réel : les
  access policies côté **spine** (`infraSpineP`, `infraSpAccPortP`,
  `infraSpAccPortGrp`) manquaient. Ajoutées, puis vérifiées.

### Tester sur ton poste Windows, sans le RHEL

Si Python est installé sur le poste, tout marche pareil en local :

```bat
python scripts\remote\fl_extract.py --selftest
python scripts\remote\fl_extract.py --root D:\backups-aci --out D:\fl-out
```

Copie un seul `.tar.gz` dans un répertoire local et pointe `--root` dessus.
L'extracteur ne dépend d'aucune bibliothèque externe et ne fait aucun appel
réseau.

## Ce qui est ré-extrait, et ce qui ne l'est pas

`fl_extract.py` empreinte chaque archive source en SHA-256 et tient un
`manifest.json`. Une archive inchangée depuis la dernière exécution est ignorée.
Relancer le `.bat` tous les matins ne coûte donc presque rien : seuls les fabrics
dont le backup a bougé sont retraités. `--force` passe outre.

## Fiabilité de la reconstruction des DN

Le point délicat : **un export APIC ne porte pas forcément `dn` ni `rn`** sur les
objets enfants. Vérifié sur un APIC 6.0(7e) — une sortie `config-only`, qui est
le contenu même d'un export, supprime les deux partout sauf à la racine.

L'extracteur reconstruit donc chaque DN depuis les règles de nommage ACI
(`RN_TEMPLATES` dans [remote/fl_extract.py](remote/fl_extract.py)). Ces gabarits
n'ont pas été écrits de mémoire : ils ont été **dérivés automatiquement** des
vrais DN d'un APIC, puis vérifiés par round-trip.

Résultat sur le lab : **467 DN reconstruits sur 467, aucun DN fantôme**, et
résultat identique que l'archive contienne un seul gros JSON ou un fichier par
sous-arbre.

Un gabarit manquant n'est jamais silencieux : la branche est écartée, comptée, et
signalée en fin d'exécution (`classes UTILES sans gabarit de nommage`). C'est
ainsi qu'on découvrira ce que les vrais backups contiennent en plus du lab.

## Dépannage

| Symptôme | Piste |
| --- | --- |
| `plink.exe introuvable` | PuTTY hors du `PATH` → renseigner `PUTTY_DIR` |
| `connexion impossible` | nom de session inexact, ou ticket Kerberos expiré (`klist`) |
| `aucun objet utile extrait` | archive en XML → passer `configExportP` en `format=json` |
| `X membre(s) XML detecte(s)` | idem |
| `classes UTILES sans gabarit` | une construction ACI absente du lab → me transmettre la liste |
| `memoire insuffisante` | relancer ce fabric seul : `--only <fabric_id>` |

## Exécution manuelle sur le RHEL

```bash
python3 fl_extract.py --root /data/backups/aci --out ~/.fabric-lens/out
python3 fl_extract.py --root /data/backups/aci --out ~/.fabric-lens/out --only DC-PARIS-01 --force
```

Python 3.6+ (RHEL 8 et 9 conviennent), **bibliothèque standard uniquement** —
aucun `pip install`, aucun droit root.
