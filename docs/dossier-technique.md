# Fabric Lens — Dossier technique de référence

*Document de référence pour l'implémentation. Toute divergence entre ce document et le code doit être arbitrée en faveur d'un test contre un backup réel du client.*
Conventions : les noms de classes et d'attributs Cisco ACI sont **en anglais, verbatim**. ⚠ = point non vérifié ou contredit par la recherche adversariale, à confirmer avant codage.

---

## 1. Format des backups ACI

### 1.1 Ce que produit réellement un `configExportP`

Un déclenchement de `configExportP` produit **une archive `.tar.gz` par exécution**, construite à partir des arbres de MO configurables des **32 shards** du cluster APIC. Ce n'est **pas** un gros JSON unique.

Nom de fichier observé en production : `ce2_<policyName>-<YYYY>-<MM>-<DD>T<hh>-<mm>-<ss>.tar.gz`
— l'heure utilise des **tirets**, pas des deux-points ; le préfixe est `ce2_` dans les exemples Cisco CLI et dans les exports réels, mais la doc GUI documente `ce_`. **Parser le préfixe avec `^ce\d*_`**.

Politiques auto-créées : `defaultOneTime` (bouton « Take Snapshot Now »), `defaultAuto` (snapshot récurrent).

### 1.2 Arborescence de l'archive (export réel APIC ~4.2, 35 fichiers, 4,64 Mo décompressés)

```
ce2_defaultOneTime-2020-11-17T17-00-58_1.xml          1 957 713 B  <- TOUT l'arbre `uni`
idconfig/ce2_..._1_idfile.xml  ...  _32_idfile.xml    2 576 344 B  <- état d'allocation d'IDs par shard
dhcpconfig/ce2_..._255_idfile.xml                                   <- inventaire switches (serial, nodeId, model, version, TEP)
packages/Fortinet.FGAPIC.1.3-51.zip                                 <- device packages L4-L7
```

- Le fichier `_1` porte **l'univers de politiques complet** : 72 enfants directs de `polUni` (23 `fvTenant`, 14 `l3extDomP`, 13 `physDomP`, 7 `vmmProvP`, `infraInfra`, `fabricInst`, `ctrlrInst`, `aaaUserEp`…), 12 612 MO, 573 classes distinctes.
- `format="xml"|"json"` sur `configExportP` ne change **que l'extension des membres**, pas la structure. **Ne pas filtrer sur `.json`** (c'est le bug de `goaci`, qui ignore silencieusement un backup XML) : sélectionner les membres dont la racine est `polUni` (ou un de ses enfants directs).
- Le tar.gz n'est **jamais chiffré globalement**. Le chiffrement AES-256 (`pkiExportEncryptionKey`) porte uniquement sur ~50 propriétés secrètes (liste dans l'annexe « Secure Properties » des ACI Fundamentals). Sans AES, **l'attribut secret est absent, pas vide** — le parseur doit tolérer la clé manquante, jamais tester `== ""`.
- Contenu sensible malgré tout : `fabricNodeIdentP` (serial numbers), `fabricSetupP@tepPool`, `mgmtRsOoBStNode` (IP OOB), `pkiKeyRing` (cert public), `fileRemotePath` (host/user). **Traiter les backups comme des données classifiées.**

### 1.3 Ce qui n'y est PAS (recensement de classes sur l'export réel)

| Absent | Compte mesuré |
|---|---|
| Endpoints `fvCEp` | 0 |
| Faults `faultInst`, health, eventRecord | 0 |
| VLAN déployés `vlanCktEp` | 0 |
| Nœuds `fabricNode` (vit sous `topology/…`, hors `uni`) | 0 |
| Règles de zoning résolues `actrlRule`/`actrlEntry`, `vzToEPg`, `fvEpP` | 0 |
| Métadonnées opérationnelles `modTs`, `uid`, `lcOwn`, `status`, `childAction`, `monPolDn` | 0 |
| Relations inverses `*Rt*` et objets dérivés `*Def` | 0 (non configurables) |

**Conséquence produit** : Fabric Lens donne **l'intention** (`fvRsPathAtt.tDn` + `encap`), jamais « quel VLAN est réellement programmé sur quel port maintenant ». Les écrans du design-spec mentionnant « 42 endpoints actifs » et « Dernier sync APIC » sont **hors périmètre offline** — à arbitrer.

### 1.4 Le piège central : les DN des enfants

Mesure sur l'export réel : sur 12 612 éléments, **73 seulement** portent un `dn` non vide (la racine + ses 72 enfants directs). Tout le reste a `dn=""`.

> ⚠ **Contradiction à instrumenter.** La recherche adversariale note que l'APIC DME émet normalement soit un `dn`, soit un `rn` sur les enfants d'une réponse `rsp-subtree`, et qu'aucune sérialisation documentée ne produit « ni dn ni rn ». Mais deux sources locales convergent dans l'autre sens : (a) l'export réel GitHub (`dn=""` partout), (b) le commentaire de `scripts/remote/fl_extract.py` (vérifié sur **APIC 6.0(7e)** : `rsp-prop-include=config-only` supprime `dn` ET `rn` sauf à la racine).
> **Décision : chaîne de repli à trois niveaux, instrumentée.**
> 1. `attrs["dn"]` si non vide.
> 2. sinon `parent_dn + "/" + attrs["rn"]` si `rn` non vide.
> 3. sinon RN synthétisé depuis `RN_TEMPLATES[cls]`.
> 4. **sinon : lever une exception / émettre une sentinelle comptée**, jamais `dn = parent_dn` (bug actuel de `fl_extract.py::flatten_mo`, qui fait collisionner deux `fvSubnet` de BD différents sur la même clé).
> Compter les hits de chaque branche sur un backup réel et le logger au premier run.

`fl_extract.py` embarque déjà une table `RN_TEMPLATES` (~110 classes) dérivée automatiquement de vrais DN APIC et vérifiée par round-trip 467/467. C'est l'actif le plus précieux du dépôt — ne pas la réécrire. Alternative de secours : la table `backup/rns.go` de `brightpuddle/goaci` (~2 000 lignes, MIT).

Piège complémentaire : un membre de l'archive peut avoir pour racine un **enfant** de `polUni` (ex. `fvTenant`) et non `polUni`. Sans `dn` sur cette racine, le préfixe `uni/` serait perdu et **tous** les DN du fichier seraient faux. `fl_extract.py::ROOT_PARENT` couvre ce cas.

### 1.5 Extrait JSON réaliste

Pas de wrapper `imdata`/`totalCount` dans les membres d'archive : la racine est directement l'objet MO.

```json
{
  "polUni": {
    "attributes": { "dn": "uni", "annotation": "", "nameAlias": "" },
    "children": [
      { "fvTenant": {
          "attributes": { "dn": "uni/tn-PROD", "name": "PROD", "descr": "", "ownerKey": "", "ownerTag": "" },
          "children": [
            { "fvCtx": {
                "attributes": { "dn": "", "name": "VRF-PROD", "pcEnfPref": "enforced", "pcEnfDir": "ingress" },
                "children": [
                  { "vzAny": { "attributes": { "dn": "", "name": "", "matchT": "AtleastOne", "prefGrMemb": "disabled" },
                      "children": [
                        { "vzRsAnyToProv": { "attributes": { "dn": "", "tnVzBrCPName": "CTR-SHARED-SVC" } } }
                      ] } }
                ] } },
            { "fvBD": {
                "attributes": { "dn": "", "name": "BD-APP-2110", "arpFlood": "no",
                                "unkMacUcastAct": "proxy", "unicastRoute": "yes", "limitIpLearnToSubnets": "yes" },
                "children": [
                  { "fvSubnet": { "attributes": { "dn": "", "ip": "10.21.10.1/24", "scope": "public,shared", "ctrl": "nd" } } },
                  { "fvRsCtx":   { "attributes": { "dn": "", "tnFvCtxName": "VRF-PROD" } } },
                  { "fvRsBDToOut": { "attributes": { "dn": "", "tnL3extOutName": "L3OUT-CORE" } } }
                ] } },
            { "fvAp": {
                "attributes": { "dn": "", "name": "AP-APP", "prio": "unspecified" },
                "children": [
                  { "fvAEPg": {
                      "attributes": { "dn": "", "name": "EPG-WEB", "pcEnfPref": "unenforced", "prefGrMemb": "exclude" },
                      "children": [
                        { "fvRsBd":      { "attributes": { "dn": "", "tnFvBDName": "BD-APP-2110" } } },
                        { "fvRsDomAtt":  { "attributes": { "dn": "", "tDn": "uni/phys-PD-PROD",
                                                           "instrImedcy": "lazy", "resImedcy": "immediate" } } },
                        { "fvRsPathAtt": { "attributes": { "dn": "",
                            "tDn": "topology/pod-1/protpaths-101-102/pathep-[VPC-ESX-01]",
                            "encap": "vlan-2110", "mode": "regular", "instrImedcy": "lazy" } } },
                        { "fvRsProv":    { "attributes": { "dn": "", "tnVzBrCPName": "CTR-WEB", "matchT": "AtleastOne" } } },
                        { "fvRsCons":    { "attributes": { "dn": "", "tnVzBrCPName": "CTR-DB" } } }
                      ] } }
                ] } }
          ] } },
      { "physDomP": {
          "attributes": { "dn": "uni/phys-PD-PROD", "name": "PD-PROD" },
          "children": [ { "infraRsVlanNs": { "attributes": { "dn": "", "tDn": "uni/infra/vlanns-[VLP-PROD]-static" } } } ] } },
      { "infraInfra": {
          "attributes": { "dn": "uni/infra" },
          "children": [
            { "fvnsVlanInstP": {
                "attributes": { "dn": "", "name": "VLP-PROD", "allocMode": "static" },
                "children": [
                  { "fvnsEncapBlk": { "attributes": { "dn": "", "from": "vlan-2100", "to": "vlan-2199",
                                                      "allocMode": "inherit", "role": "external" } } }
                ] } },
            { "infraAttEntityP": {
                "attributes": { "dn": "", "name": "AEP-ESX" },
                "children": [ { "infraRsDomP": { "attributes": { "dn": "", "tDn": "uni/phys-PD-PROD" } } } ] } },
            { "infraFuncP": {
                "attributes": { "dn": "" },
                "children": [
                  { "infraAccBndlGrp": {
                      "attributes": { "dn": "", "name": "VPC-ESX-01", "lagT": "node" },
                      "children": [
                        { "infraRsAttEntP": { "attributes": { "dn": "", "tDn": "uni/infra/attentp-AEP-ESX" } } },
                        { "infraRsLacpPol": { "attributes": { "dn": "", "tnLacpLagPolName": "LACP-ACTIVE" } } }
                      ] } }
                ] } },
            { "infraAccPortP": {
                "attributes": { "dn": "", "name": "IPROF-101-102" },
                "children": [
                  { "infraHPortS": {
                      "attributes": { "dn": "", "name": "SEL-ESX-01", "type": "range" },
                      "children": [
                        { "infraPortBlk":       { "attributes": { "dn": "", "name": "blk1", "fromCard": "1", "toCard": "1", "fromPort": "17", "toPort": "17" } } },
                        { "infraRsAccBaseGrp":  { "attributes": { "dn": "", "tDn": "uni/infra/funcprof/accbundle-VPC-ESX-01", "fexId": "101" } } }
                      ] } }
                ] } },
            { "infraNodeP": {
                "attributes": { "dn": "", "name": "SPROF-101-102" },
                "children": [
                  { "infraLeafS": {
                      "attributes": { "dn": "", "name": "SEL-101-102", "type": "range" },
                      "children": [ { "infraNodeBlk": { "attributes": { "dn": "", "name": "blk1", "from_": "101", "to_": "102" } } } ] } },
                  { "infraRsAccPortP": { "attributes": { "dn": "", "tDn": "uni/infra/accportprof-IPROF-101-102" } } }
                ] } }
          ] } },
      { "fabricInst": {
          "attributes": { "dn": "uni/fabric" },
          "children": [
            { "fabricProtPol": { "attributes": { "dn": "" }, "children": [
                { "fabricExplicitGEp": { "attributes": { "dn": "", "name": "VPC-101-102", "id": "10" },
                    "children": [
                      { "fabricNodePEp": { "attributes": { "dn": "", "id": "101", "podId": "1" } } },
                      { "fabricNodePEp": { "attributes": { "dn": "", "id": "102", "podId": "1" } } }
                    ] } }
              ] } }
          ] } }
    ]
  }
}
```

Points à noter dans cet extrait, tous porteurs de bugs classiques :
- `fvnsEncapBlk` utilise `from`/`to` **sans underscore** ; `infraNodeBlk` utilise `from_`/`to_` **avec underscore**. Ne pas partager le même helper de parsing de plage sans paramètre d'orthographe.
- `fvRsPathAtt.tDn` contient des **crochets imbriqués** : `rspathAtt-[topology/pod-1/protpaths-101-102/pathep-[VPC-ESX-01]]`. Toute regex `\[([^\]]*)\]` tronque. Splitter les DN sur `/` **uniquement à profondeur de crochets 0**.
- `fvSubnet.ip` est une **adresse hôte + masque** (`10.21.10.1/24`), pas une adresse réseau → `ipaddress.ip_network(txt, strict=False)` obligatoire.
- `fvnsEncapBlk.allocMode="inherit"` (défaut) doit être résolu vers l'`allocMode` du `fvnsVlanInstP` parent.

---

## 2. Graphe d'objets à résoudre

Règle générale vérifiée : les relations pointant vers un objet dont le conteneur est **ambigu** (domaines, AAEP, pools, EPG, profils, policy groups, chemins) portent un **`tDn` complet**. Celles pointant vers un objet à conteneur **unique** (politiques sous `uni/infra/`, objets du même tenant) portent un **`tnXxxName`** — un **nom seul**, à résoudre dans le tenant courant puis en repli sur `tn-common` (pas de troisième repli : tout autre usage inter-tenant passe par `vzCPIf`/`vzRsIf`).

Deux nuances vérifiées à ne pas confondre :
- `tnXxxName` est **naming property** (donc dans le RN) sur `fvRsProv` (`rsprov-{tnVzBrCPName}`), `fvRsCons`, `fvRsConsIf`, `fvRsProtBy`, `fvRsIntraEpg`, `vzRsSubjFiltAtt`, `vzRsFiltAtt`.
- `tnXxxName` est **admin, pas naming** sur `fvRsBd` (RN fixe `rsbd`), `fvRsCtx` (`rsctx`), `l3extRsEctx` (`rsectx`), `fvRsScope` (`rsscope`) — ce sont des singletons à RN constant. Pour la reconstruction de DN, on **concatène le RN littéral**, on ne le fabrique pas depuis le nom.

### 2.1 Chaîne d'access policies (VLAN pool → port physique)

| Class | DN | Attribut de liaison | Pointe vers |
|---|---|---|---|
| `fvnsVlanInstP` | `uni/infra/vlanns-[{name}]-{allocMode}` | — (racine de la chaîne) | — |
| `fvnsEncapBlk` | `…/vlanns-[…]/from-[{from}]-to-[{to}]` | `from`, `to` (`vlan-100`), `allocMode` (`inherit` par défaut), `role` | plage d'encaps |
| `infraRsVlanNs` | `<domaineDn>/rsvlanNs` (singleton) | **`tDn`** | `fvnsVlanInstP` |
| `physDomP` | `uni/phys-{name}` | — | — |
| `l3extDomP` | `uni/l3dom-{name}` | — | — |
| `l2extDomP` | `uni/l2dom-{name}` | — | — |
| `fcDomP` | `uni/fc-{name}` | — | — |
| `vmmDomP` | `uni/vmmp-{vendor}/dom-{name}` | peut porter `fvnsEncapBlk` **en enfant direct** en plus de `infraRsVlanNs` — fusionner les deux sources | — |
| `infraRsDomP` | `uni/infra/attentp-{name}/rsdomP-[{tDn}]` | **`tDn`** (naming) | `physDomP` \| `l3extDomP` \| `l2extDomP` \| `vmmDomP` \| `fcDomP` |
| `infraAttEntityP` | `uni/infra/attentp-{name}` | — | — |
| `infraGeneric` | `uni/infra/attentp-{name}/gen-default` | conteneur | — |
| `infraRsFuncToEpg` | `…/gen-default/rsfuncToEpg-[{tDn}]` | **`tDn`** + `encap`, `primaryEncap`, `mode`, `instrImedcy` | `fvAEPg` (EPG déployé sur **tous** les ports de l'AAEP) |
| `infraRsAttEntP` | `…/funcprof/accportgrp-{name}/rsattEntP` (singleton) | **`tDn`** | `infraAttEntityP` |
| `infraAccPortGrp` | `uni/infra/funcprof/accportgrp-{name}` | port d'accès individuel | — |
| `infraAccBndlGrp` | `uni/infra/funcprof/accbundle-{name}` | **`lagT`** : `link`=PC, `node`=vPC, `not-aggregated`, `fc-link` | — |
| `infraRsAccBaseGrp` | `…/hports-{name}-typ-{type}/rsaccBaseGrp` (singleton) | **`tDn`** + `fexId` (101-199) | `infraAccPortGrp` \| `infraAccBndlGrp` \| `infraFexBndlGrp` |
| `infraHPortS` | `uni/infra/accportprof-{name}/hports-{name}-typ-{type}` | clé composite (`name`,`type`) — **jamais `name` seul** | — |
| `infraPortBlk` | `…/hports-…/portblk-{name}` | `fromCard`/`toCard`/`fromPort`/`toPort` (tous défaut = 1) | ports `eth{card}/{port}` |
| `infraSubPortBlk` | `…/hports-…/subportblk-{name}` | + `fromSubPort`/`toSubPort` | `eth{card}/{port}/{subport}` (breakout) |
| `infraAccPortP` | `uni/infra/accportprof-{name}` | — | — |
| `infraRsAccPortP` | `uni/infra/nprof-{name}/rsaccPortP-[{tDn}]` | **`tDn`** (naming, n-à-m) | `infraAccPortP` |
| `infraNodeP` | `uni/infra/nprof-{name}` | — | — |
| `infraLeafS` | `uni/infra/nprof-{name}/leaves-{name}-typ-{type}` | clé composite (`name`,`type`) | — |
| `infraNodeBlk` | `…/leaves-…/nodeblk-{name}` | **`from_`** / **`to_`** (avec underscore) | node IDs 101-16000 |
| `infraFexP` | `uni/infra/fexprof-{name}` | profil côté hôte du FEX | — |
| `infraFexBndlGrp` | `uni/infra/fexprof-{name}/fexbundle-{name}` | — | — |
| `fabricExplicitGEp` | `uni/fabric/protpol/expgep-{name}` | `id` = domaine vPC (1-1000) | — |
| `fabricNodePEp` | `…/expgep-{name}/nodepep-{id}` | `id` = node ID, `podId` | membre de la paire vPC |
| ⚠ `fabricLagId` | `…/expgep-{name}/lagid-{funcP}-{accBndlGrp}` | `accBndlGrp` = **nom** de l'`infraAccBndlGrp`, `id` = LAG ID | jointure explicite vPC ↔ IPG |

**Relations `tnXxxName` sous un policy group** (chemin de code distinct, résolution par (classe cible, nom) sous `uni/infra/`) : `infraRsHIfPol`→`tnFabricHIfPolName` (noter le « Fabric »), `infraRsLacpPol`→`tnLacpLagPolName`, `infraRsCdpIfPol`→`tnCdpIfPolName`, `infraRsLldpIfPol`→`tnLldpIfPolName`, `infraRsStpIfPol`→`tnStpIfPolName`, `infraRsMcpIfPol`→`tnMcpIfPolName`, `infraRsL2IfPol`→`tnL2IfPolName`, `infraRsMonIfInfraPol`→`tnMonInfraPolName`.

#### ⚠ Le cas vPC — correction importante

La recherche initiale affirmait « aucun objet ne relie `infraAccBndlGrp` à `fabricExplicitGEp` ». **C'est faux dans le MIM** : `fabricLagId` (classId 996, concret, présent en 3.0 et 4.2) est exactement cette jointure — son DN nomme simultanément le protection group (RN parent) et l'IPG (`accBndlGrp` naming property). Cisco le poste inline dans `fabricExplicitGEp` (guide REST « Configuring FCoE Connectivity »).

**Mais pour Fabric Lens la conclusion pratique est inchangée** : `fabricLagId.id` est en accès *implicit* et l'objet est créé par le resolver APIC au déploiement, pas par l'admin → **il est très probablement absent de l'export**. → **Instrumenter** : compter les `fabricLagId` dans un backup réel. S'il y en a, l'utiliser ; sinon, appliquer l'inférence offline :

1. `infraAccBndlGrp.lagT == "node"` ;
2. expansion `infraNodeP` → `infraRsAccPortP` → `infraAccPortP` → `infraHPortS` → `infraRsAccBaseGrp` → ensemble de node IDs ;
3. jointure de ces node IDs contre les `fabricNodePEp.id` sous `uni/fabric/protpol/expgep-*` ;
4. **signaler comme anomalie réelle** si les deux nœuds d'un bundle ne tombent pas dans le même `fabricExplicitGEp`.

Clé de regroupement vPC = **(fabricExplicitGEp, infraAccBndlGrp)**, *pas* le seul DN du policy group : un même IPG vPC réutilisé sur une autre paire de leaves produit un vPC **distinct**. C'est exactement ce qu'encode le DN de chemin déployé `topology/pod-N/protpaths-<a>-<b>/pathep-[<ipg-name>]`.

### 2.2 Chaîne logique (tenant → VRF → BD → EPG → contrats)

| Class | DN | Attribut de liaison | Pointe vers |
|---|---|---|---|
| `fvTenant` | `uni/tn-{name}` | — | — |
| `fvCtx` (VRF) | `uni/tn-{t}/ctx-{name}` | `pcEnfPref`, `pcEnfDir`, `bdEnforcedEnable`, `ipDataPlaneLearning` | — |
| `fvBD` | `uni/tn-{t}/BD-{name}` (**`BD-` majuscule**) | `unicastRoute`, `arpFlood`, `unkMacUcastAct` (`proxy`\|`flood`), `unkMcastAct`, `multiDstPktAct`, `limitIpLearnToSubnets`, `type` (`regular`\|`fc`) | — |
| `fvRsCtx` | `uni/tn-{t}/BD-{b}/rsctx` (RN fixe) | `tnFvCtxName` (nom, admin) | `fvCtx` (tenant → `common`) |
| `fvSubnet` | `…/BD-{b}/subnet-[{ip}]` | `ip` = **passerelle/masque**, `scope` bitmask (`private`\|`public`\|`shared`), `ctrl` (`querier`\|`nd`\|`no-default-gateway`), `preferred`, `virtual` | — |
| `fvRsBDToOut` | `…/BD-{b}/rsBDToOut-{tnL3extOutName}` | `tnL3extOutName` (nom) | `l3extOut` |
| `fvAp` | `uni/tn-{t}/ap-{name}` | — | — |
| `fvAEPg` | `uni/tn-{t}/ap-{a}/epg-{name}` | `pcEnfPref` (isolation intra-EPG), `prefGrMemb`, `isAttrBasedEPg`, `floodOnEncap`, `matchT` | — |
| `fvRsBd` | `…/epg-{e}/rsbd` (RN fixe) | `tnFvBDName` (nom, admin) | `fvBD` |
| `fvRsDomAtt` | `…/epg-{e}/rsdomAtt-[{tDn}]` | **`tDn`** (naming) + `instrImedcy`, `resImedcy`, `classPref`, `encap`, `encapMode`, `switchingMode` | domaine (préfixe du `tDn` donne le type) |
| `fvRsPathAtt` | `…/epg-{e}/rspathAtt-[{tDn}]` | **`tDn`** (crochets imbriqués) + `encap`, `mode` (`regular`\|`native`\|`untagged`), `instrImedcy`, `primaryEncap` | chemin `topology/pod-N/paths-\|protpaths-\|extpaths-…` |
| `fvRsNodeAtt` | `…/epg-{e}/rsnodeAtt-[{tDn}]` | **`tDn`** + `encap`, `mode`, `instrImedcy` | `fabricNode` (binding SVI/nœud) |
| `fvRsProv` | `…/epg-{e}/rsprov-{tnVzBrCPName}` | `tnVzBrCPName` (naming) + `matchT`, `prio` | `vzBrCP` |
| `fvRsCons` | `…/epg-{e}/rscons-{tnVzBrCPName}` | `tnVzBrCPName` (naming) + `prio` | `vzBrCP` |
| `fvRsIntraEpg` | `…/rsintraEpg-{tnVzBrCPName}` | `tnVzBrCPName` | `vzBrCP` (bascule l'EPG en deny-except) |
| `fvRsProtBy` | `…/rsprotBy-{tnVzTabooName}` | `tnVzTabooName` | `vzTaboo` (`uni/tn-{t}/taboo-{n}`) |
| `fvRsConsIf` | `…/rsconsIf-{tnVzCPIfName}` | `tnVzCPIfName` | `vzCPIf` |
| `vzBrCP` | `uni/tn-{t}/brc-{name}` | `scope` : `context` (défaut, = VRF) \| `tenant` \| `application-profile` \| `global` | — |
| `vzSubj` | `…/brc-{c}/subj-{name}` | `revFltPorts`, `consMatchT`, `provMatchT` | — |
| `vzRsSubjFiltAtt` | `…/subj-{s}/rssubjFiltAtt-{tnVzFilterName}` | `tnVzFilterName` + `action` (`permit`\|`deny`), `directives` (`log`,`no_stats`) | `vzFilter` |
| `vzInTerm` / `vzOutTerm` | `…/subj-{s}/intmnl`, `…/outtmnl` | conteneurs des sujets **unidirectionnels** | — |
| `vzRsFiltAtt` | `…/intmnl/rsfiltAtt-{tnVzFilterName}` | `tnVzFilterName` + `action`, `directives` | `vzFilter` — **classe différente** de `vzRsSubjFiltAtt` ; l'ignorer perd silencieusement toutes les règles one-way |
| `vzFilter` | `uni/tn-{t}/flt-{name}` | — | — |
| `vzEntry` | `…/flt-{f}/e-{name}` | `etherT`, `prot`, `dFromPort`/`dToPort`/`sFromPort`/`sToPort` (**sérialisés en NOMS** : `https`, `dns`, `http`…), `tcpRules`, `arpOpc`, `applyToFrag`, `stateful` | — |
| `vzAny` | `uni/tn-{t}/ctx-{v}/any` (singleton) | `matchT`, `prefGrMemb`, `pcTag` | — |
| `vzRsAnyToProv` / `vzRsAnyToCons` | `…/any/rsanyToProv-{tnVzBrCPName}` | `tnVzBrCPName` | `vzBrCP` — **expansion obligatoire** : provider = *tous* les EPG dont le BD résout vers cette VRF |
| `vzRsAnyToConsIf` | `…/any/rsanyToConsIf-{tnVzCPIfName}` | `tnVzCPIfName` | `vzCPIf` |
| `vzCPIf` | `uni/tn-{t}/cif-{name}` | — | — |
| `vzRsIf` | `uni/tn-{t}/cif-{c}/rsif` (**RN fixe**) | **`tDn`** — attribut *admin*, **pas naming** ⚠ | `vzBrCP` d'un autre tenant. Seul endroit où un DN de contrat cross-tenant apparaît littéralement |
| `l3extOut` | `uni/tn-{t}/out-{name}` | `enforceRtctrl` | — |
| `l3extRsEctx` | `…/out-{o}/rsectx` (RN fixe) | `tnFvCtxName` (nom, admin) | `fvCtx` |
| `l3extRsL3DomAtt` | `…/out-{o}/rsl3DomAtt` | `tDn` | `l3extDomP` |
| `l3extInstP` | `…/out-{o}/instP-{name}` (**`P` majuscule**) | réutilise `fvRsProv`/`fvRsCons`/`fvRsProtBy`/`fvRsConsIf` verbatim | — |
| `l3extSubnet` | `…/instP-{i}/extsubnet-[{ip}]` | `scope` bitmask : `import-security` (défaut), `shared-security`, `import-rtctrl`, `export-rtctrl`, `shared-rtctrl` ; `aggregate` | — |
| `l3extLNodeP` | `…/out-{o}/lnodep-{name}` | — | — |
| `l3extRsNodeL3OutAtt` | `…/lnodep-{n}/rsnodeL3OutAtt-[{tDn}]` | **`tDn`** + `rtrId`, `rtrIdLoopBack` | `fabricNode` |
| `l3extLIfP` | `…/lnodep-{n}/lifp-{name}` | — | — |
| `l3extRsPathL3OutAtt` | `…/lifp-{l}/rspathL3OutAtt-[{tDn}]` | **`tDn`** + `ifInstT` (`sub-interface`\|`l3-port`\|`ext-svi`), `encap`, `addr`, `mtu`, `encapScope` | chemin `topology/…` |
| `l2extOut` / `l2extInstP` | `uni/tn-{t}/l2out-{name}` / `…/instP-{name}` | `l2extInstP` porte aussi `fvRsProv`/`fvRsCons` | — |
| `fvESg` (APIC 5.0+) | `uni/tn-{t}/ap-{a}/esg-{name}` | sous-classe de `fv:EPg` → réutilise `fvRsProv`/`fvRsCons`/`fvRsConsIf`/`fvRsIntraEpg` verbatim | — |
| `fvRsScope` | `…/esg-{e}/rsscope` (RN fixe, 5.0+) | `tnFvCtxName` (nom, admin) | `fvCtx` — **l'ESG s'attache à la VRF, pas à un BD** |
| `fvEPSelector` | `…/esg-{e}/epselector-[{matchExpression}]` | `matchExpression` (ex. `ip=='192.168.0.1/32'`), sélecteurs en OU | — |
| ⚠ `fvEPgSelector` / `fvTagSelector` / `fvSubnetSelector` | 5.2(1)+ | `matchEpgDn` / key,value | non vérifiés dans le MIM — confirmer sur la release cible |
| `mgmtInB` | `uni/tn-mgmt/mgmtp-default/inb-{name}` | sous-classe de `fv:EPg` → porte **`fvRsProv`/`fvRsCons`** vers `vzBrCP` | — |
| `mgmtOoB` | `uni/tn-mgmt/mgmtp-default/oob-{name}` | **`mgmtRsOoBProv`** → `tnVzOOBBrCPName` (RN `rsooBProv-…`, casse exacte) | `vzOOBBrCP` |
| `mgmtInstP` | `uni/tn-mgmt/extmgmt-default/instp-{name}` | **`mgmtRsOoBCons`** → `tnVzOOBBrCPName` (RN `rsooBCons-…`) | `vzOOBBrCP` |
| `vzOOBBrCP` | `uni/tn-mgmt/oobbrc-{name}` | namespace de contrats **séparé** de `brc-` ; enfants `vzSubj` normaux | — |

#### Corrections issues de la vérification adversariale (à ne pas se faire re-piéger)

1. **`mgmtInstP` ne porte NI `fvRsProv` NI `fvRsCons`** (elle hérite de `fv:ATg`, pas `fv:EPg`). L'affirmation initiale était fausse. Out-of-band = graphe **parallèle** : `mgmtOoB` → `mgmtRsOoBProv` → `vzOOBBrCP` ← `mgmtRsOoBCons` ← `mgmtInstP`. In-band (`mgmtInB`) utilise, lui, le graphe normal `fvRsProv`/`fvRsCons`/`vzBrCP`.
2. **`vzRsIf.tDn` n'est pas une naming property** : le RN est la constante `rsif`. Lire l'attribut, ne pas le déduire du RN.
3. **Union correcte des conteneurs de `fvRsProv`/`fvRsCons`** : `{fvAEPg, fvESg, l3extInstP, l2extInstP, mgmtInB}` + `vzAny` via `vzRsAnyToProv`/`vzRsAnyToCons`. **Pas `mgmtInstP`.** Noter que `l3extInstP`/`l2extInstP` héritent de `extnw:EPg` (pas `fv:EPg`) tout en portant ces relations → **énumérer explicitement les classes conteneurs**, ne pas dériver l'ensemble par sous-classement.
4. **ESG + `fvEPgSelector`** : quand un ESG sélectionne un EPG entier, l'APIC **hérite automatiquement** des contrats de cet EPG sur l'ESG — sans créer de `fvRsProv`/`fvRsCons` sous l'ESG dans le JSON. Donc : ne **pas** signaler « conflit EPG/ESG » dans ce cas (faux positif garanti) ; traiter les contrats de l'EPG référencé comme des arêtes **héritées** de l'ESG. Ne signaler un chevauchement que si l'appartenance ESG vient de sélecteurs tag/IP/MAC/VM alors que l'EPG des mêmes endpoints porte des contrats indépendants.
5. **Chemins de permit sans objet `fvRsProv`** : `prefGrMemb="include"` sur EPG/ESG + `vzAny.pcEnfPref` (preferred groups), et `pcEnfPref="unenforced"` sur `fvCtx` (VRF non appliquée). Un analyseur qui ne regarde que les contrats affiche un modèle de sécurité faux.

#### Classes formellement exclues du resolver

**Toutes** les relations inverses `*Rt*` et **tous** les objets dérivés `*Def` sont `[NON CONFIGURABLE]` et **absents de l'export** : `vzRtProv` (RN `rtfvProv-[{tDn}]`), `vzRtCons` (`rtfvCons-`), `vzRtAnyToProv`, `vzRtConsIf`, `vzRtAnyToConsIf`, `fvRtBd` (`rtbd-`), `fvRtCtx` (`rtctx-`), `fvnsRtVlanNs`, `l2RtL2IfPol`, `infraRtAttEntP`, `infraRtAccBaseGrp`, `infraRtDomP`, `infraRsVlanNsDef`, `fvnsVlanInstDef`, `infraRsDomVxlanNsDef`.
Idem : **ne jamais brancher sur `state`, `stateQual`, `tCl`, `rType`, `tType`** — accès *implicit*, valeurs absentes ou périmées hors ligne. L'index inverse se construit **uniquement** en inversant les relations forward.

---

## 3. Récupération des backups (Windows → RHEL)

### 3.1 Recommandation

**`pscp.exe` / `plink.exe` PuTTY, livrés en binaires autonomes à côté de l'application** (pas d'installeur, pas de droits admin), avec clé ed25519 + `-hostkey` épinglé. Repli sur `ssh.exe`/`scp.exe` natifs Windows si PuTTY absent.

Justification : PuTTY est la **seule** option gérant nativement les proxies d'entreprise HTTP CONNECT / SOCKS (paramiko n'a aucun support proxy intégré, et `ProxyCommand` sur Windows est fragile). Les binaires sont auto-suffisants et copiables.

### 3.2 Empreinte du serveur — à récupérer sur le RHEL, pas par une première connexion interactive

```bash
# sur rhel01
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
# -> 256 SHA256:AbCdEf0123456789... root@rhel01 (ED25519)
```

**`-hostkey` est obligatoire, pas optionnel** : PuTTY cache les clés hôtes dans `HKCU\Software\SimonTatham\PuTTY\SshHostKeys`, qui est **par utilisateur**. Une tâche planifiée sous un autre compte ne verra jamais la clé acceptée interactivement et se bloquera indéfiniment.

### 3.3 Le .bat — lister puis boucler (jamais de wildcard serveur)

`pscp` refuse les wildcards côté serveur par défaut ; `-unsafe` est documenté comme DANGEROUS (le serveur choisit les noms renvoyés et peut écraser des chemins locaux arbitraires).

```bat
@echo off
setlocal enabledelayedexpansion
set PUTTY=%~dp0bin
set KEY=%LOCALAPPDATA%\FabricLens\keys\backup.ppk
set HK=SHA256:AbCdEf0123456789...
set TGT=backupuser@rhel01.corp.local
set DEST=%LOCALAPPDATA%\FabricLens\inbox

"%PUTTY%\plink.exe" -batch -ssh -T -i "%KEY%" -hostkey "%HK%" %TGT% "ls -1 /var/backups/aci/*.tar.gz" > "%TEMP%\fl_files.txt"
if errorlevel 1 (echo [FL] listing failed & exit /b 1)

for /f "usebackq delims=" %%F in ("%TEMP%\fl_files.txt") do (
  "%PUTTY%\pscp.exe" -batch -sftp -p -i "%KEY%" -hostkey "%HK%" "%TGT%:%%F" "%DEST%\"
  if errorlevel 1 (echo [FL] copy of %%F failed & exit /b 2)
)
exit /b 0
```

Variante avec agent (recommandée en mode attended, aucun secret sur disque en clair) :

```bat
"%PUTTY%\pageant.exe" --encrypted "%KEY%"
"%PUTTY%\pscp.exe" -batch -sftp -p -agent -hostkey "%HK%" %TGT%:/var/backups/aci/x.tar.gz "%DEST%\"
```

Exécution one-shot avec agent temporaire : `pageant.exe "%KEY%" -c cmd /c fabric-lens-fetch.bat`

### 3.4 Repli OpenSSH natif

Sonder d'abord — OpenSSH est officiellement une *Feature-on-Demand* et les images entreprise le retirent souvent :

```bat
where ssh.exe >nul 2>&1 || goto :no_openssh
```

```bat
ssh.exe -i "%LOCALAPPDATA%\FabricLens\keys\id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=yes ^
  -o UserKnownHostsFile="%PROGRAMDATA%\FabricLens\known_hosts" ^
  backupuser@rhel01.corp.local "ls -1 /var/backups/aci/*.tar.gz" > "%TEMP%\fl_files.txt"

scp.exe -i "%LOCALAPPDATA%\FabricLens\keys\id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=yes ^
  -o UserKnownHostsFile="%PROGRAMDATA%\FabricLens\known_hosts" -p ^
  backupuser@rhel01.corp.local:/var/backups/aci/x.tar.gz "%DEST%\"
```

`sftp.exe -b batch.sftp` accepte, lui, les globs distants de façon sûre (`get /var/backups/aci/*.tar.gz D:/inbox/`). Bastion : `-J jumpuser@bastion.corp.local` sur `ssh`/`scp`/`sftp` — support natif que paramiko n'a pas.

Peupler le `known_hosts` épinglé hors bande et **vérifier l'empreinte contre le serveur** :

```bat
ssh-keyscan.exe -t ed25519 rhel01.corp.local >> "%PROGRAMDATA%\FabricLens\known_hosts"
ssh-keygen.exe -lf "%PROGRAMDATA%\FabricLens\known_hosts"
```

**Jamais** `StrictHostKeyChecking=no` ni `UserKnownHostsFile=NUL` — c'est un transfert non authentifié.

### 3.5 Conversion de clés

```bat
puttygen.exe -t ed25519 -C "fabriclens@ws01" -o backup.ppk
puttygen.exe backup.ppk -O public-openssh -o id_ed25519.pub    :: -> authorized_keys RHEL
puttygen.exe backup.ppk -O private-openssh-new -o id_ed25519   :: -> pour ssh.exe natif
puttygen.exe -E sha256 -O fingerprint backup.ppk
```

### 3.6 Credentials — ordre de préférence

1. **Attended (l'utilisateur lance l'app)** — clé ed25519 **avec** passphrase dans Pageant. Zéro secret dans le code ou la config.
2. **Unattended réel (tâche planifiée, personne connecté)** — Pageant est inaccessible. Clé sans passphrase, protégée par ACL NTFS **et** par restriction côté serveur :
   ```
   icacls "%PROGRAMDATA%\FabricLens\backup_key" /inheritance:r /grant:r "DOMAIN\svc_fabriclens:(R)" /grant:r "BUILTIN\Administrators:(F)"
   ```
   ```
   # ~backupuser/.ssh/authorized_keys sur le RHEL
   from="10.1.2.3",restrict,command="/usr/local/bin/aci-backup-fetch" ssh-ed25519 AAAA... fabriclens@ws01
   ```
3. **Mot de passe** uniquement si l'auth par clé est refusée : `keyring` (WinVaultKeyring → Credential Manager → DPAPI). Épingler la version et **tester le build gelé** (bugs connus PyInstaller #439, set_password #545).

**Anti-patterns rejetés explicitement** : `-pw` (la ligne de commande Windows est lisible via Task Manager, `Get-CimInstance Win32_Process`, Sysmon EID 1, et le secret finit en clair dans le .bat sur disque) ; `-pwfile` sans ACL.

---

## 4. Stockage et indexation

### 4.1 Décisions

| Décision | Choix | Raison mesurée |
|---|---|---|
| Parseur JSON | **`json` stdlib** | orjson = +20 % de vitesse mais **×1,7 de pic RSS** (698 Mo vs 409 Mo sur 171 k MO) |
| Base | **`sqlite3` stdlib** | DuckDB ajoute **54,5 Mo** de binaire natif au bundle PyInstaller + crash connu onefile Windows (duckdb#21602) ; la charge est point-lookup + containment + traversée 7 sauts, pas de l'agrégation colonne |
| Pickle / in-memory | **rejeté** | pas d'incrémental, coût RAM complet à chaque lancement, format d'exécution de code arbitraire |
| Ingestion | streaming `tarfile` membre par membre | pic RAM gouverné par le plus gros shard, pas par le total |

**Règle d'architecture, en une ligne : on paye tout à l'ingestion (~53 s pour 20 fabrics / 3,4 M MO, ~2 s pour un fabric modifié), pour que toute requête soit un accès index.** Corollaire dur : **toute valeur cherchable doit avoir sa colonne typée**. `json_extract` sur toute la table = **780 ms chaud / 1 248 ms froid** — hors budget. Le champ `attrs` sert à l'**affichage** d'un MO déjà localisé, jamais à le trouver.

### 4.2 Pragmas de connexion

```sql
PRAGMA journal_mode = WAL;        -- une fois, à la création
PRAGMA page_size    = 8192;       -- avant la première écriture uniquement
PRAGMA synchronous  = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA cache_size   = -262144;    -- 256 Mo
PRAGMA mmap_size    = 1073741824; -- 1 Go ; REFUSER de démarrer si la DB est sur un chemin UNC (WAL+mmap sur SMB = corruption)
PRAGMA temp_store   = MEMORY;
```

Emplacement : `%LOCALAPPDATA%\FabricLens\lens.db`. **Jamais** à côté de l'exe ni dans `sys._MEIPASS` (effacé à la sortie en onefile). UI en `sqlite3.connect('file:...?mode=ro', uri=True)`, ingestion sur une connexion séparée → WAL laisse l'UI interroger pendant une ré-ingestion.

### 4.3 DDL

```sql
-- ---------- comptabilité d'ingestion ----------
CREATE TABLE fabric (
  fabric_id    INTEGER PRIMARY KEY,
  name         TEXT NOT NULL UNIQUE,      -- 'DC-PARIS-01'
  site         TEXT,
  src_path     TEXT    NOT NULL,
  src_size     INTEGER NOT NULL,
  src_mtime_ns INTEGER NOT NULL,          -- ns entier, pas float (granularité 2 s sur FAT/SMB)
  src_sha256   TEXT    NOT NULL,
  apic_version TEXT,
  backup_ts    TEXT,
  ingested_at  TEXT    NOT NULL,
  mo_count     INTEGER NOT NULL,
  schema_ver   INTEGER NOT NULL
);

CREATE TABLE shard (                       -- hash par membre -> rebuild partiel
  fabric_id INTEGER NOT NULL REFERENCES fabric ON DELETE CASCADE,
  member    TEXT    NOT NULL,
  sha256    TEXT    NOT NULL,
  mo_count  INTEGER NOT NULL,
  PRIMARY KEY (fabric_id, member)
) WITHOUT ROWID;

-- ---------- dictionnaire de DN ----------
CREATE TABLE dn (
  dn_id INTEGER PRIMARY KEY,
  dn    TEXT NOT NULL UNIQUE              -- l'index UNIQUE est le point d'entrée cross-fabric
);

-- ---------- MIT aplatie ----------
CREATE TABLE mo (
  id        INTEGER PRIMARY KEY,           -- (fabric_id << 40) | seq
  fabric_id INTEGER NOT NULL REFERENCES fabric ON DELETE CASCADE,
  dn_id     INTEGER NOT NULL REFERENCES dn,
  parent_id INTEGER REFERENCES mo,
  cls       TEXT NOT NULL,                 -- 'fvAEPg'
  name      TEXT,
  tenant    TEXT,                          -- dénormalisé, NULL hors uni/tn-*
  digest    INTEGER NOT NULL,              -- hash des attrs canonicalisés -> diff cross-fabric sans lire le JSON
  attrs     TEXT NOT NULL                  -- JSON, défauts et chaînes vides retirés (~94 o en moyenne)
);
CREATE UNIQUE INDEX mo_fab_dn  ON mo(fabric_id, dn_id);
CREATE INDEX        mo_dn_fab  ON mo(dn_id, fabric_id);      -- "ce DN existe dans quels fabrics"
CREATE INDEX        mo_cls_fab ON mo(cls, fabric_id, id);
CREATE INDEX        mo_parent  ON mo(parent_id, cls);
CREATE INDEX        mo_name    ON mo(cls, name, fabric_id);
CREATE INDEX        mo_tenant  ON mo(fabric_id, tenant, cls);

-- ---------- relations résolues (fvRs*, infraRs*, l3extRs*, vzRs*, mgmtRs*) ----------
CREATE TABLE rel (
  fabric_id  INTEGER NOT NULL,
  src_id     INTEGER NOT NULL,   -- mo.id du PROPRIÉTAIRE (parent du MO fvRsXxx)
  rel_cls    TEXT    NOT NULL,   -- 'fvRsBd'
  rs_mo_id   INTEGER NOT NULL,   -- le MO fvRsXxx lui-même (pour ses propres attributs: encap, mode…)
  tgt_dn_id  INTEGER,            -- DN cible résolu
  tgt_id     INTEGER,            -- mo.id dans le MÊME fabric ; NULL => relation pendante
  resolution TEXT NOT NULL       -- 'tdn' | 'name-local' | 'name-common' | 'dangling'
);
CREATE INDEX rel_src ON rel(src_id, rel_cls);
CREATE INDEX rel_tgt ON rel(tgt_id, rel_cls);   -- inverse : qui pointe vers moi

-- ---------- facette VLAN / encap ----------
CREATE TABLE encap (
  mo_id     INTEGER NOT NULL,
  fabric_id INTEGER NOT NULL,
  kind      TEXT    NOT NULL,   -- 'vlan' | 'vxlan'
  lo        INTEGER NOT NULL,
  hi        INTEGER NOT NULL,   -- lo = hi pour un encap unique
  role      TEXT    NOT NULL    -- 'pool-block'|'domain'|'static-path'|'epg'|'aep-funcToEpg'|'l3out-path'
);
CREATE INDEX encap_fab ON encap(fabric_id, lo);
CREATE VIRTUAL TABLE encap_rt USING rtree_i32(mo_id, lo, hi);

-- ---------- facette IP ----------
CREATE TABLE ipnet (
  mo_id     INTEGER NOT NULL,
  fabric_id INTEGER NOT NULL,
  ver       INTEGER NOT NULL,   -- 4 | 6
  plen      INTEGER NOT NULL,
  lo        BLOB    NOT NULL,   -- 16 octets big-endian, adresse réseau
  hi        BLOB    NOT NULL,   -- 16 octets big-endian, dernière adresse
  txt       TEXT    NOT NULL,   -- '10.21.10.1/24' tel qu'écrit par l'APIC
  role      TEXT    NOT NULL    -- 'bd-subnet'|'epg-subnet'|'l3ext-subnet'|'l3-if'|'rtr-id'
);
CREATE INDEX ipnet_lo  ON ipnet(lo, hi);
CREATE INDEX ipnet_fab ON ipnet(fabric_id, lo);
```

**`rtree_i32`, jamais `rtree` nu** : le `rtree` standard stocke les coordonnées en **flottants 32 bits** et perd silencieusement la précision au-delà de 2²⁴ — fatal pour des entiers IPv4. Colonnes `rtree_i32` = int32 signés → décaler IPv4 de −2³¹ (transformation qui préserve l'ordre) si l'on veut aussi un rtree IP.

Mesure : sur 963 600 lignes `encap`, un B-tree `(lo,hi)` donne **15,18 ms** ; `rtree_i32` donne **0,044 ms** — ×345. Raison : `lo<=v AND hi>=v` dégénère en scan de la moitié de l'index (`SEARCH … USING INDEX encap_lo (lo<?)`), et l'astuce `lo BETWEEN v-4096 AND v` n'aide pas puisque les VLAN commencent à 1. Coût : 1,9 s de build, +40 Mo.

Pour l'IP, le B-tree suffit (**0,12 ms** à 128 k lignes) — le rtree IPv4 est optionnel.

### 4.4 Clé IP unifiée v4/v6

```python
import ipaddress
V4OFF = 0xffff00000000                      # ::ffff:0:0/96

def key(a):                                  # IPv4Address | IPv6Address -> 16 octets
    n = int(a)
    return ((V4OFF + n) if a.version == 4 else n).to_bytes(16, 'big')

net = ipaddress.ip_network(txt, strict=False)   # fvSubnet.ip est une adresse HÔTE
lo, hi = key(net.network_address), key(net.broadcast_address)
```

SQLite compare les BLOB par `memcmp` → l'ordre et les plages sont exacts sans collation custom. Envelopper dans `try/except ValueError` : certains attributs `ip` ACI portent des placeholders `0.0.0.0` ou des DN.

### 4.5 Patterns de requête

```sql
-- (A) Recherche VLAN : quels fabrics utilisent le VLAN 2110, et à quel titre   [0,044 ms chaud]
SELECT f.name, m.cls, e.role, d.dn, e.lo, e.hi
FROM encap_rt r
JOIN encap  e ON e.mo_id = r.mo_id
JOIN mo     m ON m.id    = r.mo_id
JOIN dn     d ON d.dn_id = m.dn_id
JOIN fabric f ON f.fabric_id = m.fabric_id
WHERE r.lo <= 2110 AND r.hi >= 2110
ORDER BY f.name, e.role;

-- (B) Subnet : correspondance exacte                                          [0,017 ms chaud]
SELECT i.fabric_id, i.txt, i.role, d.dn
FROM ipnet i JOIN mo m ON m.id = i.mo_id JOIN dn d ON d.dn_id = m.dn_id
WHERE i.lo = :lo AND i.hi = :hi;

-- (C) Containment "qui couvre cette adresse / ce préfixe"                     [0,12–0,14 ms]
SELECT i.fabric_id, i.txt, i.role, d.dn
FROM ipnet i JOIN mo m ON m.id = i.mo_id JOIN dn d ON d.dn_id = m.dn_id
WHERE i.lo <= :addr AND i.hi >= :addr;

-- (D) Containment inverse "qu'y a-t-il DANS ce /24" (direction rapide, pur B-tree)
SELECT i.fabric_id, i.txt, i.role, d.dn
FROM ipnet i JOIN mo m ON m.id = i.mo_id JOIN dn d ON d.dn_id = m.dn_id
WHERE i.lo >= :lo AND i.lo <= :hi;

-- (E) Chevauchement de plages (détection de recouvrement de pools / subnets)
--     encap :  WHERE r.lo <= :hi AND r.hi >= :lo
--     ip    :  WHERE i.lo <= :hi AND i.hi >= :lo

-- (F) Chaîne de politiques complète depuis un EPG, 7+ sauts                    [0,011 ms chaud]
WITH RECURSIVE seed AS (
  SELECT m.id FROM mo m JOIN dn d ON d.dn_id = m.dn_id
  WHERE m.fabric_id = :fid AND d.dn = :epg_dn),
chain(id, depth) AS (
  SELECT id, 0 FROM seed
  UNION
  SELECT r.tgt_id, c.depth+1 FROM chain c JOIN rel r ON r.src_id = c.id
    WHERE r.tgt_id IS NOT NULL AND c.depth < 10
  UNION
  SELECT m.parent_id, c.depth+1 FROM chain c JOIN mo m ON m.id = c.id
    WHERE m.parent_id IS NOT NULL AND c.depth < 10)
SELECT m.id, m.cls, d.dn, m.attrs
FROM chain c JOIN mo m ON m.id = c.id JOIN dn d ON d.dn_id = m.dn_id;

-- (G) Comparaison cross-fabric : objet présent ici, absent là
SELECT d.dn, group_concat(f.name), count(*) n
FROM mo m JOIN dn d ON d.dn_id = m.dn_id JOIN fabric f ON f.fabric_id = m.fabric_id
WHERE m.cls = 'fvBD'
GROUP BY m.dn_id HAVING n < (SELECT count(*) FROM fabric);

-- (H) Dérive d'attributs, sans toucher au JSON (index-ordonné sur mo_dn_fab)
SELECT d.dn FROM mo m JOIN dn d ON d.dn_id = m.dn_id
WHERE m.cls = 'fvBD' GROUP BY m.dn_id HAVING count(DISTINCT m.digest) > 1;

-- (I) Anomalies : relations pendantes = misconfigurations réelles à afficher
SELECT f.name, d.dn AS owner, r.rel_cls
FROM rel r JOIN mo m ON m.id = r.src_id JOIN dn d ON d.dn_id = m.dn_id
JOIN fabric f ON f.fabric_id = r.fabric_id
WHERE r.tgt_id IS NULL;
```

### 4.6 Ingestion et ré-ingestion incrémentale

Deux passes, par fabric :
1. **Aplatissement** — streaming des membres du tar, reconstruction des DN (§1.4), insertion `executemany` dans `mo`/`encap`/`ipnet`, collecte des MO `*Rs*` et d'un dict Python `{dn: mo_id}` local au fabric.
2. **Résolution des arêtes** — deux familles séparées :
   - `tDn` explicite (`fvRsPathAtt`, `fvRsDomAtt`, `fvRsNodeAtt`, `infraRsVlanNs`, `infraRsDomP`, `infraRsAttEntP`, `infraRsAccBaseGrp`, `infraRsAccPortP`, `infraRsFuncToEpg`, `l3extRsPathL3OutAtt`, `l3extRsNodeL3OutAtt`, `vzRsIf`) → lookup direct dans le dict.
   - `tnXxxName` → composition contre le DN du tenant propriétaire, puis repli documenté sur `tn-common`. Ex. `tnFvBDName="X"` sur un EPG de `tn-PROD` → `uni/tn-PROD/BD-X`, puis `uni/tn-common/BD-X`.
   `tgt_id = NULL` + `resolution='dangling'` → **remonté comme constat dans l'UI**, jamais avalé.

Détection de changement : `(src_size, src_mtime_ns)` en fast-path, puis confirmation `sha256` (**0,08 s pour 168 Mo** avec `hashlib.file_digest`, moins cher que blake2b à 0,14 s et md5 à 0,28 s grâce aux extensions SHA matérielles).

Ré-ingestion : un seul `BEGIN IMMEDIATE`, `DELETE FROM fabric WHERE fabric_id=:fid` (CASCADE emporte `mo`, `shard`), suppression explicite des tables de facettes (non FK pour la vitesse d'insertion), puis rechargement. **~2 s bout en bout** pour un fabric de 171 k MO. Terminer par `PRAGMA optimize` (pas `ANALYZE` complet) ; `VACUUM` uniquement sur action utilisateur explicite.

### 4.7 Dimensionnement

- Coût mémoire d'un arbre JSON parsé : **~1,35 ko de Python par MO** — c'est le chiffre stable. En multiplicateur : ×1,4 sur un fichier *pretty-printed* (les exports APIC sont indentés, ~2/3 de blancs), ×4,2 sur du JSON compact.
- Coût disque SQLite : **~480 octets par MO**, index compris. 20 fabrics × 171 k MO = 3,42 M MO → **1,64 Go**.
- Répartition dbstat (build 366 Mo) : table `mo` 40,6 %, `mo(fabric_id,dn)` 54,2 Mo, `mo(dn)` 52,8 Mo, `rel` 25,6 Mo. **Les index de DN coûtent plus que la table** → l'interning des DN (`dn_id INTEGER`) est le premier levier de réduction, et rend surtout les requêtes cross-fabric ordonnées par index. ⚠ Le gain en taille n'a pas été mesuré honnêtement (corpus synthétique à 20 fabrics identiques) ; le gain sur la *forme* des requêtes, lui, est certain.
- **FTS5 : à ne pas embarquer en v1.** Coût +31 % de base (+113 Mo) et 3,1 s de build ; surtout, `MATCH '"vlan-2110"'` et `MATCH '"10.21.10.0/24"'` renvoient **0 ligne** là où les facettes typées renvoient les 20 fabrics corrects — exactement le mode d'échec à ne pas livrer. Si le besoin de recherche libre (« trouve l'objet nommé WebServers ») apparaît, l'ajouter en `content=''` + `contentledelete=1` avec `rowid = mo.id`, réservé aux noms/descriptions.

### 4.8 Démarrage à froid

Première requête sur une base de 1,64 Go : jusqu'à **26 ms** en cache froid dans les mesures, pire sur disque mécanique. Pré-chauffer en tâche de fond pendant l'animation d'intro (2,85 s disponibles selon le design-spec) : `SELECT count(*) FROM encap; SELECT count(*) FROM ipnet;`

---

## 5. Packaging Windows

### Recommandation

**FastAPI sur `127.0.0.1` (port aléatoire + jeton par lancement) rendu dans une fenêtre pywebview/WebView2, gelé avec `pyinstaller --onedir --noupx --windowed`, signé Authenticode, enveloppé dans un installeur Inno Setup par-utilisateur.** Aucun droit administrateur à aucune étape.

### Raisons

**`--onedir`, pas `--onefile`** — les deux problèmes de `--onefile` sont les mêmes que sa cause : il s'auto-extrait dans `%TEMP%\_MEIxxxxxx` et exécute depuis là, ce qui est **littéralement le comportement packer/dropper** que Defender et les EDR heuristiques signalent, et coûte **1 à 4 s d'extraction à chaque lancement** (pire avec un antivirus temps réel sur le dossier temp). `--onedir` coûte ~0,2–0,5 s de plus que Python nu. Pour une app relancée plusieurs fois par jour, cet écart *est* l'UX.

Mitigations antivirus par ordre d'efficacité : (1) `--onedir`, (2) `--noupx`, (3) **signature Authenticode OV ou EV** — les éditeurs AV whitelistent le certificat, pas le hash, donc c'est la seule mesure qui survit à chaque rebuild, (4) soumission au portail Microsoft Security Intelligence, (5) recompilation du bootloader PyInstaller depuis les sources, (6) bascule vers Nuitka.

**WebView2 plutôt que le navigateur par défaut** — Microsoft indique que le runtime Evergreen est préinstallé sur **tout Windows 11** et sur « la grande majorité » des Windows 10. Le combler ne demande **pas d'admin** : le bootstrapper `MicrosoftEdgeWebview2Setup.exe` (~2 Mo) installe en mode par-utilisateur. Détection : clé `HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}\pv` (ou l'équivalent HKCU).
**Attention** : l'ordre de backends pywebview sur Windows est `edgechromium` puis `mshtml` — `mshtml` est le moteur IE11 et ne rendra pas une UI CSS/JS moderne. **Traiter « pas de WebView2 » comme un échec dur**, pas comme une dégradation gracieuse → prévoir un flag `--browser` qui bascule sur `webbrowser.open`.

**Pièges du serveur local** : (1) certains PAC/WPAD d'entreprise routent `127.0.0.1` par le proxy → poser `NO_PROXY=127.0.0.1,localhost` et préférer `127.0.0.1` à `localhost` ; (2) bind loopback uniquement + jeton aléatoire par lancement, sinon n'importe quel processus local pilote le backend ; (3) heartbeat `/shutdown` pour ne pas orphaniser le serveur si l'utilisateur ferme l'onglet ; (4) bon point : le pare-feu Windows ne prompte pas sur un bind loopback.

Build de référence :

```bat
pyinstaller --noconfirm --clean --onedir --windowed --noupx ^
  --name FabricLens --icon app.ico ^
  --add-data "web;web" ^
  --add-data "bin;bin" ^
  --collect-all webview ^
  --hidden-import uvicorn.logging --hidden-import uvicorn.loops.auto ^
  --hidden-import uvicorn.protocols.http.auto --hidden-import uvicorn.lifespan.on ^
  app.py
```

Séparateur `--add-data` sous Windows = **`;`**, pas `:`. Résoudre les assets via `sys._MEIPASS` / `os.path.dirname(sys.executable)`. Passer l'objet app à uvicorn, pas une chaîne d'import. Inno Setup : `PrivilegesRequired=lowest`, `DefaultDirName={localappdata}\FabricLens`.

### Rejetés

- **Electron** : ~120–180 Mo, et il faudrait *quand même* embarquer CPython → deux runtimes.
- **Tauri v2** : installeurs 3–10 Mo, mais exige la toolchain Rust **et** un backend Python gelé en sidecar → tous les problèmes PyInstaller **plus** une seconde toolchain. Justifié seulement si l'on a déjà besoin de Rust/Node ou d'une infra d'auto-update.

---

## 6. Prior art

### Ce qu'on réutilise

| Source | Licence | Ce qu'on prend |
|---|---|---|
| **`fl_extract.py` (ce dépôt)** | interne | La table `RN_TEMPLATES` (~110 classes, dérivée de vrais DN APIC, round-trip 467/467) et `ROOT_PARENT`. **Actif le plus précieux du projet.** Corriger le repli `dn = parent_dn` de `flatten_mo()`. |
| **ACI Pre-Upgrade Validation Script** — `datacenter/ACI-Pre-Upgrade-Validation-Script` | **Apache-2.0**, v4.1.1 (juin 2026), maintenu | Vendorer `AciObjectCrawler` (ligne 508) et `AciAccessPolicyParser` (ligne 601, ~312 lignes). `AciObjectCrawler.__init__(mos)` ne prend **qu'une liste plate de dicts imdata** — aucune session, aucun réseau : adapter un export aplati = ~50 lignes. `AciAccessPolicyParser` produit exactement les deux dicts dont l'UI a besoin : `port_data` clé `<node>/eth<card>/<port>` → `{ifpg, override_ifpg, pc_type, aep, domain_dns, vlan_scope, node, fex, port}`, et `vpool_per_dom` → `{name, vlan_ids (liste d'ints), dom_name, dom_type}`. Gère **FEX HIF/NIF et les IPG overrides** — les deux choses que tout le monde rate. Dépendances : `six` + stdlib. |
| Idem — les 92 fonctions `*_check` | Apache-2.0 | Catalogue de règles. Ne garder que le sous-ensemble **dérivé de la config** : `overlapping_vlan_pools_check`, `internal_vlanpool_check`, `access_untagged_check`, `port_configured_as_l2/l3_check`, `encap_already_in_use_check`. La moitié des checks interrogent `faultInst` → **irreproductibles offline**. |
| **`brightpuddle/goaci` / `requery`** | Apache-2.0 (archivé) | Référence de *design* : « le tar.gz comme base interrogeable ». Table `backup/rns.go` en secours si `RN_TEMPLATES` s'avère incomplète. |
| **netascode ACI YAML data model** (`netascode/terraform-aci-nac-aci`) | Apache-2.0, actif (07/2026) | À adopter comme **schéma de sortie** optionnel : maintenu par Cisco, couvre déjà les access policies → l'outil devient aussi une rampe brownfield→IaC. |
| **`cisco-pyaci`** (PyPI, Apache-2.0, avril 2026) | optionnel | `Backup(backupFile).load()` = parsing offline pur. ⚠ Bloqueur : exige un `aci-meta.json` **générable uniquement sur un APIC** (`scripts/rmetagen.py`) ; le meta livré (`aci-meta.limited.json`, 18 ko) ne couvre que 11 classes tenant — **inutilisable pour les access policies**. Dépendances lourdes (Flask, paramiko, lxml, pyopenssl). → **extra optionnel, pas socle**. |

⚠ Correction obligatoire lors du portage du `AciAccessPolicyParser` : il s'appuie sur `fvnsRtVlanNs` et `l2RtL2IfPol`, deux **relations inverses générées par l'APIC, absentes de tout export**. Les remplacer par les marches forward — domaine → `infraRsVlanNs.tDn` → `fvnsVlanInstP`, et IPG → `infraRsL2IfPol.tnL2IfPolName` → `l2IfPol` — via le helper `get_src_from_tDn()` déjà présent dans `AciObjectCrawler`. Correction petite et localisée.

### Ce qu'on écarte

| Projet | Raison |
|---|---|
| **acitoolkit** | **Repo archivé le 23/01/2026**. Son mode offline `FakeSession` appelle `iteritems()` (Python 2) aux lignes 171/203/228/288 de `acifakeapic.py` → `AttributeError` sur Py3. PyPI figé à 0.4 (2017). À miner pour les idées (la liste de checks d'`acilint`, l'UX `--snapshotfiles`), pas comme dépendance. |
| **acicobra / acimodel** | **Absents de PyPI** (404). Distribution uniquement depuis un APIC physique. Repo `datacenter/cobra` : dernier push 07/2020, 44 issues ouvertes. Le modèle de distribution le tue comme dépendance redistribuable. |
| **`agccie/aci-contract-parser`** | **Aucun fichier LICENSE** → tous droits réservés, juridiquement inutilisable. Dernier push 2018. Bon précédent d'UX (`--offline bundle.tgz`, `--offlineHelp` listant les endpoints requis) — à imiter, pas à importer. |
| **ACEye**, **ACI-Kubernetes-Visualiser** | **GPL-3.0** → contamination virale d'un livrable permissif. Références visuelles utiles (templates Jinja pour 200+ classes ; graphe-dans-le-navigateur) sous réserve d'arbitrage licence. |
| **ansible `cisco.aci`**, **terraform-provider-aci**, **nac-collector** | 100 % live-APIC (appels HTTP), aucun mode fichier local. |
| **pyATS / Genie** | Aucun parseur de MO ACI ; `os: apic` = plomberie de connexion/clean uniquement. |
| **DuckDB** | Cf. §4.1. |

### Ce qu'on construit

**La visualisation de la chaîne d'access policies n'existe nulle part en open source.** Prior art le plus proche : `aci-diagram` (GraphViz, 2015, sans licence, modèle **logique** uniquement, APIC live), `fabrik` (React Flow + Neo4j, live APIC), `vkaci` (graphe-dans-navigateur, GPL). Toute chaîne VLAN pool → domaine → AAEP → IPG → port trouvée dans la nature est un **PNG dessiné à la main sur un blog**.

Cisco a d'ailleurs validé le workflow « collecter un bundle, analyser hors-boîte » avec **ACI vetR** : le collecteur est open (`cisco-open/aci-collector`, Apache-2.0, actif 07/2026), **le moteur d'analyse est resté propriétaire**. Nexus Dashboard Insights (Delta Analysis, Pre-Change Analysis, Compliance) couvre le besoin — mais exige un cluster ND avec télémétrie live et une licence. **La niche « analyse offline d'un export détenu par le client » est ouverte.**

À construire, donc : le lecteur tar.gz/JSON+XML, le reconstructeur de DN, le resolver de graphe à deux passes, le schéma SQLite, la recherche VLAN/subnet/IP, la comparaison cross-fabric, et l'UI.

---

## 7. Risques et inconnues

### 7.1 Bloquants — à confirmer sur un backup réel du client AVANT d'écrire le resolver

| # | Question | Comment trancher | Impact si l'hypothèse est fausse |
|---|---|---|---|
| R1 | **Les MO enfants portent-ils `dn`, `rn`, ou rien ?** Contradiction directe entre l'export GitHub / la note APIC 6.0(7e) de `fl_extract.py` (rien) et la sémantique DME documentée (au moins `rn`). | Extraire un backup, `grep -c 'dn=""'` et `grep -c ' rn="'` sur le membre `_1`. Instrumenter les 4 branches du repli et logger les compteurs au premier run. | Si `rn` est présent, la table `RN_TEMPLATES` devient un filet de sécurité au lieu du chemin principal → risque quasi nul. Si rien n'est présent **et** qu'une classe manque à la table, **la branche entière est mal-DN'ée et tous les `tDn` la ciblant deviennent pendants**. C'est le risque n°1 du projet. |
| R2 | **Layout réel de l'archive.** Toute la preuve de layout vient d'**un seul** export ~APIC 4.2. Les releases 5.x/6.x — et APIC 6.1 avec sa nouvelle UI de backup — ont pu changer le nommage des membres, ajouter un manifeste, ou splitter le fichier de config en `_1`, `_2`… | `tar tzf` un backup réel et differ contre la liste de 35 fichiers du §1.2. | Un split `_N` non géré = perte silencieuse d'une partie de l'univers de politiques. |
| R3 | **XML ou JSON ?** `configExportP.format` est un choix local du client. | Regarder l'extension des membres. | Le parseur doit gérer **les deux** ; filtrer sur `.json` (bug goaci) rend un backup XML invisible. |
| R4 | **Version(s) d'APIC des 20 fabrics.** Le gros des citations MIM vient de 4.2(1). Varient par release : constantes `l3extSubnet.aggregate`, sélecteurs ESG (`fvEPgSelector` 5.2+), `fvBD.ipLearning`/`vmac`, `vzEntry.matchDscp`, `infraAccBndlPolGrp`. | `dhcpconfig/*_255_idfile.xml` porte `runningVer` par switch ; croiser avec l'inventaire. | Attributs manquants → `KeyError` ; classes inconnues → RN manquant → R1. Hétérogénéité entre fabrics = comparaison cross-fabric bruitée. |
| R5 | **`fabricLagId` est-il présent dans l'export ?** Le MIM dit que la classe existe et joint IPG↔protection group, mais son `id` est *implicit* et l'objet est créé au déploiement. | `grep -c fabricLagId` sur le membre `_1`. | Présent → jointure vPC explicite, code simple. Absent → inférence en 4 étapes (§2.1), plus fragile, à documenter dans l'UI comme *déduit*. |
| R6 | **Périmètre : FEX, breakout, spines ?** Les DN FEX (`infraFexP`, `infraFexBndlGrp`, `infraRsAccBaseGrp.fexId`, `infraSubPortBlk`) et spine (`infraSpineP`, `infraSpineS`, `infraSpAccPortP`, `infraSHPortS`, `infraSpAccPortGrp`, `infraRsSpAccPortP`) sont documentés par symétrie mais **non vérifiés page par page dans le MIM**. | Compter ces classes dans les backups réels. | Si présents et non gérés : trous silencieux dans `port_data`. `AciAccessPolicyParser` gère déjà FEX HIF/NIF — argument de plus pour le vendorer. |
| R7 | **Domaines VMM en périmètre ?** `vmmDomP` peut porter `fvnsEncapBlk` **en enfant direct** *en plus* de `infraRsVlanNs`. | Chercher `fvnsEncapBlk` sous `uni/vmmp-*/dom-*`. | Sources d'encap non fusionnées → VLAN manquants dans la recherche. |
| R8 | **FC/FCoE ?** Même patron structurel, classes distinctes : `fvnsVsanInstP` (`uni/infra/vsanns-[{name}]-{allocMode}`), `infraRsVsanNs`, `fvnsVsanEncapBlk`, `fcDomP`. | Compter `fcDomP` / `fvnsVsanInstP`. | Classes à enregistrer séparément dans le resolver. |

### 7.2 Inconnues secondaires

| # | Question | Note |
|---|---|---|
| R9 | **Exports partiels** (`targetDn="uni/tn-X"`). Trois `configExportP` coexistaient dans l'export réel, dont un scopé tenant. Embarquent-ils quand même les 32 `idconfig` ? Aucun exemple réel obtenu. | Le champ « root DN » de `configSnapshot` existe précisément pour enregistrer le scope. Si les entrées client sont des exports partiels, `uni/infra` (donc **toutes** les access policies) est absent. |
| R10 | **Représentation d'une propriété AES-chiffrée dans l'archive** (blob base64 ? attribut supplémentaire ? IV par propriété ?). Aucun échantillon chiffré trouvé. | Sans impact sur les requêtes de politique ; impact sur un futur diff. |
| R11 | **Pretty-printed ou compact ?** Le multiplicateur RAM va de ×1,4 à ×4,2, et le nombre de MO d'un « fichier de 200 Mo » varie de 200 k à 600 k. | `head -c 200` sur un export réel tranche en 10 s. Toutes les mesures de dimensionnement du §4.7 en dépendent. |
| R12 | **20 fabrics = 1,64 Go de SQLite. Acceptable sur le poste cible ?** | Leviers, par ordre de rendement : interning des DN, suppression de `mo_tenant`/`mo_parent` si l'UI ne s'en sert pas, stripping d'attributs plus agressif, compression zstd de `attrs` (>5 Go seulement). Décider **avant** d'écrire l'ingestion. |
| R13 | **IPv6 en périmètre ?** | Le BLOB 16 octets ne coûte rien de plus, mais si c'est IPv4 pur, des `INTEGER lo/hi` + `rtree_i32` sont plus simples à débugger. |
| R14 | **Recherche libre nécessaire ?** Le design-spec affiche « VLAN · subnet · IP », ce qui permettrait de supprimer FTS5 (−31 % de base). | Confirmer avec l'utilisateur. |
| R15 | **Ingestion en tâche de fond pendant que l'UI est ouverte ?** | Hypothèse retenue : oui (WAL + connexion read-only séparée). Sinon le setup se simplifie. |
| R16 | **Bastion et/ou proxy HTTP CONNECT entre le poste et le RHEL ?** | Branche la plus structurante du §3 : bastion → `ssh -J` ou `fabric` `gateway=` ; proxy HTTP/SOCKS → **PuTTY obligatoire** (paramiko n'a aucun support proxy). |
| R17 | **Le .bat tourne-t-il avec une session interactive ouverte, ou en tâche planifiée sans session ?** | Pageant est inaccessible sans session → force le patron clé-sans-passphrase + restriction serveur. |
| R18 | **L'auth par clé publique est-elle autorisée par la politique, ou Kerberos/GSSAPI imposé ?** | En GSSAPI, la voie pratique est PuTTY et toute la discussion de gestion de clés devient sans objet. |
| R19 | **Certificat de signature de code (OV/EV) disponible ?** | Sans lui, friction Defender/SmartScreen **à chaque rebuild** + boucle de soumission de faux positif à Microsoft. |
| R20 | **Parc : Windows 11 pur, ou queue Windows 10 ?** | Décide s'il faut embarquer le bootstrapper WebView2 Evergreen (~2 Mo). |
| R21 | **Arbitrage design-spec.** Les lignes 84-89 de `docs/design-spec.md` annoncent « 42 endpoints actifs » et « Dernier sync APIC » — données opérationnelles (`fvCEp`, `faultInst`) **absentes d'un export de config**. | Trancher maintenant. Si une source APIC live est ajoutée plus tard, elle nécessite ses propres tables + une colonne de fraîcheur — réserver la place dans le schéma plutôt que de rétrofitter. |

### 7.3 Ordre de construction imposé par ces risques

**La phase 1 n'est pas la base de données : c'est le reconstructeur de DN + la table de RN.** Rien d'autre ne fonctionne tant que les DN des enfants ne sont pas exacts, et chaque enfant d'un export réel a `dn=""`. Livrable de phase 1 : un test de fixture qui charge le membre `_1` d'un backup client réel, reconstruit tous les DN, et **assert : 0 MO en branche de repli non résolue, 0 relation `tDn` pendante hors misconfigurations connues**. Les compteurs par branche de résolution doivent être affichés à chaque ingestion, pas seulement en test.