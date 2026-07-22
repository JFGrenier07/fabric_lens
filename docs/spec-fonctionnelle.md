# Fabric Lens — spécification fonctionnelle

> Modèle d'objets **validé le 2026-07-20 contre un vrai APIC 6.0(7e)** (simulateur du lab).
> Les noms de classes et d'attributs ci-dessous sont copiés de réponses API réelles,
> pas de la documentation. ✅ = confirmé sur données réelles.

---

## 1. Recherche VLAN

**Entrée** : un identifiant de VLAN (`2110`, `vlan-2110`).

**Sortie** : la liste des fabrics où ce VLAN existe, et pour chaque fabric l'état exact :

| État | Ce que ça veut dire |
| --- | --- |
| *Déployé* | le VLAN est dans un pool **et** utilisé comme `encap` par un EPG |
| *Dans un pool, non déployé* | présent dans un `fvnsEncapBlk`, aucun EPG ne l'utilise |
| *Absent* | aucun pool ne le couvre |

Au clic sur un fabric, on déroule les deux chaînes, **remontées depuis l'encap block** :

### Chaîne access policies ✅

| # | Classe | DN observé | Attribut de liaison | Pointe vers |
| --- | --- | --- | --- | --- |
| 1 | `fvnsEncapBlk` | `uni/infra/vlanns-[Prod_VLAN_Pool]-static/from-[vlan-2000]-to-[vlan-2199]` | `from`, `to`, `allocMode`, `role` | son parent (le pool) |
| 2 | `fvnsVlanInstP` | `uni/infra/vlanns-[Prod_VLAN_Pool]-static` | `name`, `allocMode` | — |
| 3 | `infraRsVlanNs` | `uni/phys-Prod_PhysDomain/rsvlanNs` | `tDn` → le pool, `tCl` | remonte au **domaine** |
| 4 | `physDomP` / `l3extDomP` / `vmmDomP` | `uni/phys-Prod_PhysDomain`, `uni/l3dom-Test_L3DOM_Standard` | — | — |
| 5 | `infraRsDomP` | `uni/infra/attentp-SRV.AAEP/rsdomP-[uni/phys-PHY.DOM]` | `tDn` → le domaine | remonte à l'**AAEP** |
| 6 | `infraAttEntityP` | `uni/infra/attentp-SRV.AAEP` | `name` | — |
| 7 | `infraRsAttEntP` | `uni/infra/funcprof/accbundle-SRV-VPC.IPG/rsattEntP` | `tDn` → l'AAEP | remonte à l'**IPG** |
| 8 | `infraAccPortGrp` (accès) / `infraAccBndlGrp` (PC/vPC) | `uni/infra/funcprof/accbundle-SRV-VPC.IPG` | `lagT` : `node`=vPC, `link`=PC | — |
| 9 | `infraRsAccBaseGrp` | `.../hports-<sel>-typ-range/rsaccBaseGrp` | `tDn` → l'IPG | remonte au **port selector** |
| 10 | `infraHPortS` + `infraPortBlk` | `.../portblk-portblock1` | `fromCard`,`fromPort`,`toCard`,`toPort` | les **ports** |
| 11 | `infraAccPortP` | `uni/infra/accportprof-system-port-profile-node-101` | — | — |
| 12 | `infraRsAccPortP` | `uni/infra/nprof-.../rsaccPortP-[...]` | `tDn` → l'interface profile | remonte au **switch profile** |
| 13 | `infraNodeP` + `infraLeafS` + `infraNodeBlk` | `.../nodeblk-system-node-101` | `from_`, `to_` ⚠ *underscore final* | les **leaves** |

Paire vPC : `fabricExplicitGEp` (`uni/fabric/protpol/expgep-vpc_pg_pod1_101_102`) + `fabricNodePEp` ✅

### Deux modes de déploiement du VLAN — les deux doivent être supportés ✅

1. **Static port** — `fvRsPathAtt` sous l'EPG, `encap="vlan-2110"`, `tDn` de forme
   `topology/pod-1/paths-101/pathep-[eth1/15]` (accès) ou
   `topology/pod-1/protpaths-101-102/pathep-[SRV-VPC.IPG]` (vPC), `mode` ∈ `regular|native|untagged`.
2. **AAEP** — `infraRsFuncToEpg`, porte lui-même l'`encap` ✅
   DN observé : `uni/infra/attentp-EXT.AAEP/gen-default/rsfuncToEpg-[uni/tn-test-TN/ap-MIGRATION.AP/epg-V102.EPG]`
   avec `encap="vlan-102"`, `mode="regular"`, `instrImedcy="lazy"`.
   ⚠ Le segment intermédiaire est `gen-default` (`infraGeneric`) pour les AAEP utilisateur,
   mais `provacc` pour l'AAEP `default` du tenant `infra`. Le parseur doit gérer les deux.

### Chaîne logique ✅

`fvTenant` → `fvCtx` (VRF) → `fvBD` (`unicastRoute`, `arpFlood`, `unkMacUcastAct`, `mac`) →
`fvSubnet` (`ip="10.1.1.1/24"`, `scope` ∈ `private|public|shared`) ;
`fvBD` → VRF via `fvRsCtx.tnFvCtxName` ;
`fvAp` → `fvAEPg` → `fvRsBd.tnFvBDName` → BD ; `fvRsDomAtt.tDn` → domaine ;
contrats via `fvRsProv.tnVzBrCPName` / `fvRsCons.tnVzBrCPName` →
`vzBrCP` → `vzSubj` → `vzRsSubjFiltAtt` → `vzFilter` → `vzEntry`
(`etherT`, `prot`, `dFromPort`, `dToPort`).

**Chaque objet de la chaîne est sélectionnable et sa config brute est consultable** (attributs + DN).

---

## 2. Recherche subnet — l'écran signature

**Entrée** : `10.21.10.0/24`, ou une IP simple (`10.21.10.42` → on cherche le préfixe qui la contient).

Un subnet peut se trouver dans **4, 5, 6 fabrics ou plus**. Deux natures très différentes,
et l'écran doit les distinguer sans ambiguïté :

### a) Le subnet est une gateway de Bridge Domain — `fvSubnet` ✅
On affiche la même chaîne complète que pour un VLAN (BD → EPG → encap → access policies).
`scope` ∈ `private` (VRF only) · `public` (annonçable via L3Out) · `shared` (fuite inter-VRF).
Exemple réel du lab : `uni/tn-Production/BD-Web_BD/subnet-[10.1.1.1/24]` scope `public`.
⚠ `fvSubnet` peut aussi être **sous un EPG** et pas sous le BD :
`uni/tn-GOLD-BD-Test/ap-GOLD-AP/epg-GOLD-EPG-FULL/subnet-[10.50.50.1/24]` ✅ — cas à gérer.

### b) Le subnet est déclaré dans un ext-EPG de L3Out — `l3extSubnet` ✅
DN : `uni/tn-<T>/out-<L3OUT>/instP-<EXTEPG>/extsubnet-[192.0.2.0/24]`
L'attribut `scope` est une **liste séparée par des virgules** — plusieurs rôles simultanés.
Exemple réel du lab : `192.0.2.0/24` → `scope="export-rtctrl,import-security"` ✅

| Valeur `scope` | Nom dans l'IHM APIC | Nature | Sens |
| --- | --- | --- | --- |
| `import-security` | *External Subnets for the External EPG* | **Sécurité** | ce préfixe **classifie** le trafic entrant dans cet ext-EPG (c'est ce qui rend les contrats applicables) |
| `export-rtctrl` | *Advertised Externally* | **Routage** | ce préfixe est **annoncé** vers l'extérieur |
| `import-rtctrl` | *Import Route Control Subnet* | Routage | filtre ce qu'on accepte de l'extérieur |
| `shared-security` | *Shared Security Import Subnet* | Sécurité | classification inter-VRF |
| `shared-rtctrl` | *Shared Route Control Subnet* | Routage | fuite de route inter-VRF |

Attribut `aggregate` (ex. `export-rtctrl` sur `0.0.0.0/0`) = « et tous les préfixes plus spécifiques ».

**Sécurité et routage sont deux axes orthogonaux.** L'écran doit les rendre lisibles d'un
coup d'œil, sans obliger à lire une légende.

### c) Le path inter-fabric
Quand un fabric **annonce** le préfixe (`export-rtctrl`) et qu'un autre le **classifie**
(`import-security`), c'est un chemin. C'est *ça* que l'utilisateur veut voir tracé entre
les fabrics, avec pour chaque bout : nom du fabric, L3Out, ext-EPG, et les contrats
(`fvRsProv` / `fvRsCons` sous le `l3extInstP` ✅ — observé sur
`.../instP-Test_ExtEPG_Prod_Standard/rsprov-Web_to_App_Contract`).

### Cas particuliers à rendre visibles
- **Match par agrégat** — on cherche `10.21.10.0/24`, le fabric déclare `10.21.0.0/16`.
  Ce n'est pas un match exact : doit se distinguer visuellement.
- **Conflit** — même préfixe dans un autre tenant/VRF, gateway différente, VLAN réutilisé.
  Doit ressortir comme une anomalie, pas comme un résultat ordinaire.
- **Encap divergent** — même subnet, VLAN différent d'un fabric à l'autre.

---

## 3. Source des données

Backups de configuration APIC. Confirmé sur le lab ✅ :

- `configExportP` → `format="json"`, `targetDn=""` (backup complet), `snapshot="yes"`,
  `includeSecureFields="yes"`, `maxSnapshotCount="3"`
- `configSnapshot.fileName` → `ce2_DailyAutoBackup-2026-07-20T17-00-24.tar.gz`
  (préfixe `ce2_`, nom de la policy, timestamp ISO)

Donc : `.tar.gz` → JSON → arbre MIT (`polUni` + `children` imbriqués) → à aplatir.

**Ce qui n'est PAS dans un backup** : les endpoints (`fvCEp`), les faults, l'état de
déploiement réel, le compteur « 42 EP actifs » de la maquette. À retirer de l'IHM,
ou à alimenter par une connexion APIC live optionnelle.

---

## 4. Reste à confirmer avec Jean-François

- Format réel des fichiers sur le serveur RHEL (est-ce bien `ce2_*.tar.gz` ?), chemin, nommage par fabric
- Global AES Encryption activée sur les exports de production ?
- Accès SSH : clé ou mot de passe, jump host, PuTTY vs OpenSSH natif
- Python installable sur le poste Windows, ou `.exe` autonome requis ? Droits admin ?
- Historique des backups à conserver (diff dans le temps) ou dernier seulement ?
