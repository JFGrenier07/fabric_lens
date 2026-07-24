#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fl_extract.py - extracteur Fabric Lens, cote SERVEUR RHEL.

Ce script tourne SUR le serveur Red Hat qui heberge les backups APIC.
Il lit les exports de configuration (.tar.gz), aplatit l'arbre MIT, ne garde
que les classes utiles a Fabric Lens, et ecrit un fichier distille par fabric.

Pourquoi cote serveur : un export APIC complet pese des dizaines a des centaines
de Mo ; apres filtrage il en reste ~13 %, et une fois gzippe c'est negligeable.
On transfere donc des Ko au lieu de Go, et le poste Windows n'a jamais a manipuler
d'archive tar.

CONTRAINTES ASSUMEES
  - Python 3.6+ (RHEL 8 fournit 3.6, RHEL 9 fournit 3.9) - bibliotheque STANDARD
    uniquement, aucun pip install, aucun droit root necessaire.
  - Pas d'accents dans ce fichier : il transite par pscp/plink vers un shell dont
    l'encodage n'est pas garanti.

SORTIES (dans --out)
  <fabric>.fl.json.gz   un objet {meta, mos:[{c,dn,a}, ...]}
  manifest.json         empreintes des sources, pour que le poste Windows
                        sache quoi re-telecharger et quoi ignorer

La derniere ligne de stdout est un sentinelle : FL-EXTRACT-OK ou FL-EXTRACT-FAIL.
Le .bat s'appuie dessus en plus du code de retour.
"""

from __future__ import print_function

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import sys
import tarfile
import time

EXTRACTOR_VERSION = "1.2.0"

# ===========================================================================
#
#   TES FABRICS SE DECLARENT DANS LE FICHIER  fabric_path  (A COTE DE CE SCRIPT)
#
#   Une ligne par fabrique :   nom  chemin
#
#   Ce script ne contient PLUS la liste : il lit le fichier `fabric_path`
#   place dans le meme repertoire. Tu edites ce fichier-la, jamais ce script.
#   Voir fabric_path pour le format et des exemples.
#
#   (Repli : si `fabric_path` est absent, le bloc FABRICS ci-dessous est
#   utilise a la place - il est vide par defaut.)
#
# ===========================================================================

FABRICS = []      # rempli depuis le fichier fabric_path au demarrage


def load_fabric_path():
    """Lit le fichier `fabric_path` a cote du script -> [(nom, chemin), ...].

    Format, une fabrique par ligne :   nom  chemin
      - le nom ne contient pas d'espace ; le reste de la ligne est le chemin
        (un chemin peut donc contenir des espaces)
      - le separateur peut etre une virgule ou des espaces/tabulations
      - lignes vides et lignes commencant par # ignorees

    Cherche `fabric_path` puis `fabric_path.txt` (Windows ajoute parfois .txt).
    Retourne None si aucun fichier trouve (on retombe alors sur le bloc FABRICS).
    """
    here = os.path.dirname(os.path.abspath(__file__))
    for name in ("fabric_path", "fabric_path.txt"):
        path = os.path.join(here, name)
        if not os.path.isfile(path):
            continue
        out = []
        fh = open(path, "r")
        try:
            for lineno, raw in enumerate(fh, 1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if "," in line:
                    nom, chemin = line.split(",", 1)
                else:
                    parts = line.split(None, 1)
                    if len(parts) < 2:
                        sys.stderr.write("[!] fabric_path ligne %d ignoree "
                                         "(nom et chemin attendus) : %s\n"
                                         % (lineno, line))
                        continue
                    nom, chemin = parts
                nom, chemin = nom.strip(), chemin.strip().strip('"').strip("'")
                if nom and chemin:
                    out.append((nom, chemin))
        finally:
            fh.close()
        return out
    return None


_fp = load_fabric_path()
if _fp is not None:
    FABRICS = _fp

# ===========================================================================
#   Fin de la zone a editer. Le reste n'a pas besoin d'etre touche.
# ===========================================================================

# ---------------------------------------------------------------------------
# Les classes que Fabric Lens sait exploiter.
# Toutes ont ete observees sur un APIC 6.0(7e) reel, sauf mention contraire.
# Ajouter une classe ici suffit a la faire remonter jusqu'a l'interface.
# ---------------------------------------------------------------------------
KEEP_CLASSES = frozenset([
    # --- chaine access policies -------------------------------------------
    "fvnsVlanInstP", "fvnsEncapBlk", "fvnsVsanInstP",
    "physDomP", "l3extDomP", "vmmDomP", "fcDomP",
    "infraRsVlanNs",   # infraRsVlanNsDef est un MO derive : jamais dans un export
    "infraAttEntityP", "infraRsDomP", "infraGeneric", "infraRsFuncToEpg",
    "infraAccPortGrp", "infraAccBndlGrp", "infraRsAttEntP",
    "infraAccPortP", "infraHPortS", "infraPortBlk", "infraRsAccBaseGrp",
    "infraNodeP", "infraLeafS", "infraNodeBlk", "infraRsAccPortP",
    "infraFexP", "infraFexBndlGrp", "infraRsAccBndlGrpToAggrIf",
    "fabricExplicitGEp", "fabricNodePEp", "fabricProtPol",
    # cote spine (L3Out sur spine, GOLF, multipod)
    "infraSpineP", "infraSpineS", "infraSpAccPortP", "infraSHPortS",
    "infraSpAccPortGrp", "infraRsSpAccGrp", "infraRsSpAccPortP",
    # management (graphe de contrats PARALLELE : l'OOB n'utilise PAS fvRsProv)
    "mgmtMgmtP", "mgmtOoB", "mgmtInB", "mgmtInstP",
    "mgmtRsOoBProv", "mgmtRsOoBCons", "mgmtSubnet",
    # --- chaine logique ----------------------------------------------------
    "fvTenant", "fvCtx", "fvBD", "fvSubnet", "fvRsCtx", "fvRsBDToOut",
    "fvAp", "fvAEPg", "fvRsBd", "fvRsDomAtt", "fvRsPathAtt", "fvRsNodeAtt",
    "fvESg", "fvEPSelector", "fvRsScope", "fvRsSecInherited",
    "fvRsProv", "fvRsCons", "fvRsConsIf", "fvRsProtBy", "fvRsIntraEpg",
    # --- contrats ----------------------------------------------------------
    "vzBrCP", "vzSubj", "vzRsSubjFiltAtt", "vzRsFiltAtt", "vzFilter", "vzEntry",
    "vzAny", "vzRsAnyToProv", "vzRsAnyToCons", "vzCPIf", "vzRsIf",
    "vzOOBBrCP", "vzTaboo",
    # --- L3Out -------------------------------------------------------------
    "l3extOut", "l3extRsEctx", "l3extRsL3DomAtt", "l3extInstP", "l3extSubnet",
    "l3extLNodeP", "l3extRsNodeL3OutAtt", "l3extLIfP", "l3extRsPathL3OutAtt",
    "l3extIp", "l3extMember", "l3extVirtualLIfP", "l3extRsDynPathAtt",
    "ipRouteP", "ipNexthopP",
    "ospfExtP", "bgpExtP", "eigrpExtP", "bgpPeerP",
    # --- L2Out -------------------------------------------------------------
    "l2extOut", "l2extInstP", "l2extLNodeP", "l2extLIfP", "l2extRsPathL2OutAtt",
    # --- inventaire / identification du fabric -----------------------------
    "fabricNode", "fabricPod", "topSystem", "infraWiNode",
    # le nom du fabric vient de sa banniere de login - meme convention que
    # make_patrimoine_inventory.py (get_fabric_alias)
    "aaaPreLoginBanner",
])

# Attributs de tenue de livre APIC : aucune valeur pour nous, beaucoup de volume.
DROP_ATTRS = frozenset([
    "childAction", "lcOwn", "modTs", "monPolDn", "uid", "extMngdBy",
    "userdom", "annotation", "status", "rn", "dn",  # dn est reinjecte a part
    "configIssues", "configSt", "triggerSt", "stateQual", "forceResolve",
    "rType", "tType", "tContextDn", "tRn", "isUsingConnSel", "creator",
])

# Un attribut dont le nom evoque un secret est jete sans etre lu.
# Le Global AES Encryption etant actif chez nous, ces champs sont de toute facon
# du chiffre inexploitable ; les jeter garantit qu'aucun secret, meme chiffre,
# ne quitte le serveur.
SECRET_HINTS = ("pwd", "passwd", "password", "secret", "community",
                "privkey", "sharedsecret", "psk", "keyring", "certificate")

SECRET_EXACT = frozenset(["key", "cert", "token", "hash", "salt"])


def is_secret_attr(name):
    low = name.lower()
    if low in SECRET_EXACT:
        return True
    for h in SECRET_HINTS:
        if h in low:
            return True
    return False


# ---------------------------------------------------------------------------
# Reconstruction des DN
#
# POURQUOI : un export APIC ne porte PAS forcement dn ni rn sur les objets
# enfants - seule la racine a un dn, et les enfants ne gardent que leurs
# attributs de nommage. Verifie sur un APIC 6.0(7e) : une reponse
# rsp-prop-include=config-only, qui est le contenu meme d'un export, supprime
# dn ET rn partout sauf a la racine.
#
# On reconstruit donc le RN depuis les regles de nommage ACI. Ces gabarits ont
# ete DERIVES automatiquement des vrais DN d'un APIC, puis verifies par
# round-trip : 467/467 DN reconstruits a l'identique, 0 en trop.
#
# Un gabarit manquant n'est pas silencieux : la branche entiere est comptee
# comme non resolue et signalee en fin d'execution.
# ---------------------------------------------------------------------------
RN_TEMPLATES = {
    # -- racines et conteneurs structurels (non conserves, mais traverses) --
    "polUni": "uni",
    "infraInfra": "infra",
    "infraFuncP": "funcprof",
    "infraProvAcc": "provacc",
    "fabricInst": "fabric",
    "fabricProtPol": "protpol",
    "vmmProvP": "vmmp-{vendor}",
    "aaaUserEp": "userext",
    "aaaPreLoginBanner": "preloginbanner",
    # -- domaines --
    "physDomP": "phys-{name}",
    "l3extDomP": "l3dom-{name}",
    "vmmDomP": "dom-{name}",
    "fcDomP": "fc-{name}",
    # -- pools de VLAN --
    "fvnsVlanInstP": "vlanns-[{name}]-{allocMode}",
    "fvnsVsanInstP": "vsanns-[{name}]-{allocMode}",
    "fvnsEncapBlk": "from-[{from}]-to-[{to}]",
    "infraRsVlanNs": "rsvlanNs",
    # -- access policies --
    "infraAttEntityP": "attentp-{name}",
    "infraRsDomP": "rsdomP-[{tDn}]",
    "infraGeneric": "gen-{name}",
    "infraRsFuncToEpg": "rsfuncToEpg-[{tDn}]",
    "infraAccPortGrp": "accportgrp-{name}",
    "infraAccBndlGrp": "accbundle-{name}",
    "infraRsAttEntP": "rsattEntP",
    "infraAccPortP": "accportprof-{name}",
    "infraHPortS": "hports-{name}-typ-{type}",
    "infraPortBlk": "portblk-{name}",
    "infraRsAccBaseGrp": "rsaccBaseGrp",
    "infraNodeP": "nprof-{name}",
    "infraLeafS": "leaves-{name}-typ-{type}",
    "infraNodeBlk": "nodeblk-{name}",
    "infraRsAccPortP": "rsaccPortP-[{tDn}]",
    "infraFexP": "fexprof-{name}",
    "infraFexBndlGrp": "fexbundle-{name}",
    "infraRsAccBndlGrpToAggrIf": "rsaccBndlGrpToAggrIf-[{tDn}]",
    # -- cote spine --
    # spprof / spaccportprof verifies sur APIC 6.0(7e) et sur un tDn d'un vrai
    # backup ("uni/infra/spaccportprof-default"). Les quatre suivants suivent la
    # symetrie exacte de leurs equivalents leaf mais n'ont PAS pu etre verifies
    # (aucune instance dans le lab) : si un backup reel en contient et que le
    # gabarit est faux, la metrique "objets utiles perdus" le signalera.
    "infraSpineP": "spprof-{name}",
    "infraSpAccPortP": "spaccportprof-{name}",
    "infraSpineS": "spines-{name}-typ-{type}",          # non verifie
    "infraSHPortS": "shports-{name}-typ-{type}",        # non verifie
    "infraSpAccPortGrp": "spaccportgrp-{name}",         # non verifie
    "infraRsSpAccGrp": "rsspAccGrp",                    # non verifie
    "infraRsSpAccPortP": "rsspAccPortP-[{tDn}]",        # non verifie
    # -- management --
    # verifie sur APIC 6.0(7e) : uni/tn-mgmt/extmgmt-default. C'est le PARENT
    # de mgmtInstP/mgmtSubnet : sans lui, toute la branche external-management
    # etait coupee ("3 objets utiles perdus" sur chaque fabrique de prod).
    "mgmtExtMgmtEntity": "extmgmt-{name}",
    "mgmtMgmtP": "mgmtp-{name}",
    "mgmtOoB": "oob-{name}",
    "mgmtInB": "inb-{name}",
    "mgmtInstP": "instp-{name}",
    "mgmtRsOoBProv": "rsooBProv-{tnVzOOBBrCPName}",
    "mgmtRsOoBCons": "rsooBCons-{tnVzOOBBrCPName}",
    "mgmtSubnet": "subnet-[{ip}]",
    "fabricExplicitGEp": "expgep-{name}",
    "fabricNodePEp": "nodepep-{id}",
    # -- logique --
    "fvTenant": "tn-{name}",
    "fvCtx": "ctx-{name}",
    "fvBD": "BD-{name}",
    "fvSubnet": "subnet-[{ip}]",
    "fvRsCtx": "rsctx",
    "fvRsBDToOut": "rsBDToOut-{tnL3extOutName}",
    "fvAp": "ap-{name}",
    "fvAEPg": "epg-{name}",
    "fvESg": "esg-{name}",
    "fvEPSelector": "epselector-[{matchExpression}]",
    "fvRsBd": "rsbd",
    "fvRsScope": "rsscope",
    "fvRsDomAtt": "rsdomAtt-[{tDn}]",
    "fvRsPathAtt": "rspathAtt-[{tDn}]",
    "fvRsNodeAtt": "rsnodeAtt-[{tDn}]",
    "fvRsProv": "rsprov-{tnVzBrCPName}",
    "fvRsCons": "rscons-{tnVzBrCPName}",
    "fvRsConsIf": "rsconsIf-{tnVzCPIfName}",
    "fvRsProtBy": "rsprotBy-{tnVzTabooName}",
    "fvRsIntraEpg": "rsintraEpg-{tnVzBrCPName}",
    "fvRsSecInherited": "rssecInherited-[{tDn}]",
    # -- contrats --
    "vzBrCP": "brc-{name}",
    "vzOOBBrCP": "oobbrc-{name}",
    "vzTaboo": "taboo-{name}",
    "vzSubj": "subj-{name}",
    "vzRsSubjFiltAtt": "rssubjFiltAtt-{tnVzFilterName}",
    "vzRsFiltAtt": "rsfiltAtt-{tnVzFilterName}",
    "vzFilter": "flt-{name}",
    "vzEntry": "e-{name}",
    "vzAny": "any",
    "vzRsAnyToProv": "rsanyToProv-{tnVzBrCPName}",
    "vzRsAnyToCons": "rsanyToCons-{tnVzBrCPName}",
    "vzCPIf": "cif-{name}",
    "vzRsIf": "rsif",
    # -- L3Out --
    "l3extOut": "out-{name}",
    "l3extRsEctx": "rsectx",
    "l3extRsL3DomAtt": "rsl3DomAtt",
    "l3extInstP": "instP-{name}",
    "l3extSubnet": "extsubnet-[{ip}]",
    "l3extLNodeP": "lnodep-{name}",
    "l3extRsNodeL3OutAtt": "rsnodeL3OutAtt-[{tDn}]",
    # verifies sur APIC 6.0(7e) : rt-[172.31.99.0/24] / nh-[192.168.200.9]
    "ipRouteP": "rt-[{ip}]",
    "ipNexthopP": "nh-[{nhAddr}]",
    "l3extLIfP": "lifp-{name}",
    "l3extRsPathL3OutAtt": "rspathL3OutAtt-[{tDn}]",
    "l3extRsDynPathAtt": "rsdynPathAtt-[{tDn}]",
    "l3extVirtualLIfP": "vlifp-[{nodeDn}]-[{encap}]",
    "l3extIp": "addr-[{addr}]",
    "l3extMember": "mem-{side}",
    "ospfExtP": "ospfExtP",
    "bgpExtP": "bgpExtP",
    "eigrpExtP": "eigrpExtP",
    "bgpPeerP": "peerP-[{addr}]",
    # -- L2Out --
    "l2extOut": "l2out-{name}",
    "l2extInstP": "instP-{name}",
    "l2extLNodeP": "lnodep-{name}",
    "l2extLIfP": "lifp-{name}",
    "l2extRsPathL2OutAtt": "rspathL2OutAtt-[{tDn}]",
}


# Classes qui vivent directement sous "uni". Un export APIC peut etre eclate en
# plusieurs fichiers dont la racine n'est pas polUni mais l'un de ses enfants ;
# sans dn sur cette racine, le prefixe "uni/" serait perdu et TOUS les DN du
# fichier seraient faux. Cette table le restitue.
ROOT_PARENT = {
    "fvTenant": "uni",
    "physDomP": "uni",
    "l3extDomP": "uni",
    "fcDomP": "uni",
    "vmmProvP": "uni",
    "infraInfra": "uni",
    "fabricInst": "uni",
}


def build_rn(cls, attrs):
    """Reconstruit le RN d'un MO depuis son gabarit. None si impossible."""
    tpl = RN_TEMPLATES.get(cls)
    if tpl is None:
        return None
    out = []
    i = 0
    n = len(tpl)
    while i < n:
        if tpl[i] == "{":
            j = tpl.find("}", i)
            if j < 0:
                return None
            val = attrs.get(tpl[i + 1:j])
            if val is None:
                return None      # attribut de nommage absent : on n'invente pas
            out.append(val)
            i = j + 1
        else:
            out.append(tpl[i])
            i += 1
    return "".join(out)


# ---------------------------------------------------------------------------
# Aplatissement du MIT
# ---------------------------------------------------------------------------

def count_keep_in_subtree(mo, keep):
    """Nombre d'objets de classes utiles dans ce sous-arbre, lui-meme inclus."""
    n = 0
    stack = [mo]
    while stack:
        node = stack.pop()
        for cls, body in node.items():
            if not isinstance(body, dict):
                continue
            if cls in keep:
                n += 1
            for ch in (body.get("children") or []):
                if isinstance(ch, dict):
                    stack.append(ch)
    return n


def flatten_mo(mo, parent_dn, keep, out, dropped_attr_names, gaps):
    """Aplatit recursivement un MO {classe: {attributes, children}}.

    Descend TOUJOURS dans les enfants, meme quand le parent n'est pas retenu :
    fvSubnet vit sous fvBD, l3extSubnet sous l3extInstP, et un filtrage
    premature couperait la branche avant d'atteindre la feuille utile.

    Le DN est pris tel quel s'il est present, sinon reconstruit depuis le rn,
    sinon depuis le gabarit de nommage de la classe. Si aucune des trois voies
    n'aboutit, le MO et toute sa descendance sont ecartes et signales : mieux
    vaut un trou visible qu'un DN faux qui casserait silencieusement toutes
    les resolutions de chaine.
    """
    for cls, body in mo.items():
        if not isinstance(body, dict):
            continue
        attrs = body.get("attributes") or {}

        dn = attrs.get("dn")
        if not dn:
            base = parent_dn or ROOT_PARENT.get(cls, "")
            rn = attrs.get("rn") or build_rn(cls, attrs)
            if rn:
                dn = (base + "/" + rn) if base else rn
            else:
                dn = None

        if dn is None:
            if cls in RN_TEMPLATES:
                gaps["naming_attr"][cls] = gaps["naming_attr"].get(cls, 0) + 1
            elif cls in keep:
                # une classe qu'on veut garder mais dont on ignore le nommage :
                # c'est un vrai defaut de l'extracteur, pas du bruit.
                gaps["no_template_kept"][cls] = gaps["no_template_kept"].get(cls, 0) + 1
            else:
                gaps["no_template"][cls] = gaps["no_template"].get(cls, 0) + 1

            # LA metrique qui compte. Couper une branche n'est un probleme que
            # si elle contenait des objets utiles. Un arbre de politiques ACI
            # est aux trois quarts fait de classes qui ne nous concernent pas :
            # les compter toutes noierait le signal. On compte donc ce qu'on a
            # REELLEMENT perdu, et c'est ce chiffre qui est remonte a l'ecran.
            n_lost = count_keep_in_subtree(mo, keep)
            if n_lost:
                gaps["lost_useful"][cls] = gaps["lost_useful"].get(cls, 0) + n_lost
            continue          # on ne descend pas : les enfants seraient faux

        if cls in keep:
            clean = {}
            for k, v in attrs.items():
                if k in DROP_ATTRS:
                    continue
                if is_secret_attr(k):
                    dropped_attr_names.add(k)
                    continue
                if v == "":
                    continue          # un attribut vide n'apporte rien
                clean[k] = v
            out.append({"c": cls, "dn": dn, "a": clean})

        children = body.get("children")
        if children:
            for child in children:
                if isinstance(child, dict):
                    flatten_mo(child, dn, keep, out, dropped_attr_names, gaps)


# ---------------------------------------------------------------------------
# Lecture d'une archive d'export APIC
# ---------------------------------------------------------------------------

def new_stats():
    return {"bytes_read": 0, "members_seen": 0, "members_json": 0,
            "members_xml": 0, "members_other": 0, "members_skipped": 0,
            "largest_member": 0, "largest_member_name": "",
            "skipped_roots": {}, "dropped_attrs": set(),
            "gaps": {"naming_attr": {}, "no_template": {},
                     "no_template_kept": {}, "lost_useful": {}}}


def xml_to_mo(elem):
    """Convertit un element XML APIC dans la meme forme que le JSON.

    Le XML APIC est direct : <fvTenant name="PROD"><fvBD .../></fvTenant>.
    Le tag est la classe, les attributs XML sont les attributs du MO.
    """
    return {elem.tag: {"attributes": dict(elem.attrib),
                       "children": [xml_to_mo(c) for c in elem]}}


def parse_member(raw, name):
    """Retourne la liste des MOs racines d'un membre d'archive, ou None.

    Gere le JSON ET le XML : sur configExportP, l'attribut format=json|xml ne
    change QUE l'extension des membres, pas leur structure. Un extracteur qui
    ne lirait que le JSON ignorerait silencieusement un backup entier.
    """
    low = name.lower()

    if low.endswith(".xml"):
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(raw)
        except Exception as exc:            # ParseError et derives
            warn("  membre XML illisible, ignore : %s (%s)" % (name, exc))
            return None
        # Une reponse API XML est enveloppee dans <imdata>.
        if root.tag == "imdata":
            return [xml_to_mo(c) for c in root]
        return [xml_to_mo(root)]

    if low.endswith(".json"):
        try:
            doc = json.loads(raw.decode("utf-8"))
        except ValueError as exc:
            warn("  membre JSON illisible, ignore : %s (%s)" % (name, exc))
            return None
        if isinstance(doc, dict) and "imdata" in doc:
            return [r for r in doc["imdata"] if isinstance(r, dict)]
        if isinstance(doc, list):
            return [r for r in doc if isinstance(r, dict)]
        if isinstance(doc, dict):
            return [doc]
        return None

    return None                             # ni JSON ni XML : pas pour nous


def read_export(path, keep, stats):
    """Ouvre un .tar.gz d'export APIC et retourne la liste des MOs retenus.

    Agnostique a la mise en page : un export peut contenir un seul gros fichier
    ou plusieurs dizaines, en JSON ou en XML. On parcourt tous les membres.

    Un membre n'est retenu que si sa racine est `polUni` ou l'un de ses enfants
    directs connus. Cela ecarte proprement les annexes de l'archive --
    `idconfig/`, `dhcpconfig/` (numeros de serie, TEP pool, IP OOB) et
    `packages/` -- qui ne contiennent rien d'utile ici et beaucoup de choses
    sensibles. Ce qui est ecarte est compte, pas oublie.
    """
    mos = []
    dropped = set()
    accepted_roots = set(["polUni"]) | set(ROOT_PARENT)

    tar = tarfile.open(path, "r:gz")
    try:
        for member in tar:
            if not member.isfile():
                continue
            stats["members_seen"] += 1
            name = member.name
            low = name.lower()
            if not (low.endswith(".json") or low.endswith(".xml")):
                stats["members_other"] += 1
                continue

            fobj = tar.extractfile(member)
            if fobj is None:
                continue
            try:
                raw = fobj.read()
            finally:
                fobj.close()

            stats["bytes_read"] += len(raw)
            if member.size > stats["largest_member"]:
                stats["largest_member"] = member.size
                stats["largest_member_name"] = name

            roots = parse_member(raw, name)
            del raw
            if not roots:
                continue

            if low.endswith(".xml"):
                stats["members_xml"] += 1
            else:
                stats["members_json"] += 1

            used = False
            for root in roots:
                cls = None
                for k in root:
                    cls = k
                    break
                if cls not in accepted_roots:
                    stats["skipped_roots"][cls] = \
                        stats["skipped_roots"].get(cls, 0) + 1
                    continue
                used = True
                flatten_mo(root, "", keep, mos, dropped, stats["gaps"])
            if not used:
                stats["members_skipped"] += 1
            del roots
    finally:
        tar.close()

    stats["dropped_attrs"].update(dropped)
    return mos


def fabric_alias(mos):
    """Nom du fabric tel qu'il se declare lui-meme.

    Meme source que make_patrimoine_inventory.py : la banniere de login
    (aaaPreLoginBanner.guiTextMessage). Plus fiable qu'un nom de repertoire,
    puisqu'elle voyage avec le backup.
    """
    for m in mos:
        if m["c"] == "aaaPreLoginBanner":
            v = (m["a"].get("guiTextMessage") or "").strip()
            if v:
                return v
    return ""


def sha256_of(path, chunk=1024 * 1024):
    h = hashlib.sha256()
    f = open(path, "rb")
    try:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    finally:
        f.close()
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Decouverte des backups
# ---------------------------------------------------------------------------

TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}[-:]\d{2}[-:]\d{2})")


def resolve_spec(spec, root, pattern):
    """Transforme une entree de FABRICS en motif glob exploitable.

    Accepte un repertoire, un motif, un chemin absolu ou relatif a --root.
    """
    import glob as globmod

    if not os.path.isabs(spec) and root:
        spec = os.path.join(root, spec)
    if os.path.isdir(spec):
        return os.path.join(spec, pattern)
    if globmod.has_magic(spec) if hasattr(globmod, "has_magic") else \
            any(c in spec for c in "*?["):
        return spec
    # ni repertoire ni motif : soit un fichier precis, soit un prefixe
    if os.path.isfile(spec):
        return spec
    return spec + "*" if not spec.endswith(os.sep) else spec + pattern


def discover(root, inventory_path, pattern):
    """Retourne [(fabric_id, backup_retenu, tous_les_candidats), ...].

    Quatre sources, essayees dans cet ordre. La premiere qui donne quelque
    chose gagne, et la source retenue est annoncee dans le journal :
      1. le bloc FABRICS en tete de ce fichier  <-- la facon recommandee
      2. un inventaire CSV passe par --inventory
      3. un sous-repertoire par fabric sous --root
      4. tout a plat dans --root, le fabric devine depuis le nom de fichier
    """
    import glob as globmod

    found = []

    if FABRICS:
        for entry in FABRICS:
            if not entry or len(entry) < 2:
                warn("entree FABRICS ignoree (attendu un couple "
                     "(\"nom\", \"chemin\")) : %r" % (entry,))
                continue
            fabric_id, spec = entry[0], entry[1]
            pat = resolve_spec(spec, root, pattern)
            matches = globmod.glob(pat)
            if not matches:
                warn("aucun backup pour %s -> %s" % (fabric_id, pat))
                continue
            found.append((fabric_id, newest(matches), matches))
        if not found:
            warn("le bloc FABRICS est rempli mais aucun chemin ne correspond ; "
                 "verifiez les chemins avec --dry-run")
        return found

    if inventory_path:
        fh = open(inventory_path, "r")
        try:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = [p.strip() for p in line.split(",")]
                if len(parts) < 3:
                    warn("inventaire ligne %d ignoree (3 colonnes attendues) : %s"
                         % (lineno, line))
                    continue
                fabric_id, _site, pat = parts[0], parts[1], ",".join(parts[2:])
                if not os.path.isabs(pat):
                    pat = os.path.join(root, pat)
                matches = globmod.glob(pat)
                if not matches:
                    warn("aucun backup pour %s (motif : %s)" % (fabric_id, pat))
                    continue
                found.append((fabric_id, newest(matches), matches))
        finally:
            fh.close()
        return found

    if not os.path.isdir(root):
        die("repertoire racine introuvable : %s" % root)

    for entry in sorted(os.listdir(root)):
        sub = os.path.join(root, entry)
        if not os.path.isdir(sub):
            continue
        matches = globmod.glob(os.path.join(sub, pattern))
        if not matches:
            warn("aucun backup dans %s (motif : %s)" % (sub, pattern))
            continue
        found.append((entry, newest(matches), matches))

    if not found:
        # Dernier recours : tout est a plat dans root, le fabric est dans le nom.
        matches = globmod.glob(os.path.join(root, pattern))
        by_fabric = {}
        for m in matches:
            fid = fabric_from_filename(os.path.basename(m))
            by_fabric.setdefault(fid, []).append(m)
        for fid in sorted(by_fabric):
            found.append((fid, newest(by_fabric[fid]), by_fabric[fid]))

    return found


def newest(paths):
    """Le plus recent : timestamp dans le nom si present, sinon mtime."""
    def key(p):
        m = TS_RE.search(os.path.basename(p))
        if m:
            return (1, m.group(1))
        return (0, "%020d" % int(os.path.getmtime(p)))
    return sorted(paths, key=key)[-1]


def fabric_from_filename(name):
    """ce2_DailyAutoBackup-2026-07-20T17-00-24.tar.gz -> DailyAutoBackup

    Heuristique de repli seulement. En production, l'inventaire CSV ou un
    repertoire par fabric donne un resultat fiable ; ceci evite juste de
    planter quand tout est en vrac.
    """
    base = name
    for suffix in (".tar.gz", ".tgz", ".tar"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
            break
    base = re.sub(r"^ce2?_", "", base)
    base = TS_RE.sub("", base).strip("-_ ")
    return base or "inconnu"


# ---------------------------------------------------------------------------
# Utilitaires de sortie
# ---------------------------------------------------------------------------

def warn(msg):
    sys.stderr.write("[!] %s\n" % msg)
    sys.stderr.flush()


def info(msg):
    sys.stdout.write("    %s\n" % msg)
    sys.stdout.flush()


def die(msg):
    sys.stderr.write("[X] %s\n" % msg)
    sys.stdout.write("FL-EXTRACT-FAIL\n")
    sys.stdout.flush()
    sys.exit(2)


def human(n):
    for unit in ("o", "Ko", "Mo", "Go"):
        if n < 1024.0:
            return "%.1f %s" % (n, unit)
        n /= 1024.0
    return "%.1f To" % n


# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Autotest
#
# Fabrique une archive d'export synthetique, l'extrait, et verifie que chaque
# maillon des deux chaines est reconstruit avec le bon DN. Ne touche a aucun
# backup reel et n'ecrit que dans un repertoire temporaire.
#
# But : prouver, SUR LA MACHINE CIBLE, que la version de Python installee lit
# correctement les archives et reconstruit les DN - avant de lancer quoi que ce
# soit sur les vraies donnees.
# ---------------------------------------------------------------------------

def _mo(cls, attrs, children=None):
    body = {"attributes": attrs}
    if children:
        body["children"] = children
    return {cls: body}


def selftest_tree():
    """Un mini-MIT couvrant les deux chaines et les cas qui comptent.

    Volontairement SANS aucun dn ni rn : c'est le cas difficile, celui d'un
    export APIC reel, ou tout doit etre reconstruit depuis les gabarits.
    """
    vlan_pool = _mo("fvnsVlanInstP",
                    {"name": "Prod_VLAN_Pool", "allocMode": "static"},
                    [_mo("fvnsEncapBlk", {"from": "vlan-2000", "to": "vlan-2199",
                                          "allocMode": "static", "role": "external"})])
    phys_dom = _mo("physDomP", {"name": "Prod_PhysDomain"},
                   [_mo("infraRsVlanNs",
                        {"tDn": "uni/infra/vlanns-[Prod_VLAN_Pool]-static"})])
    infra = _mo("infraInfra", {}, [
        vlan_pool,
        _mo("infraAttEntityP", {"name": "SRV.AAEP"}, [
            _mo("infraRsDomP", {"tDn": "uni/phys-Prod_PhysDomain"}),
            _mo("infraGeneric", {"name": "default"}, [
                _mo("infraRsFuncToEpg",
                    {"tDn": "uni/tn-Production/ap-WebApp_AP/epg-WebServers_EPG",
                     "encap": "vlan-2110", "mode": "regular"})]),
        ]),
        _mo("infraFuncP", {}, [
            _mo("infraAccBndlGrp", {"name": "SRV-VPC.IPG", "lagT": "node"}, [
                _mo("infraRsAttEntP", {"tDn": "uni/infra/attentp-SRV.AAEP"})])]),
        _mo("infraAccPortP", {"name": "leaf101_IPP"}, [
            _mo("infraHPortS", {"name": "sel20", "type": "range"}, [
                _mo("infraPortBlk", {"name": "blk1", "fromCard": "1",
                                     "toCard": "1", "fromPort": "20", "toPort": "20"}),
                _mo("infraRsAccBaseGrp",
                    {"tDn": "uni/infra/funcprof/accbundle-SRV-VPC.IPG"})])]),
        _mo("infraNodeP", {"name": "leaf101_SP"}, [
            _mo("infraLeafS", {"name": "sel101", "type": "range"},
                [_mo("infraNodeBlk", {"name": "blk", "from_": "101", "to_": "101"})]),
            _mo("infraRsAccPortP", {"tDn": "uni/infra/accportprof-leaf101_IPP"})]),
    ])
    tenant = _mo("fvTenant", {"name": "Production"}, [
        _mo("fvCtx", {"name": "Prod_VRF"}),
        _mo("fvBD", {"name": "BD-WEB-2110", "unicastRoute": "yes",
                     "arpFlood": "no", "unkMacUcastAct": "proxy"}, [
            _mo("fvRsCtx", {"tnFvCtxName": "Prod_VRF"}),
            _mo("fvSubnet", {"ip": "10.21.10.1/24", "scope": "public,shared"})]),
        _mo("fvAp", {"name": "WebApp_AP"}, [
            _mo("fvAEPg", {"name": "WebServers_EPG"}, [
                _mo("fvRsBd", {"tnFvBDName": "BD-WEB-2110"}),
                _mo("fvRsDomAtt", {"tDn": "uni/phys-Prod_PhysDomain"}),
                _mo("fvRsPathAtt",
                    {"tDn": "topology/pod-1/protpaths-101-102/pathep-[SRV-VPC.IPG]",
                     "encap": "vlan-2110", "mode": "regular"}),
                _mo("fvRsProv", {"tnVzBrCPName": "Web_Internet_Contract"}),
                _mo("fvRsCons", {"tnVzBrCPName": "Web_to_App_Contract"})])]),
        _mo("vzBrCP", {"name": "Web_Internet_Contract", "scope": "context"}, [
            _mo("vzSubj", {"name": "web"},
                [_mo("vzRsSubjFiltAtt", {"tnVzFilterName": "https"})])]),
        _mo("vzFilter", {"name": "https"},
            [_mo("vzEntry", {"name": "https", "etherT": "ip", "prot": "tcp",
                             "dFromPort": "443", "dToPort": "443"})]),
        _mo("l3extOut", {"name": "L3OUT-INTERNET", "enforceRtctrl": "export"}, [
            _mo("l3extRsEctx", {"tnFvCtxName": "Prod_VRF"}),
            _mo("l3extInstP", {"name": "EXT-INTERNET"}, [
                _mo("l3extSubnet", {"ip": "10.21.10.0/24",
                                    "scope": "export-rtctrl,import-security"}),
                _mo("l3extSubnet", {"ip": "0.0.0.0/0", "scope": "import-security"}),
                _mo("fvRsCons", {"tnVzBrCPName": "Web_Internet_Contract"})]),
            _mo("l3extLNodeP", {"name": "NP-INTERNET"}, [
                _mo("l3extRsNodeL3OutAtt",
                    {"tDn": "topology/pod-1/node-101", "rtrId": "10.0.0.101"}, [
                    _mo("ipRouteP", {"ip": "172.31.99.0/24", "pref": "1"}, [
                        _mo("ipNexthopP", {"nhAddr": "192.168.200.9"})])])])]),
    ])
    return _mo("polUni", {"dn": "uni"}, [infra, phys_dom, tenant])


# Ce que l'extraction DOIT produire. Chaque entree est un maillon d'une chaine :
# s'il manque, une resolution casse.
SELFTEST_EXPECT = [
    ("uni/infra/vlanns-[Prod_VLAN_Pool]-static", "VLAN pool"),
    ("uni/infra/vlanns-[Prod_VLAN_Pool]-static/from-[vlan-2000]-to-[vlan-2199]", "encap block"),
    ("uni/phys-Prod_PhysDomain", "physical domain"),
    ("uni/phys-Prod_PhysDomain/rsvlanNs", "domain -> pool"),
    ("uni/infra/attentp-SRV.AAEP", "AAEP"),
    ("uni/infra/attentp-SRV.AAEP/rsdomP-[uni/phys-Prod_PhysDomain]", "AAEP -> domain"),
    ("uni/infra/attentp-SRV.AAEP/gen-default/rsfuncToEpg-"
     "[uni/tn-Production/ap-WebApp_AP/epg-WebServers_EPG]", "deploiement AAEP (encap)"),
    ("uni/infra/funcprof/accbundle-SRV-VPC.IPG", "IPG vPC"),
    ("uni/infra/funcprof/accbundle-SRV-VPC.IPG/rsattEntP", "IPG -> AAEP"),
    ("uni/infra/accportprof-leaf101_IPP/hports-sel20-typ-range/portblk-blk1", "port block"),
    ("uni/infra/accportprof-leaf101_IPP/hports-sel20-typ-range/rsaccBaseGrp", "selector -> IPG"),
    ("uni/infra/nprof-leaf101_SP/leaves-sel101-typ-range/nodeblk-blk", "node block"),
    ("uni/infra/nprof-leaf101_SP/rsaccPortP-[uni/infra/accportprof-leaf101_IPP]",
     "switch profile -> interface profile"),
    ("uni/tn-Production", "tenant"),
    ("uni/tn-Production/ctx-Prod_VRF", "VRF"),
    ("uni/tn-Production/BD-BD-WEB-2110", "bridge domain"),
    ("uni/tn-Production/BD-BD-WEB-2110/subnet-[10.21.10.1/24]", "subnet de BD"),
    ("uni/tn-Production/ap-WebApp_AP/epg-WebServers_EPG", "EPG"),
    ("uni/tn-Production/ap-WebApp_AP/epg-WebServers_EPG/rsbd", "EPG -> BD"),
    ("uni/tn-Production/ap-WebApp_AP/epg-WebServers_EPG/rspathAtt-"
     "[topology/pod-1/protpaths-101-102/pathep-[SRV-VPC.IPG]]", "static port binding"),
    ("uni/tn-Production/ap-WebApp_AP/epg-WebServers_EPG/rsprov-Web_Internet_Contract",
     "EPG provide"),
    ("uni/tn-Production/brc-Web_Internet_Contract/subj-web/rssubjFiltAtt-https",
     "subject -> filter"),
    ("uni/tn-Production/flt-https/e-https", "filter entry"),
    ("uni/tn-Production/out-L3OUT-INTERNET", "L3Out"),
    ("uni/tn-Production/out-L3OUT-INTERNET/instP-EXT-INTERNET", "ext-EPG"),
    ("uni/tn-Production/out-L3OUT-INTERNET/instP-EXT-INTERNET/extsubnet-[10.21.10.0/24]",
     "l3extSubnet (scopes)"),
    ("uni/tn-Production/out-L3OUT-INTERNET/lnodep-NP-INTERNET/"
     "rsnodeL3OutAtt-[topology/pod-1/node-101]/rt-[172.31.99.0/24]", "route statique"),
    ("uni/tn-Production/out-L3OUT-INTERNET/lnodep-NP-INTERNET/"
     "rsnodeL3OutAtt-[topology/pod-1/node-101]/rt-[172.31.99.0/24]/nh-[192.168.200.9]",
     "next-hop de route statique"),
]


def run_selftest():
    import tempfile
    import shutil

    print("Fabric Lens - autotest de l'extracteur")
    print("  version extracteur : %s" % EXTRACTOR_VERSION)
    print("  python             : %s" % sys.version.split()[0])
    print("  plateforme         : %s\n" % sys.platform)

    tmp = tempfile.mkdtemp(prefix="fl_selftest_")
    try:
        arch = os.path.join(tmp, "ce2_SELFTEST-2026-01-01T00-00-00.tar.gz")

        # Trois mises en page, pour prouver que le resultat n'en depend pas :
        # un seul JSON, plusieurs JSON, et du XML avec les annexes d'un vrai
        # export (qui doivent etre ecartees).
        layouts = []
        blob_all = json.dumps({"imdata": [selftest_tree()]},
                              separators=(",", ":")).encode("utf-8")
        layouts.append(("json monolithique", [("uni.json", blob_all)]))

        split = []
        root_children = list(selftest_tree().values())[0]["children"]
        for i, ch in enumerate(root_children):
            split.append(("uni_%d.json" % i,
                          json.dumps({"imdata": [ch]},
                                     separators=(",", ":")).encode("utf-8")))
        layouts.append(("json eclate", split))

        import xml.etree.ElementTree as ET

        def to_xml(mo, parent=None):
            for cls, body in mo.items():
                attrs = dict((k, "" if v is None else str(v))
                             for k, v in (body.get("attributes") or {}).items())
                el = (ET.Element(cls, attrs) if parent is None
                      else ET.SubElement(parent, cls, attrs))
                for ch in (body.get("children") or []):
                    to_xml(ch, el)
                return el

        xml_main = ET.tostring(to_xml(selftest_tree()), encoding="utf-8")
        layouts.append(("xml + annexes", [
            ("ce2_SELFTEST_1.xml", xml_main),
            # Annexes d'un export reel : elles portent des donnees sensibles
            # (numeros de serie, TEP pool) et doivent etre ecartees.
            ("idconfig/ce2_SELFTEST_1_idfile.xml",
             b'<fabricNodeIdentPol><fabricNodeIdentP serial="FDO000000" '
             b'nodeId="101"/></fabricNodeIdentPol>'),
            ("dhcpconfig/ce2_SELFTEST_255_idfile.xml",
             b'<dhcpPool><dhcpClient ip="10.0.80.64"/></dhcpPool>'),
            ("packages/vendor.zip", b"PK\x03\x04"),
        ]))

        results = {}
        failures = []
        for label, members in layouts:
            tar = tarfile.open(arch, "w:gz")
            try:
                for name, blob in members:
                    ti = tarfile.TarInfo(name)
                    ti.size = len(blob)
                    ti.mtime = 0
                    tar.addfile(ti, io.BytesIO(blob))
            finally:
                tar.close()

            stats = new_stats()
            mos = read_export(arch, KEEP_CLASSES, stats)
            results[label] = set(m["dn"] for m in mos)

            print("  %-18s %d fichier(s) -> %d objets, %d racine(s) ecartee(s)"
                  % (label, len(members), len(mos),
                     sum(stats["skipped_roots"].values())))
            if stats["gaps"]["no_template_kept"]:
                failures.append("classes utiles sans gabarit (%s) : %s"
                                % (label, stats["gaps"]["no_template_kept"]))
            # Rien des annexes ne doit remonter.
            for dn in results[label]:
                if "NodeIdent" in dn or "dhcp" in dn.lower():
                    failures.append("fuite depuis une annexe (%s) : %s" % (label, dn))
                    break

        print()
        reference = layouts[0][0]
        ref_set = results.get(reference, set())
        all_same = True
        for label, _ in layouts[1:]:
            other = results.get(label, set())
            if other != ref_set:
                all_same = False
                failures.append("mise en page '%s' divergente de '%s' (%d manquants, %d en trop)"
                                % (label, reference,
                                   len(ref_set - other), len(other - ref_set)))
                for d in sorted(ref_set - other)[:3]:
                    print("    manque dans %-18s %s" % (label, d))
                for d in sorted(other - ref_set)[:3]:
                    print("    en trop dans %-17s %s" % (label, d))
        if all_same:
            print("  les %d mises en page produisent des DN identiques  [OK]"
                  % len(layouts))

        got = ref_set
        print("\n  Verification des maillons de chaine :")
        n_ok = 0
        for dn, label in SELFTEST_EXPECT:
            if dn in got:
                n_ok += 1
                print("    [OK]   %s" % label)
            else:
                print("    [ECHEC] %-32s attendu : %s" % (label, dn))
                failures.append("maillon manquant : %s" % label)

        print("\n  %d/%d maillons reconstruits" % (n_ok, len(SELFTEST_EXPECT)))

        if failures:
            print("\n  %d PROBLEME(S) :" % len(failures))
            for f in failures:
                print("    - %s" % f)
            print("\nFL-SELFTEST-FAIL")
            return 2

        print("\n  L'extracteur fonctionne sur cette machine.")
        print("FL-SELFTEST-OK")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def config_source(inventory_path):
    if FABRICS:
        src = "fichier fabric_path" if _fp is not None else "bloc FABRICS de fl_extract.py"
        return "%s (%d fabrique(s))" % (src, len(FABRICS))
    if inventory_path:
        return "inventaire CSV %s" % inventory_path
    return "auto-decouverte sous --root"


def run_dryrun(targets, root, inventory_path):
    print("Fabric Lens - reperage (aucune extraction, aucune ecriture)\n")
    print("  racine  : %s" % (root or "(non fournie)"))
    print("  source  : %s\n" % config_source(inventory_path))

    if not targets:
        print("  AUCUN BACKUP TROUVE.\n")
        print("  Pistes :")
        if FABRICS:
            print("    - les chemins du bloc FABRICS existent-ils sur CE serveur ?")
            print("      verifiez-en un a la main :")
            print("        ls -l %s" % FABRICS[0][1])
            print("    - un chemin relatif est resolu depuis --root (%s)" % root)
        else:
            print("    - le bloc FABRICS est vide : remplissez-le en tete de")
            print("      fl_extract.py, c'est la facon la plus simple.")
            print("    - ou verifiez que --root contient un sous-repertoire par fabric :")
            print("        ls -l %s" % root)
        print("    - le motif correspond-il aux fichiers ? (actuel : %s)" % "*.tar.gz")
        print("\nFL-DRYRUN-EMPTY")
        return 2

    print("  %-22s %-46s %10s  %s" % ("FABRIC", "BACKUP RETENU", "TAILLE", "CANDIDATS"))
    print("  " + "-" * 92)
    total = 0
    for fabric_id, chosen, candidates in targets:
        try:
            size = os.path.getsize(chosen)
        except OSError:
            size = 0
        total += size
        base = os.path.basename(chosen)
        if len(base) > 46:
            base = base[:43] + "..."
        print("  %-22s %-46s %10s  %d" % (fabric_id, base, human(size), len(candidates)))

    print("\n  %d fabric(s), %s a lire" % (len(targets), human(total)))
    print("  Si cette liste est juste, relancez sans --dry-run.")
    print("\nFL-DRYRUN-OK")
    return 0


def main(argv):
    ap = argparse.ArgumentParser(
        description="Extrait les objets utiles des backups APIC pour Fabric Lens.")
    ap.add_argument("--root", default=None,
                    help="repertoire racine contenant les backups")
    ap.add_argument("--out", default=None,
                    help="repertoire de sortie des fichiers distilles")
    ap.add_argument("--dry-run", action="store_true", dest="dry_run",
                    help="lister les backups reperes sans rien extraire ni ecrire")
    ap.add_argument("--selftest", action="store_true",
                    help="tester l'extracteur sur une archive synthetique "
                         "(n'a besoin ni de --root ni de --out)")
    ap.add_argument("--list", action="store_true", dest="list_backups",
                    help="lister TOUS les backups disponibles par fabric, en JSON "
                         "sur la sortie standard - pour un selecteur de backup")
    ap.add_argument("--bundle", default=None,
                    help="produire UN SEUL fichier JSON pret a charger dans le "
                         "webui : {fabrics}. Le mode le plus simple pour "
                         "les premiers tests - le .bat le rapatrie et on le charge "
                         "directement dans Fabric Lens.")
    ap.add_argument("--pick", default=None,
                    help="traiter ce backup precis au lieu du plus recent "
                         "(nom de fichier ou chemin complet ; avec --only)")
    ap.add_argument("--inventory", default=None,
                    help="CSV fabric_id,site,motif (sinon auto-decouverte)")
    ap.add_argument("--pattern", default="*.tar.gz",
                    help="motif des archives (defaut: *.tar.gz)")
    ap.add_argument("--force", action="store_true",
                    help="re-extraire meme si l'empreinte source est inchangee")
    ap.add_argument("--only", default=None,
                    help="ne traiter que ce fabric_id")
    args = ap.parse_args(argv[1:])

    # -- MODE PAR DEFAUT, SANS AUCUNE OPTION --------------------------------
    # `python3 fl_extract.py` tout court : lit le bloc FABRICS, distille, et
    # ecrit fabriclens-data.json A COTE DU SCRIPT. C'est le seul geste que
    # l'utilisateur a a faire. Les options ci-dessus restent pour le debug,
    # mais on ne les tape jamais au quotidien.
    if len(argv) <= 1:
        if not FABRICS:
            die("le bloc FABRICS en tete de ce fichier est vide : ajoutez-y "
                "une ligne par fabrique, puis relancez  python3 fl_extract.py")
        here = os.path.dirname(os.path.abspath(__file__))
        args.bundle = os.path.join(here, "fabriclens-data.json")

    if args.selftest:
        return run_selftest()

    # --root n'est indispensable que si quelque chose doit s'y resoudre :
    # avec un bloc FABRICS entierement en chemins absolus, il est superflu.
    needs_root = True
    if FABRICS:
        needs_root = any(len(e) >= 2 and not os.path.isabs(e[1]) for e in FABRICS)
    if needs_root and not args.root:
        die("--root est requis (sauf avec --selftest, ou si le bloc FABRICS "
            "n'utilise que des chemins absolus)")

    if args.list_backups:
        # Sortie JSON pure sur stdout : c'est ce qu'un selecteur de backup
        # cote interface consomme. Aucune trace parasite ici.
        targets = discover(args.root, args.inventory, args.pattern)
        if args.only:
            targets = [t for t in targets if t[0] == args.only]
        cat = []
        for fabric_id, chosen, candidates in targets:
            items = []
            for c in sorted(candidates, key=lambda x: newest([x])):
                m = TS_RE.search(os.path.basename(c))
                try:
                    size = os.path.getsize(c)
                    mtime = os.path.getmtime(c)
                except OSError:
                    size, mtime = 0, 0
                items.append({
                    "file": os.path.basename(c), "path": os.path.abspath(c),
                    "date": (m.group(1).replace("T", " ").replace("-", ":", 0)
                             if m else ""),
                    "size": size, "mtime": mtime,
                    "latest": os.path.abspath(c) == os.path.abspath(chosen),
                })
            items.sort(key=lambda x: (x["date"], x["mtime"]), reverse=True)
            cat.append({"fabric": fabric_id, "count": len(items), "backups": items})
        sys.stdout.write(json.dumps(
            {"generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
             "extractorVersion": EXTRACTOR_VERSION, "fabrics": cat},
            indent=1, sort_keys=True))
        sys.stdout.write("\n")
        return 0

    if args.dry_run:
        targets = discover(args.root, args.inventory, args.pattern)
        if args.only:
            targets = [t for t in targets if t[0] == args.only]
        return run_dryrun(targets, args.root, args.inventory)

    # Avec --bundle, les .gz ne sont qu'un intermediaire : si aucun --out n'est
    # donne, on les met dans un repertoire temporaire nettoye a la fin.
    _bundle_tmp = None
    if args.bundle and not args.out:
        import tempfile
        _bundle_tmp = tempfile.mkdtemp(prefix="fl_bundle_")
        args.out = _bundle_tmp
    if not args.out:
        die("--out est requis (sauf avec --selftest, --dry-run ou --bundle)")

    t0 = time.time()

    if not os.path.isdir(args.out):
        os.makedirs(args.out)

    manifest_path = os.path.join(args.out, "manifest.json")
    previous = {}
    if os.path.exists(manifest_path) and not args.force:
        try:
            fh = open(manifest_path, "r")
            try:
                previous = json.load(fh).get("fabrics", {})
            finally:
                fh.close()
        except (ValueError, IOError) as exc:
            warn("manifeste precedent illisible, on repart de zero (%s)" % exc)

    targets = discover(args.root, args.inventory, args.pattern)
    if args.only:
        targets = [t for t in targets if t[0] == args.only]
    if args.pick:
        # On ne veut PAS le plus recent mais celui-la. Utile pour comparer une
        # config a celle d'avant-hier, ou pour rejouer un cas precis.
        picked = []
        for fabric_id, chosen, candidates in targets:
            hit = [c for c in candidates
                   if os.path.abspath(c) == os.path.abspath(args.pick)
                   or os.path.basename(c) == args.pick]
            if hit:
                picked.append((fabric_id, hit[0], candidates))
            else:
                warn("--pick : %s introuvable parmi les backups de %s"
                     % (args.pick, fabric_id))
        targets = picked
    if not targets:
        die("aucun backup trouve sous %s" % args.root)

    print("Fabric Lens - extraction (v%s, python %d.%d)"
          % (EXTRACTOR_VERSION, sys.version_info[0], sys.version_info[1]))
    print("source de configuration : %s" % config_source(args.inventory))
    print("%d fabric(s) a traiter\n" % len(targets))

    manifest = {}
    n_ok = n_skip = n_err = 0

    for fabric_id, src, _candidates in targets:
        try:
            src_size = os.path.getsize(src)
            src_mtime = os.path.getmtime(src)
            print("[%s] %s (%s)" % (fabric_id, os.path.basename(src), human(src_size)))

            digest = sha256_of(src)
            out_name = "%s.fl.json.gz" % re.sub(r"[^A-Za-z0-9._-]", "_", fabric_id)
            out_path = os.path.join(args.out, out_name)

            prev = previous.get(fabric_id)
            if (prev and prev.get("srcSha256") == digest
                    and prev.get("extractorVersion") == EXTRACTOR_VERSION
                    and os.path.exists(out_path)):
                info("inchange depuis la derniere extraction - ignore")
                manifest[fabric_id] = prev
                n_skip += 1
                continue

            stats = new_stats()

            mos = read_export(src, KEEP_CLASSES, stats)

            if not mos:
                warn("  aucun objet utile extrait - archive vide, chiffree "
                     "integralement, ou format XML ?")
                if stats["members_xml"]:
                    warn("  (%d membre(s) XML detecte(s) : reconfigurer "
                         "configExportP en format=json)" % stats["members_xml"])
                n_err += 1
                continue

            classes = {}
            for m in mos:
                classes[m["c"]] = classes.get(m["c"], 0) + 1

            payload = {
                "meta": {
                    "fabric": fabric_id,
                    "srcFile": os.path.basename(src),
                    "srcPath": os.path.abspath(src),
                    "srcSha256": digest,
                    "srcSize": src_size,
                    "srcMtime": src_mtime,
                    "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                 time.gmtime()),
                    "extractorVersion": EXTRACTOR_VERSION,
                    "moCount": len(mos),
                    "classCount": len(classes),
                    "fabricAlias": fabric_alias(mos),
                },
                "mos": mos,
            }

            blob = json.dumps(payload, separators=(",", ":"),
                              ensure_ascii=False).encode("utf-8")

            # gzip.open sans mtime pour que deux extractions identiques
            # produisent deux fichiers identiques (octet pour octet).
            buf = io.BytesIO()
            gz = gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=6, mtime=0)
            try:
                gz.write(blob)
            finally:
                gz.close()
            data = buf.getvalue()

            tmp_path = out_path + ".tmp"
            fh = open(tmp_path, "wb")
            try:
                fh.write(data)
            finally:
                fh.close()
            os.rename(tmp_path, out_path)   # ecriture atomique

            info("%d membres : %d JSON, %d XML, %d autres, %d ecartes - %s lus"
                 % (stats["members_seen"], stats["members_json"],
                    stats["members_xml"], stats["members_other"],
                    stats["members_skipped"], human(stats["bytes_read"])))
            if stats["skipped_roots"]:
                info("racines ecartees (hors arbre uni) : %s"
                     % ", ".join("%s x%d" % kv for kv in
                                 sorted(stats["skipped_roots"].items())[:6]))
            if stats["largest_member"]:
                info("plus gros membre : %s (%s)"
                     % (stats["largest_member_name"], human(stats["largest_member"])))
            info("%d objets retenus, %d classes -> %s (%s)"
                 % (len(mos), len(classes), out_name, human(len(data))))
            if stats["dropped_attrs"]:
                info("attributs sensibles ecartes : %s"
                     % ", ".join(sorted(stats["dropped_attrs"])))

            # Les trous se signalent : c'est ainsi qu'on decouvre qu'un vrai
            # backup contient une construction que l'extracteur ignore.
            gaps = stats["gaps"]
            if gaps["no_template_kept"]:
                warn("  classes UTILES sans gabarit de nommage - objets perdus : %s"
                     % ", ".join("%s x%d" % (k, v) for k, v in
                                 sorted(gaps["no_template_kept"].items())))
                warn("  -> ajouter ces classes a RN_TEMPLATES dans fl_extract.py")
            if gaps["naming_attr"]:
                warn("  gabarit connu mais attribut de nommage absent : %s"
                     % ", ".join("%s x%d" % (k, v) for k, v in
                                 sorted(gaps["naming_attr"].items())))
            lost = gaps["lost_useful"]
            if lost:
                warn("  %d objet(s) UTILE(S) perdu(s) faute de gabarit de nommage :"
                     % sum(lost.values()))
                for k, v in sorted(lost.items(), key=lambda kv: -kv[1]):
                    warn("      %-28s %d" % (k, v))
                warn("  -> ajouter ces classes a RN_TEMPLATES dans fl_extract.py")
            else:
                info("aucun objet utile perdu")

            manifest[fabric_id] = {
                "file": out_name,
                "srcFile": os.path.basename(src),
                "srcSha256": digest,
                "srcSize": src_size,
                "srcMtime": src_mtime,
                "outSha256": hashlib.sha256(data).hexdigest(),
                "outSize": len(data),
                "moCount": len(mos),
                "classes": classes,
                "fabricAlias": payload["meta"]["fabricAlias"],
                "lostUseful": lost,
                "extractorVersion": EXTRACTOR_VERSION,
                "generatedAt": payload["meta"]["generatedAt"],
            }
            n_ok += 1

        except (IOError, OSError, tarfile.TarError) as exc:
            warn("[%s] echec : %s" % (fabric_id, exc))
            n_err += 1
        except MemoryError:
            warn("[%s] memoire insuffisante pour parser l'archive. "
                 "Traiter ce fabric seul avec --only." % fabric_id)
            n_err += 1

    tmp_manifest = manifest_path + ".tmp"
    fh = open(tmp_manifest, "w")
    try:
        json.dump({"generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "extractorVersion": EXTRACTOR_VERSION,
                   "fabrics": manifest},
                  fh, indent=2, sort_keys=True)
    finally:
        fh.close()
    os.rename(tmp_manifest, manifest_path)

    print("\n%d extrait(s), %d inchange(s), %d en echec - %.1f s"
          % (n_ok, n_skip, n_err, time.time() - t0))
    # Convention maison (cf. make_patrimoine_inventory.py) : le .bat lit cette
    # ligne pour savoir quoi rapatrier.
    for fid in sorted(manifest):
        print("RESULT_FILE=%s" % manifest[fid]["file"])
    print("RESULT_FILE=manifest.json")

    if n_ok == 0 and n_skip == 0:
        print("FL-EXTRACT-FAIL")
        return 2

    # --bundle : reunir les .fl.json.gz en un seul JSON chargeable dans le webui.
    # Le resolveur vit dans la page (web/resolve.js) : ce script n'a besoin de
    # RIEN d'autre que lui-meme sur le serveur - aucun import, aucun calcul
    # d'empreintes (l'ancien controle 'verifie N/N' est remplace par des tests
    # de regression cote developpement, tests/regression.mjs).
    if args.bundle:
        fabrics = []
        for fid in sorted(manifest):
            gz = os.path.join(args.out, manifest[fid]["file"])
            if not os.path.exists(gz):
                continue
            with gzip.open(gz, "rb") as fh:
                doc = json.loads(fh.read().decode("utf-8"))
            fabrics.append({"meta": doc["meta"], "mos": doc["mos"]})

        bundle = {
            "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "fabricCount": len(fabrics),
            "fabrics": fabrics,
        }
        blob = json.dumps(bundle, ensure_ascii=False, separators=(",", ":"))
        tmp = args.bundle + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(blob)
        os.rename(tmp, args.bundle)
        print("\nBundle : %d fabrique(s) -> %s (%s)"
              % (len(fabrics), args.bundle, human(len(blob.encode("utf-8")))))
        print("RESULT_FILE=%s" % os.path.basename(args.bundle))
        if _bundle_tmp:
            shutil.rmtree(_bundle_tmp, ignore_errors=True)

    print("FL-EXTRACT-OK")
    return 1 if n_err else 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrompu\n")
        sys.stdout.write("FL-EXTRACT-FAIL\n")
        sys.exit(130)
