#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
resolve.py — le résolveur Fabric Lens.

Lit les fichiers distillés produits par `scripts/remote/fl_extract.py` et
reconstruit, pour un VLAN ou un subnet, le graphe complet des objets ACI qui
le portent — sur tous les fabrics à la fois.

Principe : on n'utilise QUE les relations « forward » présentes dans un backup
(`tDn`, `tnXxxName`). Les relations inverses (`*Rt*`) et les objets dérivés
(`*Def`) n'existent pas dans un export — l'index inverse est donc construit ici,
en inversant les relations forward. On ne branche jamais sur `state`, `tCl`,
`rType` ni `tType` : hors ligne, ces attributs sont absents ou périmés.

Sortie : un graphe {nodes, edges, paths} directement consommable par l'interface,
où chaque nœud porte ses attributs bruts et son DN — pour que l'utilisateur
puisse naviguer d'objet en objet et consulter la config de chacun.
"""

from __future__ import annotations

import gzip
import hashlib
import ipaddress
import json
import os
import re
from collections import defaultdict

# --------------------------------------------------------------------------
# Étiquettes lisibles — l'interface est en français, les termes ACI en anglais
# --------------------------------------------------------------------------

KIND_LABEL = {
    "fvnsEncapBlk": "Encap Block",
    "fvnsVlanInstP": "VLAN Pool",
    "physDomP": "Physical Domain",
    "l3extDomP": "L3 Domain",
    "vmmDomP": "VMM Domain",
    "infraAttEntityP": "AAEP",
    "infraAccPortGrp": "Interface Policy Group",
    "infraAccBndlGrp": "Interface Policy Group",
    "infraAccPortP": "Interface Profile",
    "infraHPortS": "Port Selector",
    "infraPortBlk": "Port Block",
    "infraNodeP": "Switch Profile",
    "infraLeafS": "Leaf Selector",
    "infraNodeBlk": "Node Block",
    "fvTenant": "Tenant",
    "fvCtx": "VRF",
    "fvBD": "Bridge Domain",
    "fvSubnet": "Subnet",
    "fvAp": "Application Profile",
    "fvAEPg": "EPG",
    "fvESg": "ESG",
    "vzBrCP": "Contract",
    "vzSubj": "Subject",
    "vzFilter": "Filter",
    "vzEntry": "Filter Entry",
    "l3extOut": "L3Out",
    "l3extInstP": "External EPG",
    "l3extSubnet": "External Subnet",
    "l2extOut": "L2Out",
    "l2extInstP": "External EPG (L2)",
    # relations : ce sont des objets a part entiere dans le MIT, et
    # l'utilisateur doit pouvoir cliquer dessus pour voir leur config brute
    "infraRsFuncToEpg": "Deploiement AAEP",
    "fvRsPathAtt": "Static Path Binding",
    "infraRsVlanNs": "Domain -> VLAN Pool",
    "infraRsDomP": "AAEP -> Domain",
    "infraRsAttEntP": "IPG -> AAEP",
    "infraRsAccBaseGrp": "Selector -> IPG",
    "infraRsAccPortP": "Switch -> Interface Profile",
    "fvRsBd": "EPG -> BD",
    "fvRsCtx": "BD -> VRF",
    "fvRsDomAtt": "EPG -> Domain",
    "fvRsProv": "Provide",
    "fvRsCons": "Consume",
    "fvRsBDToOut": "BD -> L3Out",
    "l3extRsEctx": "L3Out -> VRF",
    "vzRsSubjFiltAtt": "Subject -> Filter",
    "infraFexP": "FEX Profile",
    "infraFexBndlGrp": "FEX Policy Group",
    "infraLeafS": "Leaf Selector",
    "infraGeneric": "AAEP Generic",
    "l3extRsPathL3OutAtt": "L3Out Interface",
    "l3extLIfP": "Logical Interface Profile",
    "l3extLNodeP": "Logical Node Profile",
    "bgpPeerP": "BGP Peer",
    "ospfExtP": "OSPF",
    "bgpExtP": "BGP",
    "eigrpExtP": "EIGRP",
}

# Les rôles d'un l3extSubnet. Sécurité et routage sont deux axes ORTHOGONAUX :
# un même préfixe porte souvent les deux, et l'interface doit le montrer sans
# obliger à lire une légende.
SCOPE_ROLE = {
    "import-security": ("securite", "External Subnets for the External EPG",
                        "classifie le trafic entrant dans cet ext-EPG"),
    "shared-security": ("securite", "Shared Security Import",
                        "classifie le trafic inter-VRF"),
    "export-rtctrl": ("routage", "Advertised Externally",
                      "le prefixe est annonce vers l'exterieur"),
    "import-rtctrl": ("routage", "Import Route Control",
                      "filtre ce qui est accepte de l'exterieur"),
    "shared-rtctrl": ("routage", "Shared Route Control",
                      "fuite de route inter-VRF"),
}


def split_rns(dn):
    """Découpe un DN en RN en respectant les crochets.

    `rsplit("/")` naïf casse sur `pathep-[eth1/15]` et renvoie `15]`.
    """
    parts, depth, cur = [], 0, []
    for ch in dn:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == "/" and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


def last_rn(dn):
    return split_rns(dn)[-1] if dn else ""


def path_label(tdn):
    """`topology/pod-1/protpaths-101-102/pathep-[SRV-VPC.IPG]`
       -> `101-102 . SRV-VPC.IPG`"""
    if not tdn:
        return ""
    parts = split_rns(tdn)
    node = ""
    port = last_rn(tdn)
    for p in parts:
        if p.startswith("protpaths-"):
            node = "vPC " + p[len("protpaths-"):]
        elif p.startswith("paths-"):
            node = "leaf " + p[len("paths-"):]
    m = re.match(r"pathep-\[(.*)\]$", port)
    if m:
        port = m.group(1)
    return ("%s . %s" % (node, port)) if node else port


def parse_path_tdn(tdn):
    """Décompose un tDn de chemin en cible physique exploitable.

    `topology/pod-1/paths-101/pathep-[eth1/10]`
        -> {kind:'access', pod:'1', nodes:['101'], port:'eth1/10'}
    `topology/pod-1/protpaths-101-102/pathep-[SRV-VPC.IPG]`
        -> {kind:'vpc', pod:'1', nodes:['101','102'], ipg:'SRV-VPC.IPG'}

    C'est ce qui permet de nommer la ou les leaf ET l'interface sans deviner :
    l'information est déjà dans le DN, il suffit de la lire correctement.
    """
    if not tdn:
        return None
    parts = split_rns(tdn)
    out = {"tDn": tdn, "kind": None, "pod": None, "nodes": [], "port": None,
           "ipg": None, "fex": None}
    for p in parts:
        if p.startswith("pod-"):
            out["pod"] = p[4:]
        elif p.startswith("protpaths-"):
            out["kind"] = "vpc"
            out["nodes"] = p[len("protpaths-"):].split("-")
        elif p.startswith("paths-"):
            out["kind"] = "access"
            out["nodes"] = [p[len("paths-"):]]
        elif p.startswith("extpaths-"):
            out["fex"] = p[len("extpaths-"):]
        elif p.startswith("pathep-["):
            inner = p[len("pathep-["):]
            if inner.endswith("]"):
                inner = inner[:-1]
            # Sur un vPC, la cible du pathep est le NOM de l'IPG, pas un port.
            if out["kind"] == "vpc":
                out["ipg"] = inner
            else:
                out["port"] = inner
    if not out["kind"]:
        return None
    return out


def path_target_label(t):
    if not t:
        return "?"
    who = "leaf " + "+".join(t["nodes"]) if t["nodes"] else "?"
    if t.get("fex"):
        who += " fex " + t["fex"]
    what = t.get("port") or (("IPG " + t["ipg"]) if t.get("ipg") else "?")
    return "%s . %s" % (who, what)


def rn_parent(dn):
    """DN du parent, en respectant les crochets (qui peuvent contenir des /)."""
    depth = 0
    for i in range(len(dn) - 1, -1, -1):
        c = dn[i]
        if c == "]":
            depth += 1
        elif c == "[":
            depth -= 1
        elif c == "/" and depth == 0:
            return dn[:i]
    return ""


def encap_num(encap):
    """'vlan-2110' -> 2110. None si ce n'est pas un VLAN."""
    if not encap:
        return None
    m = re.search(r"(\d+)\s*$", encap)
    return int(m.group(1)) if m else None


class Fabric:
    """Un fabric chargé en mémoire, avec ses index."""

    def __init__(self, path):
        with gzip.open(path, "rb") as fh:
            doc = json.loads(fh.read().decode("utf-8"))
        self.meta = doc["meta"]
        self.id = self.meta["fabric"]
        self.mos = doc["mos"]

        self.by_dn = {}
        self.by_class = defaultdict(list)
        for m in self.mos:
            self.by_dn[m["dn"]] = m
            self.by_class[m["c"]].append(m)

        # Index inverse : cible d'une relation -> [relations qui la visent].
        # C'est ce qui remplace les *Rt* absents des backups.
        self.rev = defaultdict(list)
        for m in self.mos:
            tdn = m["a"].get("tDn")
            if tdn:
                self.rev[tdn].append(m)

        # Index par nom pour les relations tnXxxName, qui pointent par NOM
        # dans la portée du tenant — pas par DN.
        self.by_tenant_name = defaultdict(dict)
        for cls in ("fvBD", "fvCtx", "vzBrCP", "l3extOut", "vzFilter",
                    "vzCPIf", "vzTaboo", "vzOOBBrCP"):
            for m in self.by_class.get(cls, []):
                tn = self.tenant_of(m["dn"])
                name = m["a"].get("name")
                if tn and name:
                    self.by_tenant_name[(tn, cls)][name] = m

    @staticmethod
    def tenant_of(dn):
        m = re.match(r"(uni/tn-[^/]+)", dn)
        return m.group(1) if m else None

    def label(self, mo):
        a = mo["a"]
        cls = mo["c"]

        # Cas particuliers d'abord : pour ces classes, l'attribut `name` existe
        # mais ne dit rien d'utile — c'est la plage ou la cible qui compte.
        if cls == "fvnsEncapBlk":
            return "%s - %s" % (a.get("from", "?"), a.get("to", "?"))
        if cls == "infraPortBlk":
            rng = "eth%s/%s" % (a.get("fromCard", "1"), a.get("fromPort", "?"))
            if a.get("toPort") and a["toPort"] != a.get("fromPort"):
                rng += "-%s" % a["toPort"]
            return rng
        if cls == "infraNodeBlk":
            rng = a.get("from_", "?")
            if a.get("to_") and a["to_"] != a.get("from_"):
                rng += "-%s" % a["to_"]
            # le switch profile est 2 niveaux au-dessus : nprof-X/leaves-Y/nodeblk-Z
            prof = last_rn(rn_parent(rn_parent(mo["dn"])))
            if prof.startswith("nprof-"):
                return "leaf %s  (%s)" % (rng, prof[len("nprof-"):])
            return "leaf " + rng
        if cls in ("fvRsPathAtt", "l3extRsPathL3OutAtt"):
            # tDn = topology/pod-1/protpaths-101-102/pathep-[IPG] ; on veut la
            # partie lisible, sans se faire couper par le / dans les crochets.
            return path_label(a.get("tDn", ""))

        for k in ("name", "ip", "id"):
            if a.get(k):
                return a[k]
        if a.get("tDn"):
            return last_rn(a["tDn"])
        for k in sorted(a):
            if k.startswith("tn") and a[k]:
                return a[k]
        return last_rn(mo["dn"])

    def node(self, mo, kind=None, note=None):
        return {
            "dn": mo["dn"],
            "cls": mo["c"],
            "clsLabel": KIND_LABEL.get(mo["c"], mo["c"]),
            "label": self.label(mo),
            "kind": kind or mo["c"],
            "note": note,
            "attrs": mo["a"],
        }

    # -- résolution par nom, portée tenant --------------------------------
    def in_tenant(self, dn, cls, name):
        tn = self.tenant_of(dn)
        if not tn or not name:
            return None
        hit = self.by_tenant_name.get((tn, cls), {}).get(name)
        if hit:
            return hit
        # repli : le tenant `common` est visible depuis tous les tenants
        return self.by_tenant_name.get(("uni/tn-common", cls), {}).get(name)


class Graph:
    """Accumulateur de nœuds et d'arêtes, dédupliqué par DN."""

    def __init__(self):
        self.nodes = {}
        self.edges = []
        self._seen = set()

    def add(self, node):
        dn = node["dn"]
        if dn not in self.nodes:
            self.nodes[dn] = node
        elif node.get("note") and not self.nodes[dn].get("note"):
            self.nodes[dn]["note"] = node["note"]
        return dn

    def link(self, src, dst, rel, label=None):
        if not src or not dst:
            return
        key = (src, dst, rel)
        if key in self._seen:
            return
        self._seen.add(key)
        self.edges.append({"from": src, "to": dst, "rel": rel,
                           "label": label or rel})


# ==========================================================================
# Chaîne ACCESS POLICIES : de l'encap block jusqu'au port physique
# ==========================================================================

def resolve_access_chain(fab, vlan, g):
    """Remonte encap block -> pool -> domain -> AAEP -> IPG -> ports -> leaves.

    Retourne la liste des DN d'encap blocks qui couvrent ce VLAN.
    """
    roots = []
    for blk in fab.by_class.get("fvnsEncapBlk", []):
        lo = encap_num(blk["a"].get("from"))
        hi = encap_num(blk["a"].get("to"))
        if lo is None or hi is None or not (lo <= vlan <= hi):
            continue
        blk_dn = g.add(fab.node(blk, "encapBlk",
                                "bloc %s-%s (%s)" % (blk["a"].get("from"),
                                                     blk["a"].get("to"),
                                                     blk["a"].get("allocMode", "?"))))
        roots.append(blk_dn)

        pool = fab.by_dn.get(rn_parent(blk["dn"]))
        if not pool:
            continue
        pool_dn = g.add(fab.node(pool, "vlanPool"))
        g.link(blk_dn, pool_dn, "contenu-dans", "appartient au pool")

        # domaines qui référencent ce pool (via infraRsVlanNs.tDn)
        for rs in fab.rev.get(pool["dn"], []):
            if rs["c"] != "infraRsVlanNs":
                continue
            dom = fab.by_dn.get(rn_parent(rs["dn"]))
            if not dom:
                continue
            dom_dn = g.add(fab.node(dom, "domain"))
            g.link(pool_dn, dom_dn, "utilise-par", "pool utilise par le domaine")

            # AAEP qui référencent ce domaine (via infraRsDomP.tDn)
            for rs2 in fab.rev.get(dom["dn"], []):
                if rs2["c"] != "infraRsDomP":
                    continue
                aaep = fab.by_dn.get(rn_parent(rs2["dn"]))
                if not aaep:
                    continue
                aaep_dn = g.add(fab.node(aaep, "aaep"))
                g.link(dom_dn, aaep_dn, "utilise-par", "domaine attache a l'AAEP")
                resolve_aaep(fab, aaep, vlan, g, aaep_dn)
    return roots


def resolve_aaep(fab, aaep, vlan, g, aaep_dn):
    """Depuis un AAEP : déploiement direct d'EPG, puis — SEULEMENT si le VLAN
    y est réellement déployé — les IPG, ports et leaves.

    LE FILTRE EST LE POINT CENTRAL. Un VLAN pool partagé porte des centaines
    d'encaps ; son domain est rattaché à plusieurs AAEP, chacun à des dizaines
    d'IPG. Sans ce filtre, chercher UN VLAN déroulait toute l'infrastructure
    access du domain — des centaines d'objets sans rapport avec la recherche
    (constaté sur une fabrique réelle : l'écran devenait illisible).

    La sémantique ACI qui justifie le filtre : quand le VLAN est déployé VIA
    l'AAEP (infraRsFuncToEpg), il atterrit sur tous les ports des IPG
    rattachés — les dérouler est alors une information vraie. Quand il ne
    l'est pas (pool seulement, ou déploiement par static path), les vrais
    ports viennent du static path binding, déjà résolus précisément par
    link_path_to_hardware. Le fan-out serait du bruit.
    """
    # 1. Déploiement direct de l'EPG par l'AAEP (infraRsFuncToEpg porte l'encap)
    deployed_here = False
    for f in fab.by_class.get("infraRsFuncToEpg", []):
        if not f["dn"].startswith(aaep["dn"] + "/"):
            continue
        if encap_num(f["a"].get("encap")) != vlan:
            continue
        deployed_here = True
        f_dn = g.add(fab.node(f, "aaepDeploy",
                              "deploiement AAEP - encap %s, mode %s"
                              % (f["a"].get("encap"), f["a"].get("mode", "?"))))
        g.link(aaep_dn, f_dn, "deploie", "l'AAEP deploie un EPG")
        epg = fab.by_dn.get(f["a"].get("tDn", ""))
        if epg:
            g.link(f_dn, g.add(fab.node(epg, "epg")), "vers-epg", "vers l'EPG")

    # 2. IPG qui référencent cet AAEP — seulement si le VLAN y est déployé
    n_ipg = 0
    for rs in fab.rev.get(aaep["dn"], []):
        if rs["c"] != "infraRsAttEntP":
            continue
        ipg = fab.by_dn.get(rn_parent(rs["dn"]))
        if not ipg:
            continue
        n_ipg += 1
        if not deployed_here:
            continue          # compté, pas déroulé : le VLAN n'arrive pas ici
        lag = ipg["a"].get("lagT")
        kindnote = {"node": "vPC", "link": "Port-Channel"}.get(lag, "acces")
        ipg_dn = g.add(fab.node(ipg, "ipg", kindnote))
        g.link(aaep_dn, ipg_dn, "utilise-par", "AAEP utilise par l'IPG")
        resolve_ipg_ports(fab, ipg, g, ipg_dn)

    # L'information n'est pas perdue : l'AAEP dit combien d'IPG il porte,
    # et pourquoi ils ne sont pas déroulés.
    if n_ipg and not deployed_here:
        node = g.nodes.get(aaep_dn)
        if node is not None and not node.get("note"):
            node["note"] = ("%d IPG rattache(s) - non deroules : ce VLAN "
                            "n'est pas deploye via cet AAEP" % n_ipg)


def resolve_ipg_ports(fab, ipg, g, ipg_dn):
    """IPG -> port selector -> port blocks -> interface profile -> leaves."""
    for rs in fab.rev.get(ipg["dn"], []):
        if rs["c"] != "infraRsAccBaseGrp":
            continue
        hports_dn = rn_parent(rs["dn"])
        hports = fab.by_dn.get(hports_dn)
        prof_dn = rn_parent(hports_dn)
        prof = fab.by_dn.get(prof_dn)
        if not hports or not prof:
            continue

        sel_dn = g.add(fab.node(hports, "portSelector"))
        g.link(ipg_dn, sel_dn, "selectionne-par", "IPG utilise par le selecteur")

        ports = []
        for blk in fab.by_class.get("infraPortBlk", []):
            if not blk["dn"].startswith(hports_dn + "/"):
                continue
            a = blk["a"]
            rng = "eth%s/%s" % (a.get("fromCard", "1"), a.get("fromPort", "?"))
            if a.get("toPort") and a.get("toPort") != a.get("fromPort"):
                rng += "-%s" % a["toPort"]
            ports.append(rng)
            blk_dn = g.add(fab.node(blk, "portBlk", rng))
            g.link(sel_dn, blk_dn, "contient", "ports")

        iprof_dn = g.add(fab.node(prof, "ifProfile"))
        g.link(sel_dn, iprof_dn, "contenu-dans", "dans l'interface profile")

        # switch profiles qui référencent cet interface profile
        for rs2 in fab.rev.get(prof_dn, []):
            if rs2["c"] != "infraRsAccPortP":
                continue
            nprof_dn_s = rn_parent(rs2["dn"])
            nprof = fab.by_dn.get(nprof_dn_s)
            if not nprof:
                continue
            sp_dn = g.add(fab.node(nprof, "switchProfile"))
            g.link(iprof_dn, sp_dn, "utilise-par", "utilise par le switch profile")
            for nb in fab.by_class.get("infraNodeBlk", []):
                if not nb["dn"].startswith(nprof_dn_s + "/"):
                    continue
                a = nb["a"]
                rng = a.get("from_", "?")
                if a.get("to_") and a["to_"] != a.get("from_"):
                    rng += "-%s" % a["to_"]
                nb_dn = g.add(fab.node(nb, "nodeBlk", "leaf " + rng))
                g.link(sp_dn, nb_dn, "contient", "leaves")


# ==========================================================================
# Chaîne LOGIQUE : EPG -> BD -> VRF -> subnets, et les contrats
# ==========================================================================

def resolve_epg(fab, epg, g, note=None, vlan=None):
    """EPG -> AP -> tenant, BD, VRF, subnets, domaines, contrats.

    `vlan` sert uniquement a marquer les static paths qui portent le VLAN
    recherche. On affiche TOUS les bindings de l'EPG - masquer les autres
    cacherait qu'un meme EPG porte plusieurs encapsulations - mais on dit
    lesquels repondent a la question posee.
    """
    epg_dn = g.add(fab.node(epg, "epg", note))

    ap = fab.by_dn.get(rn_parent(epg["dn"]))
    if ap and ap["c"] == "fvAp":
        ap_dn = g.add(fab.node(ap, "ap"))
        g.link(epg_dn, ap_dn, "contenu-dans", "dans l'application profile")
        tn = fab.by_dn.get(rn_parent(ap["dn"]))
        if tn:
            g.link(ap_dn, g.add(fab.node(tn, "tenant")), "contenu-dans", "dans le tenant")

    # EPG -> BD (par NOM, portée tenant)
    for rsbd in fab.by_class.get("fvRsBd", []):
        if rn_parent(rsbd["dn"]) != epg["dn"]:
            continue
        bd = fab.in_tenant(epg["dn"], "fvBD", rsbd["a"].get("tnFvBDName"))
        if not bd:
            continue
        bd_dn = g.add(fab.node(bd, "bd"))
        g.link(epg_dn, bd_dn, "vers-bd", "EPG rattache au BD")
        resolve_bd(fab, bd, g, bd_dn)

    # EPG -> domaine
    for rsd in fab.by_class.get("fvRsDomAtt", []):
        if rn_parent(rsd["dn"]) != epg["dn"]:
            continue
        dom = fab.by_dn.get(rsd["a"].get("tDn", ""))
        if dom:
            g.link(epg_dn, g.add(fab.node(dom, "domain")), "vers-domaine", "domaine associe")

    # EPG -> static path bindings
    for rsp in fab.by_class.get("fvRsPathAtt", []):
        if rn_parent(rsp["dn"]) != epg["dn"]:
            continue
        a = rsp["a"]
        hit = vlan is not None and encap_num(a.get("encap")) == vlan
        tgt = parse_path_tdn(a.get("tDn"))
        p_dn = g.add(fab.node(rsp, "staticPath",
                              "encap %s sur %s, mode %s%s"
                              % (a.get("encap"), path_target_label(tgt),
                                 a.get("mode", "?"),
                                 "" if hit else "  (autre encap)")))
        g.nodes[p_dn]["matchesQuery"] = bool(hit)
        g.nodes[p_dn]["target"] = tgt
        g.link(epg_dn, p_dn, "static-port",
               "static path binding" if hit else "autre encapsulation")
        # Rattacher le binding a l'IPG reel (vPC) et aux leaves nommees dans le
        # tDn : c'est ce qui donne "l'IPG, la ou les leaf, et l'interface".
        if tgt:
            link_path_to_hardware(fab, tgt, g, p_dn)

    resolve_contracts(fab, epg["dn"], g, epg_dn)
    return epg_dn


def link_path_to_hardware(fab, tgt, g, path_node_dn):
    """Depuis une cible de chemin, retrouve l'IPG, les leaves et les ports.

    Sur un vPC le tDn nomme directement l'IPG : on le resout dans les deux
    familles de policy group. Sur un port d'acces on retrouve le port block qui
    couvre ce port sur ce noeud. C'est l'information que l'utilisateur reclame
    explicitement : « l'IPG et la ou les leaf et l'interface ».
    """
    # 1. l'IPG, nomme dans le tDn quand c'est un vPC ou un port-channel
    if tgt.get("ipg"):
        for cls in ("infraAccBndlGrp", "infraAccPortGrp"):
            for ipg in fab.by_class.get(cls, []):
                if ipg["a"].get("name") == tgt["ipg"]:
                    lag = ipg["a"].get("lagT")
                    kindnote = {"node": "vPC", "link": "Port-Channel"}.get(lag, "acces")
                    ipg_dn = g.add(fab.node(ipg, "ipg", kindnote))
                    g.link(path_node_dn, ipg_dn, "vers-ipg", "cible l'IPG")
                    resolve_ipg_ports(fab, ipg, g, ipg_dn)

    # 2. les leaves nommees dans le tDn -> node block correspondant
    for node_id in tgt.get("nodes") or []:
        for nb in fab.by_class.get("infraNodeBlk", []):
            a = nb["a"]
            lo, hi = a.get("from_"), a.get("to_") or a.get("from_")
            try:
                if not (int(lo) <= int(node_id) <= int(hi)):
                    continue
            except (TypeError, ValueError):
                continue
            nb_dn = g.add(fab.node(nb, "nodeBlk", "leaf " + str(node_id)))
            g.link(path_node_dn, nb_dn, "vers-leaf", "leaf " + str(node_id))

    # 3. le port physique nomme dans le tDn -> port block, PUIS remontee vers
    #    l'IPG qui programme reellement ce port.
    #
    #    C'est la troisieme route vers l'IPG, et souvent la seule qui aboutit :
    #      - route A : AAEP -> infraRsAttEntP -> IPG   (echoue si aucun IPG
    #        n'est rattache a cet AAEP, ce qui arrive)
    #      - route B : le tDn d'un vPC nomme l'IPG     (n'existe que sur un vPC)
    #      - route C : port -> port selector -> infraRsAccBaseGrp -> IPG  <-- ici
    #
    #    Le port block seul ne suffit pas : plusieurs leaves ont un eth1/1.
    #    On ne retient donc un selecteur QUE si son interface profile est
    #    rattache a un switch profile dont un node block couvre ce noeud.
    port = tgt.get("port")
    nodes = [str(n) for n in (tgt.get("nodes") or [])]
    if port:
        m = re.match(r"eth(\d+)/(\d+)$", port)
        if m:
            card, num = m.group(1), int(m.group(2))
            for blk in fab.by_class.get("infraPortBlk", []):
                a = blk["a"]
                if a.get("fromCard") != card:
                    continue
                try:
                    lo = int(a.get("fromPort"))
                    hi = int(a.get("toPort") or a.get("fromPort"))
                except (TypeError, ValueError):
                    continue
                if not (lo <= num <= hi):
                    continue

                hports_dn = rn_parent(blk["dn"])
                prof_dn = rn_parent(hports_dn)
                if nodes and not profile_covers_nodes(fab, prof_dn, nodes):
                    continue          # ce eth1/1 est sur une autre leaf

                b_dn = g.add(fab.node(blk, "portBlk", port))
                g.link(path_node_dn, b_dn, "vers-port", port)

                for rs in fab.by_class.get("infraRsAccBaseGrp", []):
                    if rn_parent(rs["dn"]) != hports_dn:
                        continue
                    ipg = fab.by_dn.get(rs["a"].get("tDn", ""))
                    if not ipg:
                        continue
                    lag = ipg["a"].get("lagT")
                    kindnote = {"node": "vPC", "link": "Port-Channel"}.get(lag, "acces")
                    ipg_dn = g.add(fab.node(ipg, "ipg", kindnote))
                    g.link(b_dn, ipg_dn, "vers-ipg", "port programme par l'IPG")
                    g.link(path_node_dn, ipg_dn, "vers-ipg", "IPG de ce port")
                    resolve_ipg_ports(fab, ipg, g, ipg_dn)


def profile_covers_nodes(fab, iface_profile_dn, node_ids):
    """L'interface profile est-il applique a au moins un de ces noeuds ?

    infraAccPortP <- infraRsAccPortP(tDn) <- infraNodeP -> infraLeafS -> infraNodeBlk
    """
    for rs in fab.rev.get(iface_profile_dn, []):
        if rs["c"] != "infraRsAccPortP":
            continue
        nprof_dn = rn_parent(rs["dn"])
        for nb in fab.by_class.get("infraNodeBlk", []):
            if not nb["dn"].startswith(nprof_dn + "/"):
                continue
            a = nb["a"]
            try:
                lo = int(a.get("from_"))
                hi = int(a.get("to_") or a.get("from_"))
            except (TypeError, ValueError):
                continue
            for nid in node_ids:
                try:
                    if lo <= int(nid) <= hi:
                        return True
                except (TypeError, ValueError):
                    continue
    return False


def resolve_bd(fab, bd, g, bd_dn):
    """BD -> VRF, subnets, L3Outs associés."""
    for rsctx in fab.by_class.get("fvRsCtx", []):
        if rn_parent(rsctx["dn"]) != bd["dn"]:
            continue
        vrf = fab.in_tenant(bd["dn"], "fvCtx", rsctx["a"].get("tnFvCtxName"))
        if vrf:
            g.link(bd_dn, g.add(fab.node(vrf, "vrf")), "vers-vrf", "BD dans le VRF")

    for sub in fab.by_class.get("fvSubnet", []):
        if not sub["dn"].startswith(bd["dn"] + "/"):
            continue
        s_dn = g.add(fab.node(sub, "subnet",
                              "scope %s" % sub["a"].get("scope", "?")))
        g.link(bd_dn, s_dn, "contient", "gateway")

    for rso in fab.by_class.get("fvRsBDToOut", []):
        if rn_parent(rso["dn"]) != bd["dn"]:
            continue
        out = fab.in_tenant(bd["dn"], "l3extOut", rso["a"].get("tnL3extOutName"))
        if out:
            g.link(bd_dn, g.add(fab.node(out, "l3out")), "vers-l3out", "BD annonce via")


def resolve_contracts(fab, owner_dn, g, owner_node_dn):
    """Contrats fournis/consommés par un EPG, ESG ou ext-EPG.

    Les classes porteuses sont ENUMEREES explicitement : l3extInstP herite de
    extnw:EPg et non de fv:EPg, et mgmtInstP ne porte NI fvRsProv NI fvRsCons
    (l'out-of-band a son propre graphe, parallele). Deriver l'ensemble par
    sous-classement donnerait un resultat faux.
    """
    for cls, direction, attr in (("fvRsProv", "provide", "tnVzBrCPName"),
                                 ("fvRsCons", "consume", "tnVzBrCPName"),
                                 ("fvRsIntraEpg", "intra-epg", "tnVzBrCPName")):
        for rel in fab.by_class.get(cls, []):
            if rn_parent(rel["dn"]) != owner_dn:
                continue
            ctr = fab.in_tenant(owner_dn, "vzBrCP", rel["a"].get(attr))
            if not ctr:
                continue
            c_dn = g.add(fab.node(ctr, "contract"))
            g.link(owner_node_dn, c_dn, direction, direction.upper())
            resolve_contract_detail(fab, ctr, g, c_dn)


def resolve_contract_detail(fab, ctr, g, c_dn):
    """Contract -> subjects -> filters -> entries."""
    for subj in fab.by_class.get("vzSubj", []):
        if rn_parent(subj["dn"]) != ctr["dn"]:
            continue
        s_dn = g.add(fab.node(subj, "subject"))
        g.link(c_dn, s_dn, "contient", "subject")
        for rf in fab.by_class.get("vzRsSubjFiltAtt", []):
            if rn_parent(rf["dn"]) != subj["dn"]:
                continue
            flt = fab.in_tenant(ctr["dn"], "vzFilter", rf["a"].get("tnVzFilterName"))
            if not flt:
                continue
            f_dn = g.add(fab.node(flt, "filter"))
            g.link(s_dn, f_dn, "vers-filter", "filter")
            for ent in fab.by_class.get("vzEntry", []):
                if not ent["dn"].startswith(flt["dn"] + "/"):
                    continue
                a = ent["a"]
                desc = a.get("prot", "")
                if a.get("dFromPort") and a["dFromPort"] != "unspecified":
                    desc += "/%s" % a["dFromPort"]
                    if a.get("dToPort") and a["dToPort"] != a["dFromPort"]:
                        desc += "-%s" % a["dToPort"]
                g.link(f_dn, g.add(fab.node(ent, "entry", desc or None)),
                       "contient", "entry")


# ==========================================================================
# Recherche VLAN, tous fabrics
# ==========================================================================

def find_vlan_users(fab, vlan, g):
    """Tous les EPG qui utilisent ce VLAN, avec TOUS leurs modes de deploiement.

    Un EPG peut etre deploye des DEUX facons a la fois - static path binding ET
    via l'AAEP. C'est frequent, souvent involontaire, et c'est precisement ce
    qu'un ingenieur doit voir. Ne retenir que le premier mode rencontre serait
    un mensonge : verifie sur des backups reels, 3 fabrics sur 5 sont dans ce
    cas pour le VLAN 100.
    """
    epgs = {}

    def bucket(epg):
        return epgs.setdefault(epg["dn"], {
            "epg": epg, "static": [], "aaep": [],
        })

    for rsp in fab.by_class.get("fvRsPathAtt", []):
        if encap_num(rsp["a"].get("encap")) != vlan:
            continue
        epg = fab.by_dn.get(rn_parent(rsp["dn"]))
        if epg and epg["c"] in ("fvAEPg", "fvESg"):
            bucket(epg)["static"].append(rsp["dn"])

    for f in fab.by_class.get("infraRsFuncToEpg", []):
        if encap_num(f["a"].get("encap")) != vlan:
            continue
        epg = fab.by_dn.get(f["a"].get("tDn", ""))
        if epg:
            bucket(epg)["aaep"].append(f["dn"])

    for dn, b in epgs.items():
        ns, na = len(b["static"]), len(b["aaep"])
        if ns and na:
            b["mode"] = "both"
            b["note"] = ("deploye DES DEUX FACONS - %d static path(s) ET %d "
                         "deploiement(s) AAEP" % (ns, na))
        elif ns:
            b["mode"] = "static-port"
            b["note"] = "deploiement static port (%d binding%s)" % (ns, "s" if ns > 1 else "")
        else:
            b["mode"] = "aaep"
            b["note"] = "deploiement via AAEP (%d)" % na
    return epgs


def find_vlan_transit(fab, vlan, g):
    """Le VLAN porte-t-il une interface de L3Out ? (peering routé)

    Un VLAN dans un fabric n'est pas forcément un VLAN client. Il peut être un
    TRANSIT : une sous-interface de L3Out (`l3extRsPathL3OutAtt` avec
    `ifInstT=sub-interface` ou `ext-svi`) qui porte un peering BGP / OSPF /
    EIGRP vers un équipement externe — firewall, routeur, hyperviseur NSX.
    Vérifié sur des backups réels : `vlan-900`, sub-interface 192.168.200.1/30
    sur leaf 101 eth1/12, avec des `bgpPeerP`.

    Cette distinction change complètement la lecture de l'écran : un VLAN
    client aboutit sur un EPG, un VLAN de transit aboutit hors du fabric.
    """
    found = []
    for rp in fab.by_class.get("l3extRsPathL3OutAtt", []):
        a = rp["a"]
        if encap_num(a.get("encap")) != vlan:
            continue
        tgt = parse_path_tdn(a.get("tDn"))
        p_dn = g.add(fab.node(rp, "l3outPath",
                              "%s %s sur %s"
                              % (a.get("ifInstT", "?"), a.get("addr", ""),
                                 path_target_label(tgt))))
        g.nodes[p_dn]["target"] = tgt
        g.nodes[p_dn]["matchesQuery"] = True
        if tgt:
            link_path_to_hardware(fab, tgt, g, p_dn)

        lifp = fab.by_dn.get(rn_parent(rp["dn"]))
        if not lifp:
            found.append(p_dn)
            continue
        lifp_dn = g.add(fab.node(lifp, "l3outIfProfile"))
        g.link(lifp_dn, p_dn, "contient", "interface")

        lnodep = fab.by_dn.get(rn_parent(lifp["dn"]))
        if not lnodep:
            found.append(p_dn)
            continue
        lnodep_dn = g.add(fab.node(lnodep, "l3outNodeProfile"))
        g.link(lnodep_dn, lifp_dn, "contient", "logical interface profile")

        out_mo = fab.by_dn.get(rn_parent(lnodep["dn"]))
        if not out_mo:
            found.append(p_dn)
            continue
        o_dn = g.add(fab.node(out_mo, "l3out"))
        g.link(o_dn, lnodep_dn, "contient", "logical node profile")

        # protocoles de routage portes par ce L3Out
        protos = []
        for cls, name in (("ospfExtP", "OSPF"), ("bgpExtP", "BGP"),
                          ("eigrpExtP", "EIGRP")):
            for pr in fab.by_class.get(cls, []):
                if rn_parent(pr["dn"]) == out_mo["dn"]:
                    protos.append(name)
                    g.link(o_dn, g.add(fab.node(pr, "routingProto", name)),
                           "active", name)
        for peer in fab.by_class.get("bgpPeerP", []):
            if peer["dn"].startswith(lnodep["dn"] + "/") or \
                    peer["dn"].startswith(lifp["dn"] + "/"):
                protos.append("BGP")
                g.link(p_dn, g.add(fab.node(peer, "bgpPeer",
                                            "peer " + peer["a"].get("addr", "?"))),
                       "peer", "voisin BGP")
        g.nodes[p_dn]["protocols"] = sorted(set(protos))

        # VRF du L3Out, et ext-EPG qu'il porte
        for rse in fab.by_class.get("l3extRsEctx", []):
            if rn_parent(rse["dn"]) != out_mo["dn"]:
                continue
            vrf = fab.in_tenant(out_mo["dn"], "fvCtx", rse["a"].get("tnFvCtxName"))
            if vrf:
                g.link(o_dn, g.add(fab.node(vrf, "vrf")), "vers-vrf", "L3Out dans le VRF")
        for inst in fab.by_class.get("l3extInstP", []):
            if rn_parent(inst["dn"]) != out_mo["dn"]:
                continue
            i_dn = g.add(fab.node(inst, "extEpg"))
            g.link(o_dn, i_dn, "contient", "external EPG")
            resolve_contracts(fab, inst["dn"], g, i_dn)
            for sub in fab.by_class.get("l3extSubnet", []):
                if rn_parent(sub["dn"]) != inst["dn"]:
                    continue
                scopes = [s for s in (sub["a"].get("scope") or "").split(",") if s]
                s_dn = g.add(fab.node(sub, "l3extSubnet", ", ".join(scopes)))
                g.nodes[s_dn]["roles"] = [
                    {"scope": s, "axis": SCOPE_ROLE.get(s, ("?", s, ""))[0],
                     "gui": SCOPE_ROLE.get(s, ("?", s, ""))[1],
                     "sens": SCOPE_ROLE.get(s, ("?", s, ""))[2]} for s in scopes]
                g.link(i_dn, s_dn, "contient", "prefixe externe")

        found.append(p_dn)
    return found


def resolve_vlan(fabrics, vlan):
    out = {"query": {"type": "vlan", "value": vlan}, "fabrics": []}
    for fab in fabrics:
        g = Graph()
        blocks = resolve_access_chain(fab, vlan, g)
        transit = find_vlan_transit(fab, vlan, g)
        users = find_vlan_users(fab, vlan, g)
        for dn, b in sorted(users.items()):
            epg_dn = resolve_epg(fab, b["epg"], g, b["note"], vlan=vlan)
            # Le mode est une DONNEE structuree, pas une phrase a analyser :
            # l'interface ne doit jamais avoir a deviner par regex sur `note`.
            g.nodes[epg_dn]["deployment"] = {
                "mode": b["mode"],
                "staticPaths": b["static"],
                "aaepDeploys": b["aaep"],
                "conflict": b["mode"] == "both",
            }

        # Le ROLE du VLAN dans ce fabric : client (aboutit sur un EPG),
        # transit (porte un peering routé et sort du fabric), ou les deux.
        roles = []
        if users:
            roles.append("client")
        if transit:
            roles.append("transit")
        protos = sorted({p for dn in transit
                         for p in (g.nodes[dn].get("protocols") or [])})

        if users or transit:
            status = "deployed"
            bits = []
            if users:
                nboth = sum(1 for b in users.values() if b["mode"] == "both")
                bits.append("%d EPG client%s" % (len(users), "s" if len(users) > 1 else ""))
                if nboth:
                    bits.append("%d en DOUBLE deploiement" % nboth)
            if transit:
                bits.append("%d interface%s de L3Out%s"
                            % (len(transit), "s" if len(transit) > 1 else "",
                               (" (" + ", ".join(protos) + ")") if protos else ""))
            summary = " - ".join(bits)
        elif blocks:
            status, summary = "pool-only", "present dans un pool, aucun EPG ne l'utilise"
            roles = []
        else:
            status, summary = "absent", "aucune correspondance"
            roles = []

        # Diagnostic sur l'IPG. L'absence d'IPG n'est pas un silence : c'est
        # un fait de configuration. Un VLAN deploye via un AAEP auquel aucun
        # interface policy group n'est rattache n'atteint AUCUNE interface
        # physique - il est configure mais inerte. Verifie sur LAB-RECON.
        warnings = []
        ipg_nodes = [n for n in g.nodes.values() if n["kind"] == "ipg"]
        if (users or transit) and not ipg_nodes:
            aaeps = [n for n in g.nodes.values() if n["kind"] == "aaep"]
            has_static = any(n.get("matchesQuery") for n in g.nodes.values()
                             if n["kind"] == "staticPath")
            if aaeps and not has_static:
                warnings.append({
                    "code": "aaep-sans-ipg",
                    "gravite": "haute",
                    "titre": "Ce VLAN n'atteint aucune interface",
                    "detail": "Deploye via l'AAEP %s, mais aucun interface policy "
                              "group (infraRsAttEntP) n'est rattache a cet AAEP, et "
                              "aucun static path binding ne porte l'encapsulation. "
                              "La chaine s'arrete avant le port physique."
                              % ", ".join(sorted(n["label"] for n in aaeps)),
                })
            else:
                warnings.append({
                    "code": "ipg-non-resolu",
                    "gravite": "moyenne",
                    "titre": "IPG non resolu",
                    "detail": "Aucune des trois routes n'a abouti : ni depuis l'AAEP "
                              "(infraRsAttEntP), ni depuis le nom d'IPG d'un vPC, ni "
                              "depuis le port physique (port block -> port selector "
                              "-> infraRsAccBaseGrp).",
                })

        out["fabrics"].append({
            "id": fab.id,
            "status": status,
            "summary": summary,
            "warnings": warnings,
            "backup": {"file": fab.meta.get("srcFile"),
                       "generatedAt": fab.meta.get("generatedAt")},
            "roots": blocks,
            "roles": roles,
            "protocols": protos,
            "transitPaths": transit,
            "nodes": g.nodes,
            "edges": g.edges,
        })
    return out


# ==========================================================================
# Recherche subnet, tous fabrics
# ==========================================================================

def resolve_subnet(fabrics, query):
    try:
        qnet = ipaddress.ip_network(query, strict=False)
    except ValueError:
        qip = ipaddress.ip_address(query.split("/")[0])
        qnet = ipaddress.ip_network(str(qip) + "/32", strict=False)

    out = {"query": {"type": "subnet", "value": str(qnet)}, "fabrics": []}
    for fab in fabrics:
        g = Graph()
        hits = []

        for sub in fab.by_class.get("fvSubnet", []):
            ip = sub["a"].get("ip")
            if not ip:
                continue
            try:
                net = ipaddress.ip_interface(ip).network
            except ValueError:
                continue
            kind = match_kind(qnet, net)
            if not kind:
                continue
            bd = fab.by_dn.get(rn_parent(sub["dn"]))
            s_dn = g.add(fab.node(sub, "subnet", "gateway %s - scope %s"
                                  % (ip, sub["a"].get("scope", "?"))))
            hits.append({"dn": s_dn, "role": "bd-gateway", "match": kind})
            if bd and bd["c"] == "fvBD":
                bd_dn = g.add(fab.node(bd, "bd"))
                g.link(bd_dn, s_dn, "contient", "gateway")
                resolve_bd(fab, bd, g, bd_dn)
                for rsbd in fab.by_class.get("fvRsBd", []):
                    if rsbd["a"].get("tnFvBDName") != bd["a"].get("name"):
                        continue
                    epg = fab.by_dn.get(rn_parent(rsbd["dn"]))
                    if epg and fab.tenant_of(epg["dn"]) == fab.tenant_of(bd["dn"]):
                        resolve_epg(fab, epg, g)

        for sub in fab.by_class.get("l3extSubnet", []):
            ip = sub["a"].get("ip")
            if not ip:
                continue
            try:
                net = ipaddress.ip_network(ip, strict=False)
            except ValueError:
                continue
            kind = match_kind(qnet, net)
            if not kind:
                continue
            scopes = [s for s in (sub["a"].get("scope") or "").split(",") if s]
            roles = [{"scope": s, "axis": SCOPE_ROLE.get(s, ("?", s, ""))[0],
                      "gui": SCOPE_ROLE.get(s, ("?", s, ""))[1],
                      "sens": SCOPE_ROLE.get(s, ("?", s, ""))[2]} for s in scopes]
            s_dn = g.add(fab.node(sub, "l3extSubnet", ", ".join(scopes)))
            g.nodes[s_dn]["roles"] = roles
            hits.append({"dn": s_dn, "role": "l3ext-subnet", "match": kind,
                         "scopes": scopes,
                         "securite": any(r["axis"] == "securite" for r in roles),
                         "routage": any(r["axis"] == "routage" for r in roles)})
            inst = fab.by_dn.get(rn_parent(sub["dn"]))
            if inst and inst["c"] == "l3extInstP":
                i_dn = g.add(fab.node(inst, "extEpg"))
                g.link(i_dn, s_dn, "contient", "declare le prefixe")
                resolve_contracts(fab, inst["dn"], g, i_dn)
                out_mo = fab.by_dn.get(rn_parent(inst["dn"]))
                if out_mo and out_mo["c"] == "l3extOut":
                    o_dn = g.add(fab.node(out_mo, "l3out"))
                    g.link(i_dn, o_dn, "contenu-dans", "dans le L3Out")
                    for rse in fab.by_class.get("l3extRsEctx", []):
                        if rn_parent(rse["dn"]) != out_mo["dn"]:
                            continue
                        vrf = fab.in_tenant(out_mo["dn"], "fvCtx",
                                            rse["a"].get("tnFvCtxName"))
                        if vrf:
                            g.link(o_dn, g.add(fab.node(vrf, "vrf")),
                                   "vers-vrf", "L3Out dans le VRF")

        out["fabrics"].append({
            "id": fab.id,
            "status": "hit" if hits else "absent",
            "summary": "%d correspondance(s)" % len(hits) if hits else "aucune correspondance",
            "backup": {"file": fab.meta.get("srcFile"),
                       "generatedAt": fab.meta.get("generatedAt")},
            "hits": hits,
            "nodes": g.nodes,
            "edges": g.edges,
        })
    return out


def match_kind(qnet, net):
    """'exact' | 'aggregate' | 'plus-specifique' | None.

    Un agrégat n'est PAS un match exact : l'interface doit les distinguer,
    sinon on affirme une couverture qui n'existe pas au préfixe demandé.
    """
    if qnet == net:
        return "exact"
    if qnet.version != net.version:
        return None
    if qnet.subnet_of(net):
        return "aggregate"
    if net.subnet_of(qnet):
        return "plus-specifique"
    return None


# ==========================================================================
# Auto-verification, sans rien faire sortir du reseau
#
# Le resolveur JavaScript est une reecriture de ce fichier. Une reecriture se
# trompe. On veut donc la verifier SUR LES VRAIES DONNEES du client - mais son
# reseau est ferme et rien n'en sort.
#
# La parade : ce module calcule ici, cote RHEL, la reponse a CHAQUE requete
# possible, et n'en conserve qu'une EMPREINTE SHA-256 tronquee. L'empreinte
# est embarquee dans la page ; le JavaScript recalcule et compare. Une
# empreinte ne permet pas de reconstituer un DN, une IP ni un nom de tenant,
# et elle ne quitte de toute facon jamais la machine.
# ==========================================================================

def _canon(graph):
    """Forme canonique d'un graphe : ce qui est compare, et rien d'autre."""
    out = []
    for f in graph["fabrics"]:
        out.append({
            "id": f["id"], "status": f["status"], "summary": f["summary"],
            "roles": f.get("roles") or [], "protocols": f.get("protocols") or [],
            "nodes": sorted(f["nodes"].keys()),
            "edges": sorted("%s>%s|%s" % (e["from"], e["to"], e["rel"])
                            for e in f["edges"]),
            "hits": sorted("%s|%s|%s" % (h.get("dn"), h.get("role"), h.get("match"))
                           for h in (f.get("hits") or [])),
        })
    return json.dumps(out, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def digest_of(graph):
    return hashlib.sha256(_canon(graph).encode("utf-8")).hexdigest()[:16]


def all_queries(fabrics):
    """Tous les VLAN et tous les prefixes reellement presents."""
    vlans, nets = set(), set()
    for fab in fabrics:
        for m in fab.mos:
            a = m["a"]
            for k in ("encap", "from", "to"):
                v = encap_num(a.get(k))
                if v is not None and 1 <= v <= 4094:
                    vlans.add(v)
            if m["c"] in ("fvSubnet", "l3extSubnet", "mgmtSubnet") and a.get("ip"):
                nets.add(a["ip"])
    return sorted(vlans), sorted(nets)


def build_digests(fabrics):
    vlans, nets = all_queries(fabrics)
    out = {"vlan": {}, "subnet": {}}
    for v in vlans:
        out["vlan"][str(v)] = digest_of(resolve_vlan(fabrics, v))
    for n in nets:
        try:
            out["subnet"][n] = digest_of(resolve_subnet(fabrics, n))
        except ValueError:
            continue
    return out


def load_fabrics(directory):
    fabs = []
    for name in sorted(os.listdir(directory)):
        if name.endswith(".fl.json.gz"):
            fabs.append(Fabric(os.path.join(directory, name)))
    return fabs


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Resolveur Fabric Lens")
    ap.add_argument("--data", required=True, help="repertoire des .fl.json.gz")
    ap.add_argument("--vlan", type=int)
    ap.add_argument("--subnet")
    ap.add_argument("--out", help="ecrire le graphe JSON ici")
    ap.add_argument("--digests", action="store_true",
                    help="calculer l'empreinte de CHAQUE requete possible, "
                         "pour que le resolveur JS se verifie tout seul "
                         "sur ces donnees sans que rien n'en sorte")
    args = ap.parse_args()

    fabs = load_fabrics(args.data)

    if args.digests:
        d = build_digests(fabs)
        blob = json.dumps(d, sort_keys=True, separators=(",", ":"))
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(blob)
            print("%d VLAN + %d subnet -> %s (%.0f Ko)"
                  % (len(d["vlan"]), len(d["subnet"]), args.out, len(blob) / 1024.0))
        else:
            print(blob)
        return 0

    if args.vlan is not None:
        res = resolve_vlan(fabs, args.vlan)
    elif args.subnet:
        res = resolve_subnet(fabs, args.subnet)
    else:
        ap.error("--vlan ou --subnet requis")

    for f in res["fabrics"]:
        print("%-14s %-10s %-40s %4d objets, %3d relations"
              % (f["id"], f["status"], f["summary"], len(f["nodes"]), len(f["edges"])))

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(res, fh, ensure_ascii=False, separators=(",", ":"))
        print("\n-> %s (%.1f Ko)" % (args.out, os.path.getsize(args.out) / 1024.0))


if __name__ == "__main__":
    main()
