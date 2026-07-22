// resolve.js — portage JavaScript du resolveur Fabric Lens (fabriclens/resolve.py).
//
// Contrat : a requete et donnees identiques, ce module doit produire EXACTEMENT
// le meme graphe que le Python — memes DN de noeuds, memes aretes, memes champs.
// Tout ce qui suit est ecrit pour tenir cette egalite, pas pour etre elegant.
//
// Trois familles de pieges ont dicte la forme du code :
//   - le decoupage des DN (crochets contenant des `/`) ;
//   - la semantique de Python la ou JS diverge (int(), %s sur None, dict.get
//     avec defaut, tri de chaines, ordre d'insertion) ;
//   - l'arithmetique d'adresses, que Python obtient gratuitement via ipaddress
//     et qu'il faut ecrire ici a la main, IPv4 comme IPv6.
//
// Le module est un ES module sans dependance : utilisable dans un <script
// type="module"> inline (application hors ligne, fichier HTML unique) comme
// sous node (test differentiel contre l'oracle Python).

// --------------------------------------------------------------------------
// Etiquettes lisibles — l'interface est en francais, les termes ACI en anglais
// --------------------------------------------------------------------------

export const KIND_LABEL = {
  fvnsEncapBlk: "Encap Block",
  fvnsVlanInstP: "VLAN Pool",
  physDomP: "Physical Domain",
  l3extDomP: "L3 Domain",
  vmmDomP: "VMM Domain",
  infraAttEntityP: "AAEP",
  infraAccPortGrp: "Interface Policy Group",
  infraAccBndlGrp: "Interface Policy Group",
  infraAccPortP: "Interface Profile",
  infraHPortS: "Port Selector",
  infraPortBlk: "Port Block",
  infraNodeP: "Switch Profile",
  infraLeafS: "Leaf Selector",
  infraNodeBlk: "Node Block",
  fvTenant: "Tenant",
  fvCtx: "VRF",
  fvBD: "Bridge Domain",
  fvSubnet: "Subnet",
  fvAp: "Application Profile",
  fvAEPg: "EPG",
  fvESg: "ESG",
  vzBrCP: "Contract",
  vzSubj: "Subject",
  vzFilter: "Filter",
  vzEntry: "Filter Entry",
  l3extOut: "L3Out",
  l3extInstP: "External EPG",
  l3extSubnet: "External Subnet",
  l2extOut: "L2Out",
  l2extInstP: "External EPG (L2)",
  // relations : ce sont des objets a part entiere dans le MIT, et
  // l'utilisateur doit pouvoir cliquer dessus pour voir leur config brute
  infraRsFuncToEpg: "Deploiement AAEP",
  fvRsPathAtt: "Static Path Binding",
  infraRsVlanNs: "Domain -> VLAN Pool",
  infraRsDomP: "AAEP -> Domain",
  infraRsAttEntP: "IPG -> AAEP",
  infraRsAccBaseGrp: "Selector -> IPG",
  infraRsAccPortP: "Switch -> Interface Profile",
  fvRsBd: "EPG -> BD",
  fvRsCtx: "BD -> VRF",
  fvRsDomAtt: "EPG -> Domain",
  fvRsProv: "Provide",
  fvRsCons: "Consume",
  fvRsBDToOut: "BD -> L3Out",
  l3extRsEctx: "L3Out -> VRF",
  vzRsSubjFiltAtt: "Subject -> Filter",
  infraFexP: "FEX Profile",
  infraFexBndlGrp: "FEX Policy Group",
  infraGeneric: "AAEP Generic",
  l3extRsPathL3OutAtt: "L3Out Interface",
  l3extLIfP: "Logical Interface Profile",
  l3extLNodeP: "Logical Node Profile",
  bgpPeerP: "BGP Peer",
  ospfExtP: "OSPF",
  bgpExtP: "BGP",
  eigrpExtP: "EIGRP",
};

// Les roles d'un l3extSubnet. Securite et routage sont deux axes ORTHOGONAUX :
// un meme prefixe porte souvent les deux, et l'interface doit le montrer sans
// obliger a lire une legende.
export const SCOPE_ROLE = {
  "import-security": ["securite", "External Subnets for the External EPG",
    "classifie le trafic entrant dans cet ext-EPG"],
  "shared-security": ["securite", "Shared Security Import",
    "classifie le trafic inter-VRF"],
  "export-rtctrl": ["routage", "Advertised Externally",
    "le prefixe est annonce vers l'exterieur"],
  "import-rtctrl": ["routage", "Import Route Control",
    "filtre ce qui est accepte de l'exterieur"],
  "shared-rtctrl": ["routage", "Shared Route Control",
    "fuite de route inter-VRF"],
};

// --------------------------------------------------------------------------
// Compatibilite Python : les quelques primitives ou JS ment differemment
// --------------------------------------------------------------------------

// `"%s" % None` donne "None" en Python. Un `${undefined}` donnerait "undefined"
// et suffirait a faire diverger une note, donc un libelle, donc le test.
function S(v) {
  return v === undefined || v === null ? "None" : String(v);
}

// dict.get(k, default) : le defaut ne s'applique QU'A la cle absente.
function getd(a, k, d) {
  return a[k] === undefined ? d : a[k];
}

// Verite pythonique restreinte aux valeurs qu'on rencontre ici : "" et
// undefined sont faux, toute autre chaine est vraie. `if a.get(k):` partout.
function truthy(v) {
  return v !== undefined && v !== null && v !== "" && v !== false;
}

// int(x) de Python : leve sur None, sur "" et sur "12a" — on renvoie null et
// l'appelant traite null comme le `except (TypeError, ValueError): continue`.
// Les espaces de tete/queue sont tolerees, comme int().
function pyInt(v) {
  if (v === undefined || v === null) return null;
  const s = String(v).trim();
  if (!/^[+-]?\d+$/.test(s)) return null;
  const n = Number(s);
  return Number.isFinite(n) ? n : null;
}

// Tri de chaines : Python compare par code point, JS par unite UTF-16. Les deux
// coincident sur tout ce qui n'est pas hors BMP — c'est le cas des DN ACI.
function cmpStr(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

// --------------------------------------------------------------------------
// Decoupage des DN — la source de bugs numero un
// --------------------------------------------------------------------------

/** Decoupe un DN en RN en respectant les crochets.
 *  Un split("/") naif casse sur `pathep-[eth1/15]` et renvoie `15]`. */
export function splitRns(dn) {
  const parts = [];
  let depth = 0;
  let cur = "";
  for (const ch of dn) {
    if (ch === "[") depth += 1;
    else if (ch === "]") depth -= 1;
    // Le `/` n'est un separateur qu'a l'exterieur des crochets ; sinon il fait
    // partie du RN courant (et le caractere `[`/`]` y reste lui aussi).
    if (ch === "/" && depth === 0) {
      parts.push(cur);
      cur = "";
    } else {
      cur += ch;
    }
  }
  parts.push(cur);
  return parts;
}

export function lastRn(dn) {
  if (!dn) return "";
  const p = splitRns(dn);
  return p[p.length - 1];
}

/** DN du parent, en respectant les crochets (qui peuvent contenir des /).
 *  Parcours arriere : on ne coupe qu'au premier `/` de profondeur nulle, donc
 *  le parent de `.../epg-Z/rspathAtt-[topology/pod-1/...]` est bien l'EPG. */
export function rnParent(dn) {
  let depth = 0;
  for (let i = dn.length - 1; i >= 0; i--) {
    const c = dn[i];
    if (c === "]") depth += 1;
    else if (c === "[") depth -= 1;
    else if (c === "/" && depth === 0) return dn.slice(0, i);
  }
  return "";
}

/** `topology/pod-1/protpaths-101-102/pathep-[SRV-VPC.IPG]`
 *  -> `vPC 101-102 . SRV-VPC.IPG` */
export function pathLabel(tdn) {
  if (!tdn) return "";
  const parts = splitRns(tdn);
  let node = "";
  let port = lastRn(tdn);
  for (const p of parts) {
    if (p.startsWith("protpaths-")) node = "vPC " + p.slice("protpaths-".length);
    else if (p.startsWith("paths-")) node = "leaf " + p.slice("paths-".length);
  }
  // `.*` glouton : on va jusqu'au DERNIER `]`, comme le re.match Python.
  const m = /^pathep-\[(.*)\]$/.exec(port);
  if (m) port = m[1];
  return node ? `${node} . ${port}` : port;
}

/** Decompose un tDn de chemin en cible physique exploitable.
 *
 *  `topology/pod-1/paths-101/pathep-[eth1/10]`
 *      -> {kind:'access', pod:'1', nodes:['101'], port:'eth1/10'}
 *  `topology/pod-1/protpaths-101-102/pathep-[SRV-VPC.IPG]`
 *      -> {kind:'vpc', pod:'1', nodes:['101','102'], ipg:'SRV-VPC.IPG'}
 *
 *  L'ordre des tests compte : `protpaths-` et `extpaths-` ne commencent pas par
 *  `paths-`, mais un jour quelqu'un reordonnera — l'ordre du Python est garde
 *  tel quel. `extpaths-` ne fixe PAS `kind` : sur un FEX le RN `paths-101` reste
 *  present et donne kind=access, le FEX n'etant qu'une precision.
 */
export function parsePathTdn(tdn) {
  if (!tdn) return null;
  const parts = splitRns(tdn);
  const out = { tDn: tdn, kind: null, pod: null, nodes: [], port: null, ipg: null, fex: null };
  for (const p of parts) {
    if (p.startsWith("pod-")) {
      out.pod = p.slice(4);
    } else if (p.startsWith("protpaths-")) {
      out.kind = "vpc";
      out.nodes = p.slice("protpaths-".length).split("-");
    } else if (p.startsWith("paths-")) {
      out.kind = "access";
      out.nodes = [p.slice("paths-".length)];
    } else if (p.startsWith("extpaths-")) {
      out.fex = p.slice("extpaths-".length);
    } else if (p.startsWith("pathep-[")) {
      let inner = p.slice("pathep-[".length);
      if (inner.endsWith("]")) inner = inner.slice(0, -1);
      // Sur un vPC, la cible du pathep est le NOM de l'IPG, pas un port.
      if (out.kind === "vpc") out.ipg = inner;
      else out.port = inner;
    }
  }
  if (!out.kind) return null;
  return out;
}

export function pathTargetLabel(t) {
  if (!t) return "?";
  let who = t.nodes && t.nodes.length ? "leaf " + t.nodes.join("+") : "?";
  if (truthy(t.fex)) who += " fex " + t.fex;
  const what = truthy(t.port) ? t.port : (truthy(t.ipg) ? "IPG " + t.ipg : "?");
  return `${who} . ${what}`;
}

/** 'vlan-2110' -> 2110. null si ce n'est pas un VLAN.
 *  `\d+` glouton ancre en fin : 'unknown' ne matche pas, 'vlan-100' donne 100. */
export function encapNum(encap) {
  if (!truthy(encap)) return null;
  const m = /(\d+)\s*$/.exec(String(encap));
  return m ? parseInt(m[1], 10) : null;
}

// --------------------------------------------------------------------------
// Arithmetique d'adresses — l'equivalent maison du module ipaddress
// --------------------------------------------------------------------------
//
// Un reseau est {version, addr:BigInt (adresse reseau masquee), prefix:int,
// bits:int}. BigInt pour les deux familles : IPv6 depasse Number, et un seul
// chemin de code evite d'avoir deux comparateurs qui divergent.

function parseIPv4(s) {
  const parts = s.split(".");
  if (parts.length !== 4) return null;
  let v = 0n;
  for (const p of parts) {
    // Python >= 3.9.5 REJETTE les zeros de tete (ambiguite octale) : on fait
    // pareil, sinon '010.1.1.1' passerait ici et pas dans l'oracle.
    if (!/^\d+$/.test(p)) return null;
    if (p.length > 1 && p[0] === "0") return null;
    if (p.length > 3) return null;
    const n = Number(p);
    if (n > 255) return null;
    v = (v << 8n) | BigInt(n);
  }
  return v;
}

function parseIPv6(s) {
  if (s.indexOf(".") !== -1) {
    // Forme mixte `::ffff:10.0.0.1` : on convertit la queue IPv4 en deux
    // groupes hexa avant de traiter le reste normalement.
    const idx = s.lastIndexOf(":");
    const v4 = parseIPv4(s.slice(idx + 1));
    if (v4 === null) return null;
    const hi = (v4 >> 16n).toString(16);
    const lo = (v4 & 0xffffn).toString(16);
    s = s.slice(0, idx + 1) + hi + ":" + lo;
  }
  const dbl = s.indexOf("::");
  let head, tail;
  if (dbl !== -1) {
    if (s.indexOf("::", dbl + 1) !== -1) return null; // un seul `::` autorise
    head = s.slice(0, dbl) === "" ? [] : s.slice(0, dbl).split(":");
    tail = s.slice(dbl + 2) === "" ? [] : s.slice(dbl + 2).split(":");
    if (head.length + tail.length > 7) return null;
  } else {
    head = s.split(":");
    tail = [];
    if (head.length !== 8) return null;
  }
  const groups = [];
  for (const g of head) groups.push(g);
  for (let i = head.length + tail.length; i < 8; i++) groups.push("0");
  for (const g of tail) groups.push(g);
  let v = 0n;
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    v = (v << 16n) | BigInt(parseInt(g, 16));
  }
  return v;
}

function parseIpAddress(s) {
  if (typeof s !== "string" || s === "") return null;
  if (s.indexOf(":") !== -1) {
    const v = parseIPv6(s);
    return v === null ? null : { version: 6, addr: v, bits: 128 };
  }
  const v = parseIPv4(s);
  return v === null ? null : { version: 4, addr: v, bits: 32 };
}

function maskOf(bits, prefix) {
  const all = (1n << BigInt(bits)) - 1n;
  return (all << BigInt(bits - prefix)) & all;
}

/** ip_network(s, strict=False) : masque les bits hote au lieu de refuser.
 *  Renvoie null la ou Python leverait ValueError. */
export function parseIpNetwork(s, strict = false) {
  if (typeof s !== "string") return null;
  const slash = s.indexOf("/");
  let addrPart = s;
  let prefPart = null;
  if (slash !== -1) {
    addrPart = s.slice(0, slash);
    prefPart = s.slice(slash + 1);
    if (prefPart.indexOf("/") !== -1) return null;
  }
  const ip = parseIpAddress(addrPart);
  if (!ip) return null;
  let prefix = ip.bits;
  if (prefPart !== null) {
    if (/^\d+$/.test(prefPart)) {
      prefix = Number(prefPart);
      if (prefix > ip.bits) return null;
    } else if (ip.version === 4) {
      // Forme `10.0.0.0/255.0.0.0`, acceptee par ipaddress : on la reconnait
      // pour ne pas rejeter une donnee qu'un backup pourrait contenir.
      const nm = parseIPv4(prefPart);
      if (nm === null) return null;
      const inv = ~nm & 0xffffffffn;
      if (((inv + 1n) & inv) !== 0n) return null; // masque non contigu
      prefix = 32;
      let t = inv;
      while (t > 0n) { prefix -= 1; t >>= 1n; }
    } else {
      return null;
    }
  }
  const net = ip.addr & maskOf(ip.bits, prefix);
  if (strict && net !== ip.addr) return null;
  return { version: ip.version, addr: net, prefix, bits: ip.bits };
}

/** ip_interface(s).network : l'adresse porte des bits hote, on ne garde que
 *  le reseau. C'est exactement parseIpNetwork non strict. */
export function parseIpInterfaceNetwork(s) {
  return parseIpNetwork(s, false);
}

function broadcastOf(n) {
  return n.addr | ((1n << BigInt(n.bits - n.prefix)) - 1n);
}

function netEq(a, b) {
  return a.version === b.version && a.addr === b.addr && a.prefix === b.prefix;
}

/** a.subnet_of(b) : a est-il contenu dans b (au sens large, egalite incluse) ? */
function subnetOf(a, b) {
  return b.addr <= a.addr && broadcastOf(b) >= broadcastOf(a);
}

/** Representation canonique, identique a str(ip_network(...)) en Python. */
export function netToString(n) {
  if (n.version === 4) {
    const v = n.addr;
    const o = [(v >> 24n) & 255n, (v >> 16n) & 255n, (v >> 8n) & 255n, v & 255n];
    return o.join(".") + "/" + n.prefix;
  }
  // RFC 5952 : minuscules, groupes sans zeros de tete, plus longue suite de
  // groupes nuls (>= 2) compressee, la plus a gauche en cas d'egalite.
  const g = [];
  for (let i = 7; i >= 0; i--) g.push(Number((n.addr >> BigInt(i * 16)) & 0xffffn));
  let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (g[i] === 0) {
      if (curStart === -1) { curStart = i; curLen = 0; }
      curLen += 1;
      if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
    } else {
      curStart = -1; curLen = 0;
    }
  }
  const hex = g.map((x) => x.toString(16));
  let s;
  if (bestLen >= 2) {
    s = hex.slice(0, bestStart).join(":") + "::" + hex.slice(bestStart + bestLen).join(":");
  } else {
    s = hex.join(":");
  }
  return s + "/" + n.prefix;
}

/** 'exact' | 'aggregate' | 'plus-specifique' | null.
 *
 *  Un agregat n'est PAS un match exact : l'interface doit les distinguer,
 *  sinon on affirme une couverture qui n'existe pas au prefixe demande. */
export function matchKind(qnet, net) {
  if (netEq(qnet, net)) return "exact";
  if (qnet.version !== net.version) return null;
  if (subnetOf(qnet, net)) return "aggregate";
  if (subnetOf(net, qnet)) return "plus-specifique";
  return null;
}

// --------------------------------------------------------------------------
// Fabric et Graph
// --------------------------------------------------------------------------

class Fabric {
  constructor(doc) {
    this.meta = doc.meta;
    this.id = this.meta.fabric;
    this.mos = doc.mos;

    this.byDn = new Map();
    this.byClass = new Map();
    for (const m of this.mos) {
      this.byDn.set(m.dn, m);
      let l = this.byClass.get(m.c);
      if (!l) { l = []; this.byClass.set(m.c, l); }
      l.push(m);
    }

    // Index inverse : cible d'une relation -> [relations qui la visent].
    // C'est ce qui remplace les *Rt* absents des backups — un export ne
    // contient QUE les relations forward (tDn, tnXxxName).
    this.rev = new Map();
    for (const m of this.mos) {
      const tdn = m.a.tDn;
      if (truthy(tdn)) {
        let l = this.rev.get(tdn);
        if (!l) { l = []; this.rev.set(tdn, l); }
        l.push(m);
      }
    }

    // Index par nom pour les relations tnXxxName, qui pointent par NOM dans la
    // portee du tenant — pas par DN.
    this.byTenantName = new Map();
    for (const cls of ["fvBD", "fvCtx", "vzBrCP", "l3extOut", "vzFilter",
      "vzCPIf", "vzTaboo", "vzOOBBrCP"]) {
      for (const m of this.cls(cls)) {
        const tn = Fabric.tenantOf(m.dn);
        const name = m.a.name;
        if (tn && truthy(name)) {
          const key = tn + " " + cls;
          let d = this.byTenantName.get(key);
          if (!d) { d = new Map(); this.byTenantName.set(key, d); }
          // Python ecrase : le dernier vu gagne. On reproduit (pas de test
          // d'existence prealable).
          d.set(name, m);
        }
      }
    }
  }

  /** by_class.get(cls, []) — jamais undefined cote appelant. */
  cls(name) {
    return this.byClass.get(name) || [];
  }

  revOf(dn) {
    return this.rev.get(dn) || [];
  }

  static tenantOf(dn) {
    const m = /^(uni\/tn-[^/]+)/.exec(dn);
    return m ? m[1] : null;
  }

  label(mo) {
    const a = mo.a;
    const cls = mo.c;

    // Cas particuliers d'abord : pour ces classes, l'attribut `name` existe
    // mais ne dit rien d'utile — c'est la plage ou la cible qui compte.
    if (cls === "fvnsEncapBlk") {
      return `${S(getd(a, "from", "?"))} - ${S(getd(a, "to", "?"))}`;
    }
    if (cls === "infraPortBlk") {
      let rng = `eth${S(getd(a, "fromCard", "1"))}/${S(getd(a, "fromPort", "?"))}`;
      if (truthy(a.toPort) && a.toPort !== a.fromPort) rng += `-${a.toPort}`;
      return rng;
    }
    if (cls === "infraNodeBlk") {
      let rng = S(getd(a, "from_", "?"));
      if (truthy(a.to_) && a.to_ !== a.from_) rng += `-${a.to_}`;
      // le switch profile est 2 niveaux au-dessus : nprof-X/leaves-Y/nodeblk-Z
      const prof = lastRn(rnParent(rnParent(mo.dn)));
      if (prof.startsWith("nprof-")) return `leaf ${rng}  (${prof.slice("nprof-".length)})`;
      return "leaf " + rng;
    }
    if (cls === "fvRsPathAtt" || cls === "l3extRsPathL3OutAtt") {
      // tDn = topology/pod-1/protpaths-101-102/pathep-[IPG] ; on veut la partie
      // lisible, sans se faire couper par le / dans les crochets.
      return pathLabel(getd(a, "tDn", ""));
    }

    for (const k of ["name", "ip", "id"]) {
      if (truthy(a[k])) return a[k];
    }
    if (truthy(a.tDn)) return lastRn(a.tDn);
    for (const k of Object.keys(a).sort(cmpStr)) {
      if (k.startsWith("tn") && truthy(a[k])) return a[k];
    }
    return lastRn(mo.dn);
  }

  node(mo, kind = null, note = null) {
    // note vaut null et non undefined : JSON.stringify effacerait la cle, et le
    // Python emet bien `"note": null`.
    return {
      dn: mo.dn,
      cls: mo.c,
      clsLabel: KIND_LABEL[mo.c] !== undefined ? KIND_LABEL[mo.c] : mo.c,
      label: this.label(mo),
      kind: kind !== null && kind !== undefined ? kind : mo.c,
      note: note === undefined ? null : note,
      attrs: mo.a,
    };
  }

  // -- resolution par nom, portee tenant --------------------------------
  inTenant(dn, cls, name) {
    const tn = Fabric.tenantOf(dn);
    if (!tn || !truthy(name)) return null;
    const d = this.byTenantName.get(tn + " " + cls);
    const hit = d ? d.get(name) : undefined;
    if (hit) return hit;
    // repli : le tenant `common` est visible depuis tous les tenants
    const c = this.byTenantName.get("uni/tn-common " + cls);
    const h2 = c ? c.get(name) : undefined;
    return h2 || null;
  }
}

/** Accumulateur de noeuds et d'aretes, dedupliqué par DN.
 *  `nodes` est une Map pour garantir l'ordre d'insertion quel que soit le DN
 *  (un objet JS reordonne les cles numeriques ; les DN n'en sont pas, mais on
 *  ne fait pas reposer l'egalite avec Python sur ce detail). */
class Graph {
  constructor() {
    this.nodes = new Map();
    this.edges = [];
    this._seen = new Set();
  }

  add(node) {
    const dn = node.dn;
    const cur = this.nodes.get(dn);
    if (cur === undefined) {
      this.nodes.set(dn, node);
    } else if (truthy(node.note) && !truthy(cur.note)) {
      // On ne remplace une note QUE si l'existante etait vide : le premier
      // passage informatif gagne, les suivants n'ecrasent pas.
      cur.note = node.note;
    }
    return dn;
  }

  link(src, dst, rel, label = null) {
    if (!src || !dst) return;
    const key = src + " " + dst + " " + rel;
    if (this._seen.has(key)) return;
    this._seen.add(key);
    this.edges.push({ from: src, to: dst, rel, label: truthy(label) ? label : rel });
  }

  nodesObject() {
    const o = {};
    for (const [k, v] of this.nodes) o[k] = v;
    return o;
  }
}

// ==========================================================================
// Chaine ACCESS POLICIES : de l'encap block jusqu'au port physique
// ==========================================================================

function resolveAccessChain(fab, vlan, g) {
  const roots = [];
  for (const blk of fab.cls("fvnsEncapBlk")) {
    const lo = encapNum(blk.a.from);
    const hi = encapNum(blk.a.to);
    if (lo === null || hi === null || !(lo <= vlan && vlan <= hi)) continue;
    const blkDn = g.add(fab.node(blk, "encapBlk",
      `bloc ${S(blk.a.from)}-${S(blk.a.to)} (${S(getd(blk.a, "allocMode", "?"))})`));
    roots.push(blkDn);

    const pool = fab.byDn.get(rnParent(blk.dn));
    if (!pool) continue;
    const poolDn = g.add(fab.node(pool, "vlanPool"));
    g.link(blkDn, poolDn, "contenu-dans", "appartient au pool");

    // domaines qui referencent ce pool (via infraRsVlanNs.tDn)
    for (const rs of fab.revOf(pool.dn)) {
      if (rs.c !== "infraRsVlanNs") continue;
      const dom = fab.byDn.get(rnParent(rs.dn));
      if (!dom) continue;
      const domDn = g.add(fab.node(dom, "domain"));
      g.link(poolDn, domDn, "utilise-par", "pool utilise par le domaine");

      // AAEP qui referencent ce domaine (via infraRsDomP.tDn)
      for (const rs2 of fab.revOf(dom.dn)) {
        if (rs2.c !== "infraRsDomP") continue;
        const aaep = fab.byDn.get(rnParent(rs2.dn));
        if (!aaep) continue;
        const aaepDn = g.add(fab.node(aaep, "aaep"));
        g.link(domDn, aaepDn, "utilise-par", "domaine attache a l'AAEP");
        resolveAaep(fab, aaep, vlan, g, aaepDn);
      }
    }
  }
  return roots;
}

function resolveAaep(fab, aaep, vlan, g, aaepDn) {
  // 1. Deploiement direct de l'EPG par l'AAEP (infraRsFuncToEpg porte l'encap)
  for (const f of fab.cls("infraRsFuncToEpg")) {
    if (!f.dn.startsWith(aaep.dn + "/")) continue;
    if (encapNum(f.a.encap) !== vlan) continue;
    const fDn = g.add(fab.node(f, "aaepDeploy",
      `deploiement AAEP - encap ${S(f.a.encap)}, mode ${S(getd(f.a, "mode", "?"))}`));
    g.link(aaepDn, fDn, "deploie", "l'AAEP deploie un EPG");
    const epg = fab.byDn.get(getd(f.a, "tDn", ""));
    if (epg) g.link(fDn, g.add(fab.node(epg, "epg")), "vers-epg", "vers l'EPG");
  }

  // 2. IPG qui referencent cet AAEP (infraRsAttEntP.tDn)
  for (const rs of fab.revOf(aaep.dn)) {
    if (rs.c !== "infraRsAttEntP") continue;
    const ipg = fab.byDn.get(rnParent(rs.dn));
    if (!ipg) continue;
    const ipgDn = g.add(fab.node(ipg, "ipg", lagNote(ipg)));
    g.link(aaepDn, ipgDn, "utilise-par", "AAEP utilise par l'IPG");
    resolveIpgPorts(fab, ipg, g, ipgDn);
  }
}

/** {"node":"vPC","link":"Port-Channel"}.get(lagT, "acces") */
function lagNote(ipg) {
  const lag = ipg.a.lagT;
  if (lag === "node") return "vPC";
  if (lag === "link") return "Port-Channel";
  return "acces";
}

function resolveIpgPorts(fab, ipg, g, ipgDn) {
  for (const rs of fab.revOf(ipg.dn)) {
    if (rs.c !== "infraRsAccBaseGrp") continue;
    const hportsDn = rnParent(rs.dn);
    const hports = fab.byDn.get(hportsDn);
    const profDn = rnParent(hportsDn);
    const prof = fab.byDn.get(profDn);
    if (!hports || !prof) continue;

    const selDn = g.add(fab.node(hports, "portSelector"));
    g.link(ipgDn, selDn, "selectionne-par", "IPG utilise par le selecteur");

    for (const blk of fab.cls("infraPortBlk")) {
      if (!blk.dn.startsWith(hportsDn + "/")) continue;
      const a = blk.a;
      let rng = `eth${S(getd(a, "fromCard", "1"))}/${S(getd(a, "fromPort", "?"))}`;
      if (truthy(a.toPort) && a.toPort !== a.fromPort) rng += `-${a.toPort}`;
      const blkDn = g.add(fab.node(blk, "portBlk", rng));
      g.link(selDn, blkDn, "contient", "ports");
    }

    const iprofDn = g.add(fab.node(prof, "ifProfile"));
    g.link(selDn, iprofDn, "contenu-dans", "dans l'interface profile");

    // switch profiles qui referencent cet interface profile
    for (const rs2 of fab.revOf(profDn)) {
      if (rs2.c !== "infraRsAccPortP") continue;
      const nprofDnS = rnParent(rs2.dn);
      const nprof = fab.byDn.get(nprofDnS);
      if (!nprof) continue;
      const spDn = g.add(fab.node(nprof, "switchProfile"));
      g.link(iprofDn, spDn, "utilise-par", "utilise par le switch profile");
      for (const nb of fab.cls("infraNodeBlk")) {
        if (!nb.dn.startsWith(nprofDnS + "/")) continue;
        const a = nb.a;
        let rng = S(getd(a, "from_", "?"));
        if (truthy(a.to_) && a.to_ !== a.from_) rng += `-${a.to_}`;
        const nbDn = g.add(fab.node(nb, "nodeBlk", "leaf " + rng));
        g.link(spDn, nbDn, "contient", "leaves");
      }
    }
  }
}

// ==========================================================================
// Chaine LOGIQUE : EPG -> BD -> VRF -> subnets, et les contrats
// ==========================================================================

function resolveEpg(fab, epg, g, note = null, vlan = null) {
  const epgDn = g.add(fab.node(epg, "epg", note));

  const ap = fab.byDn.get(rnParent(epg.dn));
  if (ap && ap.c === "fvAp") {
    const apDn = g.add(fab.node(ap, "ap"));
    g.link(epgDn, apDn, "contenu-dans", "dans l'application profile");
    const tn = fab.byDn.get(rnParent(ap.dn));
    if (tn) g.link(apDn, g.add(fab.node(tn, "tenant")), "contenu-dans", "dans le tenant");
  }

  // EPG -> BD (par NOM, portee tenant)
  for (const rsbd of fab.cls("fvRsBd")) {
    if (rnParent(rsbd.dn) !== epg.dn) continue;
    const bd = fab.inTenant(epg.dn, "fvBD", rsbd.a.tnFvBDName);
    if (!bd) continue;
    const bdDn = g.add(fab.node(bd, "bd"));
    g.link(epgDn, bdDn, "vers-bd", "EPG rattache au BD");
    resolveBd(fab, bd, g, bdDn);
  }

  // EPG -> domaine
  for (const rsd of fab.cls("fvRsDomAtt")) {
    if (rnParent(rsd.dn) !== epg.dn) continue;
    const dom = fab.byDn.get(getd(rsd.a, "tDn", ""));
    if (dom) g.link(epgDn, g.add(fab.node(dom, "domain")), "vers-domaine", "domaine associe");
  }

  // EPG -> static path bindings.
  // On affiche TOUS les bindings de l'EPG — masquer les autres cacherait qu'un
  // meme EPG porte plusieurs encapsulations — mais on dit lesquels repondent a
  // la question posee (matchesQuery).
  for (const rsp of fab.cls("fvRsPathAtt")) {
    if (rnParent(rsp.dn) !== epg.dn) continue;
    const a = rsp.a;
    const hit = vlan !== null && vlan !== undefined && encapNum(a.encap) === vlan;
    const tgt = parsePathTdn(a.tDn);
    const pDn = g.add(fab.node(rsp, "staticPath",
      `encap ${S(a.encap)} sur ${pathTargetLabel(tgt)}, mode ${S(getd(a, "mode", "?"))}`
      + (hit ? "" : "  (autre encap)")));
    // Mutation du noeud STOCKE (il a pu etre fusionne avec un precedent).
    g.nodes.get(pDn).matchesQuery = Boolean(hit);
    g.nodes.get(pDn).target = tgt;
    g.link(epgDn, pDn, "static-port",
      hit ? "static path binding" : "autre encapsulation");
    // Rattacher le binding a l'IPG reel (vPC) et aux leaves nommees dans le
    // tDn : c'est ce qui donne "l'IPG, la ou les leaf, et l'interface".
    if (tgt) linkPathToHardware(fab, tgt, g, pDn);
  }

  resolveContracts(fab, epg.dn, g, epgDn);
  return epgDn;
}

/** Depuis une cible de chemin, retrouve l'IPG, les leaves et les ports.
 *
 *  Trois routes independantes menent a l'IPG, et il faut les tenter toutes :
 *    - route A : AAEP -> infraRsAttEntP -> IPG   (echoue si aucun IPG n'est
 *      rattache a cet AAEP, ce qui arrive)
 *    - route B : le tDn d'un vPC nomme l'IPG     (n'existe que sur un vPC)
 *    - route C : port -> port selector -> infraRsAccBaseGrp -> IPG
 *  B et C sont ici ; A est dans resolveAaep. */
function linkPathToHardware(fab, tgt, g, pathNodeDn) {
  // 1. l'IPG, nomme dans le tDn quand c'est un vPC ou un port-channel
  if (truthy(tgt.ipg)) {
    for (const cls of ["infraAccBndlGrp", "infraAccPortGrp"]) {
      for (const ipg of fab.cls(cls)) {
        if (ipg.a.name === tgt.ipg) {
          const ipgDn = g.add(fab.node(ipg, "ipg", lagNote(ipg)));
          g.link(pathNodeDn, ipgDn, "vers-ipg", "cible l'IPG");
          resolveIpgPorts(fab, ipg, g, ipgDn);
        }
      }
    }
  }

  // 2. les leaves nommees dans le tDn -> node block correspondant
  for (const nodeId of tgt.nodes || []) {
    for (const nb of fab.cls("infraNodeBlk")) {
      const a = nb.a;
      const loS = a.from_;
      const hiS = truthy(a.to_) ? a.to_ : a.from_;
      const lo = pyInt(loS), hi = pyInt(hiS), nid = pyInt(nodeId);
      if (lo === null || hi === null || nid === null) continue; // int() aurait leve
      if (!(lo <= nid && nid <= hi)) continue;
      const nbDn = g.add(fab.node(nb, "nodeBlk", "leaf " + String(nodeId)));
      g.link(pathNodeDn, nbDn, "vers-leaf", "leaf " + String(nodeId));
    }
  }

  // 3. le port physique nomme dans le tDn -> port block, PUIS remontee vers
  //    l'IPG qui programme reellement ce port.
  //
  //    Le port block seul ne suffit pas : plusieurs leaves ont un eth1/1. On ne
  //    retient donc un selecteur QUE si son interface profile est rattache a un
  //    switch profile dont un node block couvre ce noeud.
  const port = tgt.port;
  const nodes = (tgt.nodes || []).map((n) => String(n));
  if (truthy(port)) {
    const m = /^eth(\d+)\/(\d+)$/.exec(port);
    if (m) {
      const card = m[1];
      const num = parseInt(m[2], 10);
      for (const blk of fab.cls("infraPortBlk")) {
        const a = blk.a;
        if (a.fromCard !== card) continue;
        const lo = pyInt(a.fromPort);
        const hi = pyInt(truthy(a.toPort) ? a.toPort : a.fromPort);
        if (lo === null || hi === null) continue;
        if (!(lo <= num && num <= hi)) continue;

        const hportsDn = rnParent(blk.dn);
        const profDn = rnParent(hportsDn);
        if (nodes.length && !profileCoversNodes(fab, profDn, nodes)) continue; // autre leaf

        const bDn = g.add(fab.node(blk, "portBlk", port));
        g.link(pathNodeDn, bDn, "vers-port", port);

        for (const rs of fab.cls("infraRsAccBaseGrp")) {
          if (rnParent(rs.dn) !== hportsDn) continue;
          const ipg = fab.byDn.get(getd(rs.a, "tDn", ""));
          if (!ipg) continue;
          const ipgDn = g.add(fab.node(ipg, "ipg", lagNote(ipg)));
          g.link(bDn, ipgDn, "vers-ipg", "port programme par l'IPG");
          g.link(pathNodeDn, ipgDn, "vers-ipg", "IPG de ce port");
          resolveIpgPorts(fab, ipg, g, ipgDn);
        }
      }
    }
  }
}

/** L'interface profile est-il applique a au moins un de ces noeuds ?
 *  infraAccPortP <- infraRsAccPortP(tDn) <- infraNodeP -> infraLeafS -> infraNodeBlk */
function profileCoversNodes(fab, ifaceProfileDn, nodeIds) {
  for (const rs of fab.revOf(ifaceProfileDn)) {
    if (rs.c !== "infraRsAccPortP") continue;
    const nprofDn = rnParent(rs.dn);
    for (const nb of fab.cls("infraNodeBlk")) {
      if (!nb.dn.startsWith(nprofDn + "/")) continue;
      const a = nb.a;
      const lo = pyInt(a.from_);
      const hi = pyInt(truthy(a.to_) ? a.to_ : a.from_);
      if (lo === null || hi === null) continue;
      for (const nid of nodeIds) {
        const n = pyInt(nid);
        if (n === null) continue;
        if (lo <= n && n <= hi) return true;
      }
    }
  }
  return false;
}

function resolveBd(fab, bd, g, bdDn) {
  for (const rsctx of fab.cls("fvRsCtx")) {
    if (rnParent(rsctx.dn) !== bd.dn) continue;
    const vrf = fab.inTenant(bd.dn, "fvCtx", rsctx.a.tnFvCtxName);
    if (vrf) g.link(bdDn, g.add(fab.node(vrf, "vrf")), "vers-vrf", "BD dans le VRF");
  }

  for (const sub of fab.cls("fvSubnet")) {
    if (!sub.dn.startsWith(bd.dn + "/")) continue;
    const sDn = g.add(fab.node(sub, "subnet", `scope ${S(getd(sub.a, "scope", "?"))}`));
    g.link(bdDn, sDn, "contient", "gateway");
  }

  for (const rso of fab.cls("fvRsBDToOut")) {
    if (rnParent(rso.dn) !== bd.dn) continue;
    const out = fab.inTenant(bd.dn, "l3extOut", rso.a.tnL3extOutName);
    if (out) g.link(bdDn, g.add(fab.node(out, "l3out")), "vers-l3out", "BD annonce via");
  }
}

/** Contrats fournis/consommes par un EPG, ESG ou ext-EPG.
 *  Les classes porteuses sont ENUMEREES explicitement : l3extInstP herite de
 *  extnw:EPg et non de fv:EPg, et mgmtInstP ne porte NI fvRsProv NI fvRsCons.
 *  Deriver l'ensemble par sous-classement donnerait un resultat faux. */
function resolveContracts(fab, ownerDn, g, ownerNodeDn) {
  for (const [cls, direction, attr] of [
    ["fvRsProv", "provide", "tnVzBrCPName"],
    ["fvRsCons", "consume", "tnVzBrCPName"],
    ["fvRsIntraEpg", "intra-epg", "tnVzBrCPName"],
  ]) {
    for (const rel of fab.cls(cls)) {
      if (rnParent(rel.dn) !== ownerDn) continue;
      const ctr = fab.inTenant(ownerDn, "vzBrCP", rel.a[attr]);
      if (!ctr) continue;
      const cDn = g.add(fab.node(ctr, "contract"));
      g.link(ownerNodeDn, cDn, direction, direction.toUpperCase());
      resolveContractDetail(fab, ctr, g, cDn);
    }
  }
}

function resolveContractDetail(fab, ctr, g, cDn) {
  for (const subj of fab.cls("vzSubj")) {
    if (rnParent(subj.dn) !== ctr.dn) continue;
    const sDn = g.add(fab.node(subj, "subject"));
    g.link(cDn, sDn, "contient", "subject");
    for (const rf of fab.cls("vzRsSubjFiltAtt")) {
      if (rnParent(rf.dn) !== subj.dn) continue;
      const flt = fab.inTenant(ctr.dn, "vzFilter", rf.a.tnVzFilterName);
      if (!flt) continue;
      const fDn = g.add(fab.node(flt, "filter"));
      g.link(sDn, fDn, "vers-filter", "filter");
      for (const ent of fab.cls("vzEntry")) {
        if (!ent.dn.startsWith(flt.dn + "/")) continue;
        const a = ent.a;
        let desc = getd(a, "prot", "");
        if (truthy(a.dFromPort) && a.dFromPort !== "unspecified") {
          desc += `/${a.dFromPort}`;
          if (truthy(a.dToPort) && a.dToPort !== a.dFromPort) desc += `-${a.dToPort}`;
        }
        g.link(fDn, g.add(fab.node(ent, "entry", truthy(desc) ? desc : null)),
          "contient", "entry");
      }
    }
  }
}

// ==========================================================================
// Recherche VLAN, tous fabrics
// ==========================================================================

/** Tous les EPG qui utilisent ce VLAN, avec TOUS leurs modes de deploiement.
 *
 *  Un EPG peut etre deploye des DEUX facons a la fois — static path binding ET
 *  via l'AAEP. Ne retenir que le premier mode rencontre serait un mensonge :
 *  d'ou le mode 'both' et le drapeau conflict. */
function findVlanUsers(fab, vlan) {
  const epgs = new Map();
  const bucket = (epg) => {
    let b = epgs.get(epg.dn);
    if (!b) { b = { epg, static: [], aaep: [] }; epgs.set(epg.dn, b); }
    return b;
  };

  for (const rsp of fab.cls("fvRsPathAtt")) {
    if (encapNum(rsp.a.encap) !== vlan) continue;
    const epg = fab.byDn.get(rnParent(rsp.dn));
    if (epg && (epg.c === "fvAEPg" || epg.c === "fvESg")) bucket(epg).static.push(rsp.dn);
  }

  for (const f of fab.cls("infraRsFuncToEpg")) {
    if (encapNum(f.a.encap) !== vlan) continue;
    const epg = fab.byDn.get(getd(f.a, "tDn", ""));
    if (epg) bucket(epg).aaep.push(f.dn);
  }

  for (const b of epgs.values()) {
    const ns = b.static.length, na = b.aaep.length;
    if (ns && na) {
      b.mode = "both";
      b.note = `deploye DES DEUX FACONS - ${ns} static path(s) ET ${na} deploiement(s) AAEP`;
    } else if (ns) {
      b.mode = "static-port";
      b.note = `deploiement static port (${ns} binding${ns > 1 ? "s" : ""})`;
    } else {
      b.mode = "aaep";
      b.note = `deploiement via AAEP (${na})`;
    }
  }
  return epgs;
}

/** Le VLAN porte-t-il une interface de L3Out ? (peering route)
 *
 *  Un VLAN dans un fabric n'est pas forcement un VLAN client : il peut etre un
 *  TRANSIT (sub-interface ou ext-svi de L3Out portant un peering BGP/OSPF/
 *  EIGRP). Un VLAN client aboutit sur un EPG, un VLAN de transit sort du
 *  fabric — la lecture de l'ecran change completement. */
function findVlanTransit(fab, vlan, g) {
  const found = [];
  for (const rp of fab.cls("l3extRsPathL3OutAtt")) {
    const a = rp.a;
    if (encapNum(a.encap) !== vlan) continue;
    const tgt = parsePathTdn(a.tDn);
    const pDn = g.add(fab.node(rp, "l3outPath",
      `${S(getd(a, "ifInstT", "?"))} ${S(getd(a, "addr", ""))} sur ${pathTargetLabel(tgt)}`));
    g.nodes.get(pDn).target = tgt;
    g.nodes.get(pDn).matchesQuery = true;
    if (tgt) linkPathToHardware(fab, tgt, g, pDn);

    const lifp = fab.byDn.get(rnParent(rp.dn));
    if (!lifp) { found.push(pDn); continue; }
    const lifpDn = g.add(fab.node(lifp, "l3outIfProfile"));
    g.link(lifpDn, pDn, "contient", "interface");

    const lnodep = fab.byDn.get(rnParent(lifp.dn));
    if (!lnodep) { found.push(pDn); continue; }
    const lnodepDn = g.add(fab.node(lnodep, "l3outNodeProfile"));
    g.link(lnodepDn, lifpDn, "contient", "logical interface profile");

    const outMo = fab.byDn.get(rnParent(lnodep.dn));
    if (!outMo) { found.push(pDn); continue; }
    const oDn = g.add(fab.node(outMo, "l3out"));
    g.link(oDn, lnodepDn, "contient", "logical node profile");

    // protocoles de routage portes par ce L3Out
    const protos = [];
    for (const [cls, name] of [["ospfExtP", "OSPF"], ["bgpExtP", "BGP"], ["eigrpExtP", "EIGRP"]]) {
      for (const pr of fab.cls(cls)) {
        if (rnParent(pr.dn) === outMo.dn) {
          protos.push(name);
          g.link(oDn, g.add(fab.node(pr, "routingProto", name)), "active", name);
        }
      }
    }
    for (const peer of fab.cls("bgpPeerP")) {
      if (peer.dn.startsWith(lnodep.dn + "/") || peer.dn.startsWith(lifp.dn + "/")) {
        protos.push("BGP");
        g.link(pDn, g.add(fab.node(peer, "bgpPeer", "peer " + S(getd(peer.a, "addr", "?")))),
          "peer", "voisin BGP");
      }
    }
    g.nodes.get(pDn).protocols = [...new Set(protos)].sort(cmpStr);

    // VRF du L3Out, et ext-EPG qu'il porte
    for (const rse of fab.cls("l3extRsEctx")) {
      if (rnParent(rse.dn) !== outMo.dn) continue;
      const vrf = fab.inTenant(outMo.dn, "fvCtx", rse.a.tnFvCtxName);
      if (vrf) g.link(oDn, g.add(fab.node(vrf, "vrf")), "vers-vrf", "L3Out dans le VRF");
    }
    for (const inst of fab.cls("l3extInstP")) {
      if (rnParent(inst.dn) !== outMo.dn) continue;
      const iDn = g.add(fab.node(inst, "extEpg"));
      g.link(oDn, iDn, "contient", "external EPG");
      resolveContracts(fab, inst.dn, g, iDn);
      for (const sub of fab.cls("l3extSubnet")) {
        if (rnParent(sub.dn) !== inst.dn) continue;
        const scopes = String(sub.a.scope || "").split(",").filter((s) => s !== "");
        const sDn = g.add(fab.node(sub, "l3extSubnet", scopes.join(", ")));
        g.nodes.get(sDn).roles = scopes.map(scopeRole);
        g.link(iDn, sDn, "contient", "prefixe externe");
      }
    }

    found.push(pDn);
  }
  return found;
}

function scopeRole(s) {
  const r = SCOPE_ROLE[s] || ["?", s, ""];
  return { scope: s, axis: r[0], gui: r[1], sens: r[2] };
}

export function resolveVlan(fabrics, vlan) {
  const out = { query: { type: "vlan", value: vlan }, fabrics: [] };
  for (const fab of fabrics) {
    const g = new Graph();
    const blocks = resolveAccessChain(fab, vlan, g);
    const transit = findVlanTransit(fab, vlan, g);
    const users = findVlanUsers(fab, vlan);

    // sorted(users.items()) : tri par DN, pour un ordre d'insertion identique
    // au Python (le test compare des ensembles, mais un ordre identique rend
    // un diff lisible).
    const userDns = [...users.keys()].sort(cmpStr);
    for (const dn of userDns) {
      const b = users.get(dn);
      const epgDn = resolveEpg(fab, b.epg, g, b.note, vlan);
      // Le mode est une DONNEE structuree, pas une phrase a analyser :
      // l'interface ne doit jamais avoir a deviner par regex sur `note`.
      g.nodes.get(epgDn).deployment = {
        mode: b.mode,
        staticPaths: b.static,
        aaepDeploys: b.aaep,
        conflict: b.mode === "both",
      };
    }

    // Le ROLE du VLAN dans ce fabric : client (aboutit sur un EPG), transit
    // (porte un peering route et sort du fabric), ou les deux.
    let roles = [];
    const nUsers = users.size;
    if (nUsers) roles.push("client");
    if (transit.length) roles.push("transit");
    const protoSet = new Set();
    for (const dn of transit) {
      for (const p of (g.nodes.get(dn).protocols || [])) protoSet.add(p);
    }
    const protos = [...protoSet].sort(cmpStr);

    let status, summary;
    if (nUsers || transit.length) {
      status = "deployed";
      const bits = [];
      if (nUsers) {
        let nboth = 0;
        for (const b of users.values()) if (b.mode === "both") nboth += 1;
        bits.push(`${nUsers} EPG client${nUsers > 1 ? "s" : ""}`);
        if (nboth) bits.push(`${nboth} en DOUBLE deploiement`);
      }
      if (transit.length) {
        bits.push(`${transit.length} interface${transit.length > 1 ? "s" : ""} de L3Out`
          + (protos.length ? ` (${protos.join(", ")})` : ""));
      }
      summary = bits.join(" - ");
    } else if (blocks.length) {
      status = "pool-only";
      summary = "present dans un pool, aucun EPG ne l'utilise";
      roles = [];
    } else {
      status = "absent";
      summary = "aucune correspondance";
      roles = [];
    }

    // Diagnostic sur l'IPG. L'absence d'IPG n'est pas un silence : c'est un
    // fait de configuration. Un VLAN deploye via un AAEP auquel aucun interface
    // policy group n'est rattache n'atteint AUCUNE interface physique — il est
    // configure mais inerte.
    const warnings = [];
    const allNodes = [...g.nodes.values()];
    const ipgNodes = allNodes.filter((n) => n.kind === "ipg");
    if ((nUsers || transit.length) && ipgNodes.length === 0) {
      const aaeps = allNodes.filter((n) => n.kind === "aaep");
      const hasStatic = allNodes.some((n) => n.kind === "staticPath" && truthy(n.matchesQuery));
      if (aaeps.length && !hasStatic) {
        warnings.push({
          code: "aaep-sans-ipg",
          gravite: "haute",
          titre: "Ce VLAN n'atteint aucune interface",
          detail: "Deploye via l'AAEP "
            + aaeps.map((n) => n.label).sort(cmpStr).join(", ")
            + ", mais aucun interface policy group (infraRsAttEntP) n'est "
            + "rattache a cet AAEP, et aucun static path binding ne porte "
            + "l'encapsulation. La chaine s'arrete avant le port physique.",
        });
      } else {
        warnings.push({
          code: "ipg-non-resolu",
          gravite: "moyenne",
          titre: "IPG non resolu",
          detail: "Aucune des trois routes n'a abouti : ni depuis l'AAEP "
            + "(infraRsAttEntP), ni depuis le nom d'IPG d'un vPC, ni depuis le "
            + "port physique (port block -> port selector -> infraRsAccBaseGrp).",
        });
      }
    }

    out.fabrics.push({
      id: fab.id,
      status,
      summary,
      warnings,
      backup: { file: nullish(fab.meta.srcFile), generatedAt: nullish(fab.meta.generatedAt) },
      roots: blocks,
      roles,
      protocols: protos,
      transitPaths: transit,
      nodes: g.nodesObject(),
      edges: g.edges,
    });
  }
  return out;
}

// dict.get(k) sur cle absente vaut None -> null, pas undefined (que
// JSON.stringify supprimerait de l'objet).
function nullish(v) {
  return v === undefined ? null : v;
}

// ==========================================================================
// Recherche subnet, tous fabrics
// ==========================================================================

export function resolveSubnet(fabrics, query) {
  let qnet = parseIpNetwork(query, false);
  if (!qnet) {
    // Repli identique au Python : on isole la partie adresse et on force /32.
    // Oui, /32 sur une IPv6 est etrange — c'est ce que fait la reference, et le
    // contrat est l'egalite, pas la correction.
    const ip = parseIpAddress(String(query).split("/")[0]);
    if (!ip) throw new Error("adresse invalide : " + query);
    qnet = parseIpNetwork(ipToString(ip) + "/32", false);
    if (!qnet) throw new Error("adresse invalide : " + query);
  }

  const out = { query: { type: "subnet", value: netToString(qnet) }, fabrics: [] };
  for (const fab of fabrics) {
    const g = new Graph();
    const hits = [];

    for (const sub of fab.cls("fvSubnet")) {
      const ip = sub.a.ip;
      if (!truthy(ip)) continue;
      const net = parseIpInterfaceNetwork(ip);
      if (!net) continue;
      const kind = matchKind(qnet, net);
      if (!kind) continue;
      const bd = fab.byDn.get(rnParent(sub.dn));
      const sDn = g.add(fab.node(sub, "subnet",
        `gateway ${S(ip)} - scope ${S(getd(sub.a, "scope", "?"))}`));
      hits.push({ dn: sDn, role: "bd-gateway", match: kind });
      if (bd && bd.c === "fvBD") {
        const bdDn = g.add(fab.node(bd, "bd"));
        g.link(bdDn, sDn, "contient", "gateway");
        resolveBd(fab, bd, g, bdDn);
        // fvRsBd pointe par NOM : on balaye tout le fabric puis on filtre sur
        // l'egalite de tenant, faute d'index inverse par nom.
        for (const rsbd of fab.cls("fvRsBd")) {
          if (rsbd.a.tnFvBDName !== bd.a.name) continue;
          const epg = fab.byDn.get(rnParent(rsbd.dn));
          if (epg && Fabric.tenantOf(epg.dn) === Fabric.tenantOf(bd.dn)) {
            resolveEpg(fab, epg, g);
          }
        }
      }
    }

    for (const sub of fab.cls("l3extSubnet")) {
      const ip = sub.a.ip;
      if (!truthy(ip)) continue;
      const net = parseIpNetwork(ip, false);
      if (!net) continue;
      const kind = matchKind(qnet, net);
      if (!kind) continue;
      const scopes = String(sub.a.scope || "").split(",").filter((s) => s !== "");
      const roles = scopes.map(scopeRole);
      const sDn = g.add(fab.node(sub, "l3extSubnet", scopes.join(", ")));
      g.nodes.get(sDn).roles = roles;
      hits.push({
        dn: sDn,
        role: "l3ext-subnet",
        match: kind,
        scopes,
        securite: roles.some((r) => r.axis === "securite"),
        routage: roles.some((r) => r.axis === "routage"),
      });
      const inst = fab.byDn.get(rnParent(sub.dn));
      if (inst && inst.c === "l3extInstP") {
        const iDn = g.add(fab.node(inst, "extEpg"));
        g.link(iDn, sDn, "contient", "declare le prefixe");
        resolveContracts(fab, inst.dn, g, iDn);
        const outMo = fab.byDn.get(rnParent(inst.dn));
        if (outMo && outMo.c === "l3extOut") {
          const oDn = g.add(fab.node(outMo, "l3out"));
          g.link(iDn, oDn, "contenu-dans", "dans le L3Out");
          for (const rse of fab.cls("l3extRsEctx")) {
            if (rnParent(rse.dn) !== outMo.dn) continue;
            const vrf = fab.inTenant(outMo.dn, "fvCtx", rse.a.tnFvCtxName);
            if (vrf) g.link(oDn, g.add(fab.node(vrf, "vrf")), "vers-vrf", "L3Out dans le VRF");
          }
        }
      }
    }

    out.fabrics.push({
      id: fab.id,
      status: hits.length ? "hit" : "absent",
      summary: hits.length ? `${hits.length} correspondance(s)` : "aucune correspondance",
      backup: { file: nullish(fab.meta.srcFile), generatedAt: nullish(fab.meta.generatedAt) },
      hits,
      nodes: g.nodesObject(),
      edges: g.edges,
    });
  }
  return out;
}

function ipToString(ip) {
  return netToString({ version: ip.version, addr: ip.addr, prefix: ip.bits, bits: ip.bits })
    .split("/")[0];
}

// ==========================================================================
// Chargement
// ==========================================================================

/** json = {fabrics:[{meta,mos}]} -> objet opaque a passer aux resolveurs.
 *  L'ordre du tableau fixe l'ordre des fabrics en sortie : il doit etre celui
 *  du Python, qui trie les fichiers .fl.json.gz par nom. C'est le producteur du
 *  bundle qui en repond, pas ce module. */
export function loadFabrics(json) {
  const doc = typeof json === "string" ? JSON.parse(json) : json;
  return (doc.fabrics || []).map((f) => new Fabric(f));
}

/* FL:CLI-ONLY — tout ce qui suit est retire par build_page.py.
   Cette partie n'existe que pour le test differentiel sous node : elle
   utilise import.meta, qui est une ERREUR DE SYNTAXE hors module. La
   laisser dans la page fait echouer le parsing du bloc entier, donc
   window.FLResolve n'est jamais defini - et la page se charge quand
   meme, l'air de rien. Le marqueur ci-dessous n'est pas decoratif. */
// ==========================================================================
// Entree ligne de commande (node) — sert au test differentiel.
//
// L'import de node:fs est DYNAMIQUE et conditionne : un import statique ferait
// echouer le chargement du module dans un navigateur, ou ce fichier doit vivre
// inline dans une page unique.
// ==========================================================================

(async function cliMain() {
  if (typeof process === "undefined" || !process.argv || process.argv.length < 3) return;
  const entry = String(process.argv[1] || "").replace(/\\/g, "/");
  if (!entry || !import.meta.url.endsWith(entry.split("/").pop())) return;

  const args = process.argv.slice(2);
  let data = null, vlan = null, subnet = null;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--vlan") vlan = parseInt(args[++i], 10);
    else if (args[i] === "--subnet") subnet = args[++i];
    else if (args[i] === "--data") data = args[++i];
    else if (data === null) data = args[i];
  }
  if (!data || (vlan === null && !subnet)) {
    process.stderr.write("usage: node resolve.js <fabrics.json> --vlan N | --subnet CIDR\n");
    process.exit(2);
  }
  // `node resolve.js ... | head` ferme le tube : sans ce garde-fou node leve un
  // EPIPE non capture et sort en erreur alors que le travail est fait.
  process.stdout.on("error", (e) => { if (e && e.code === "EPIPE") process.exit(0); });
  const { readFileSync } = await import("node:fs");
  const F = loadFabrics(readFileSync(data, "utf-8"));
  const res = vlan !== null ? resolveVlan(F, vlan) : resolveSubnet(F, subnet);
  process.stdout.write(JSON.stringify(res));
})();
