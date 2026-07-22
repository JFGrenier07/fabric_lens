/* Auto-vérification du résolveur, sans rien faire sortir du réseau.
   ---------------------------------------------------------------------------
   Le résolveur JS est une réécriture du résolveur Python. On veut la vérifier
   sur les VRAIES données du client, dont le réseau est fermé. La RHEL calcule
   donc l'empreinte de chaque requête possible (`resolve.py --digests`), la page
   recalcule et compare. Rien ne sort : l'empreinte est produite et consommée
   sur la même machine, et ne permet de reconstituer ni DN, ni IP, ni tenant.

   SHA-256 en JS pur, DÉLIBÉRÉMENT : `crypto.subtle` n'existe que dans un
   « contexte sécurisé » (HTTPS ou localhost). Mesuré : absent en HTTP simple.
   L'application doit tourner depuis un file:// sur un poste Windows verrouillé,
   donc aucune dépendance à une API conditionnelle. */

const K = new Uint32Array([
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);

const rotr = (x, n) => (x >>> n) | (x << (32 - n));

/** SHA-256 d'une chaîne UTF-8 -> hex minuscule. */
export function sha256hex(str) {
  const bytes = new TextEncoder().encode(str);
  const len = bytes.length;
  const withPad = (((len + 8) >> 6) + 1) << 6;      // multiple de 64, place pour 1+longueur
  const buf = new Uint8Array(withPad);
  buf.set(bytes);
  buf[len] = 0x80;
  const bits = len * 8;
  const dv = new DataView(buf.buffer);
  // longueur sur 64 bits big-endian ; len*8 tient largement dans 53 bits
  dv.setUint32(withPad - 8, Math.floor(bits / 4294967296));
  dv.setUint32(withPad - 4, bits >>> 0);

  const H = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                             0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
  const w = new Uint32Array(64);
  for (let off = 0; off < withPad; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >>> 3);
      const s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >>> 10);
      w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0;
    }
    let [a,b,c,d,e,f,g,h] = H;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
      const mj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + mj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0]=(H[0]+a)>>>0; H[1]=(H[1]+b)>>>0; H[2]=(H[2]+c)>>>0; H[3]=(H[3]+d)>>>0;
    H[4]=(H[4]+e)>>>0; H[5]=(H[5]+f)>>>0; H[6]=(H[6]+g)>>>0; H[7]=(H[7]+h)>>>0;
  }
  let out = "";
  for (let i = 0; i < 8; i++) out += H[i].toString(16).padStart(8, "0");
  return out;
}

/** Forme canonique d'un graphe — doit rester alignée sur `_canon()` en Python. */
export function canon(graph) {
  return JSON.stringify(graph.fabrics.map(f => ({
    edges: f.edges.map(e => `${e.from}>${e.to}|${e.rel}`).sort(),
    hits: (f.hits || []).map(h => `${h.dn}|${h.role}|${h.match}`).sort(),
    id: f.id,
    nodes: Object.keys(f.nodes).sort(),
    protocols: f.protocols || [],
    roles: f.roles || [],
    status: f.status,
    summary: f.summary,
  })));
}

export const digestOf = graph => sha256hex(canon(graph)).slice(0, 16);

/** Rejoue toutes les requêtes de référence. Retourne {total, ok, ko:[...]}. */
export function selfCheck(resolver, F, digests) {
  const ko = [];
  let total = 0;
  for (const [v, d] of Object.entries(digests.vlan || {})) {
    total++;
    if (digestOf(resolver.resolveVlan(F, Number(v))) !== d) ko.push("vlan " + v);
  }
  for (const [s, d] of Object.entries(digests.subnet || {})) {
    total++;
    try {
      if (digestOf(resolver.resolveSubnet(F, s)) !== d) ko.push("subnet " + s);
    } catch (e) { ko.push("subnet " + s + " (exception)"); }
  }
  return { total, ok: total - ko.length, ko };
}
