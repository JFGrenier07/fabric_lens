#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_page.py — assemble `fabric-lens.html`, l'application d'un seul fichier.

Tourne SUR LA RHEL, chaque matin, juste après `fl_extract.py`.
Prend les fichiers distillés (un `.fl.json.gz` par fabrique) et le gabarit HTML,
et produit UNE page autonome que le `.bat` rapatrie et que l'utilisateur ouvre
par double-clic. Aucun Python, aucun serveur, aucun réseau côté Windows.

    fl_extract.py   →  out/<fabric>.fl.json.gz   (N fichiers)
    build_page.py   →  fabric-lens.html          (1 fichier)

CONTRAINTE, comme partout dans ce projet : bibliothèque standard uniquement.

CE QUI EST SUBSTITUÉ
Le gabarit délimite ses zones variables par des sentinelles explicites :

    <!-- FL:BLOCK <nom> src=... xform=... -->  …  <!-- FL:END <nom> -->

  fabrics    les données du jour, toutes fabriques confondues
  digests    l'empreinte de chaque requête possible, pour que le résolveur
             JavaScript se vérifie tout seul sans que rien ne sorte du réseau
  resolve    web/resolve.js, transformé pour vivre dans la page
  selfcheck  web/selfcheck.js, idem
  stamp      le repère de version affiché en bas à droite

Tout le reste du gabarit est recopié à l'octet près.
"""

from __future__ import print_function

import argparse
import gzip
import hashlib
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import resolve as R                                          # noqa: E402

BUILDER_VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# Rassemblement des fabriques
# ---------------------------------------------------------------------------

def bundle_fabrics(distilled_dir):
    """Fusionne les .fl.json.gz en un objet unique {"fabrics":[{meta,mos}]}.

    L'ORDRE EST FIGÉ : tri par nom de fichier, exactement comme
    `resolve.load_fabrics()`. Le résolveur JavaScript ne retrie pas — il suit
    l'ordre du tableau. Si les deux divergeaient, les empreintes calculées ici
    ne correspondraient plus à ce que la page recalcule, et l'auto-vérification
    crierait à tort.
    """
    out = []
    names = sorted(n for n in os.listdir(distilled_dir)
                   if n.endswith(".fl.json.gz"))
    if not names:
        die("aucun fichier .fl.json.gz dans %s" % distilled_dir)
    for name in names:
        path = os.path.join(distilled_dir, name)
        with gzip.open(path, "rb") as fh:
            doc = json.loads(fh.read().decode("utf-8"))
        out.append({"meta": doc["meta"], "mos": doc["mos"]})
    return {"fabrics": out}, names


# ---------------------------------------------------------------------------
# Mise en page des modules JavaScript
# ---------------------------------------------------------------------------

# Marqueur EXPLICITE, pose dans le source. Une heuristique sur des libelles de
# commentaire a deja echoue silencieusement : la queue CLI etait restee, son
# `import.meta` faisait echouer le parsing du bloc entier, `window.FLResolve`
# n'etait jamais defini - et la page se chargeait quand meme, sans une erreur.
CLI_MARKER = "/* FL:CLI-ONLY"

# Ce qui n'a RIEN A FAIRE dans un <script> classique. Si l'un survit a la
# transformation, le bloc ne parsera pas et la page sera muette.
INTERDITS_JS = ("import.meta", "node:fs", "process.argv", "require(")


def inline_js(src_path, global_name):
    """Transforme un module ES en bloc <script> inline.

    QUATRE transformations, et la quatrième est un piège qui a déjà mordu :

    1. `export ` retiré — un module ES ne peut pas être inliné tel quel.
    2. La queue CLI (usage sous node) retirée : elle importe `node:fs`, qui
       n'existe pas dans un navigateur.
    3. Les octets NUL littéraux échappés en `\\u0000`. `resolve.js` en contient
       cinq, utilisés comme séparateurs de clés d'index. Recopiés bruts dans du
       HTML, le parseur les remplace par U+FFFD — les clés d'index changent
       silencieusement, et la page fonctionne QUAND MÊME, à ceci près que
       l'auto-vérification passerait au vert sur un résolveur abîmé.
    4. Le tout enveloppé dans une IIFE qui expose les fonctions sur `window`.
    """
    with open(src_path, "r", encoding="utf-8") as fh:
        code = fh.read()

    # 2. couper la queue CLI sur le marqueur explicite
    i = code.find(CLI_MARKER)
    if i >= 0:
        code = code[:i]

    # 1. retirer les mots-clés export, et collecter ce qui était exporté
    exported = []
    for m in re.finditer(r"^export\s+(?:async\s+)?(?:function|const|let|class)\s+(\w+)",
                         code, re.M):
        exported.append(m.group(1))
    for m in re.finditer(r"^export\s*\{([^}]*)\}", code, re.M):
        for piece in m.group(1).split(","):
            piece = piece.strip().split(" as ")[-1].strip()
            if piece:
                exported.append(piece)
    code = re.sub(r"^export\s+", "", code, flags=re.M)
    code = re.sub(r"^export\s*\{[^}]*\}\s*;?\s*$", "", code, flags=re.M)

    # 3. les NUL littéraux
    n_nul = code.count("\0")
    code = code.replace("\0", "\\u0000")

    # 4. l'enveloppe
    seen, uniq = set(), []
    for name in exported:
        if name not in seen:
            seen.add(name)
            uniq.append(name)
    # Garde-fou : ce qui suit ne parse pas hors module.
    restants = [x for x in INTERDITS_JS if x in code]
    if restants:
        die("%s : apres transformation, il reste %s. Le bloc ne parserait pas et "
            "la page serait muette. Verifier le marqueur %s dans le source."
            % (os.path.basename(src_path), ", ".join(restants), CLI_MARKER))
    if not uniq:
        die("%s : aucun export detecte - window.%s serait vide"
            % (os.path.basename(src_path), global_name))

    expose = ", ".join("%s: %s" % (n, n) for n in uniq)
    head = ("/* %s — recopie fidèle. export retiré, queue CLI retirée"
            "%s. */\n;(function () { \"use strict\";\n"
            % (os.path.relpath(src_path, os.path.dirname(os.path.dirname(
                os.path.abspath(src_path)))),
               (", %d octet(s) NUL échappé(s)" % n_nul) if n_nul else ""))
    tail = "\nwindow.%s = { %s };\n})();" % (global_name, expose)
    return head + code + tail, uniq, n_nul


# ---------------------------------------------------------------------------
# Substitution dans le gabarit
# ---------------------------------------------------------------------------

def replace_block(html, nom, contenu):
    """Remplace ce qui est ENTRE les sentinelles, sentinelles comprises."""
    ouvre = re.search(r"<!--\s*FL:BLOCK\s+%s\b[^>]*-->" % re.escape(nom), html)
    ferme = re.search(r"<!--\s*FL:END\s+%s\s*-->" % re.escape(nom), html)
    if not ouvre or not ferme or ferme.start() < ouvre.end():
        die("sentinelles FL:BLOCK %s absentes ou mal ordonnees dans le gabarit" % nom)
    return html[:ouvre.end()] + "\n" + contenu + "\n" + html[ferme.start():]


def warn(msg):
    sys.stderr.write("[!] %s\n" % msg)


def die(msg):
    sys.stderr.write("[X] %s\n" % msg)
    sys.stdout.write("FL-BUILD-FAIL\n")
    sys.exit(2)


def human(n):
    for u in ("o", "Ko", "Mo"):
        if n < 1024.0:
            return "%.1f %s" % (n, u)
        n /= 1024.0
    return "%.1f Go" % n


def main(argv):
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--distilled", required=True,
                    help="repertoire des .fl.json.gz produits par fl_extract.py")
    ap.add_argument("--template", default=os.path.join(root, "prototypes", "app-prise-2.html"),
                    help="gabarit HTML porteur des sentinelles FL:BLOCK")
    ap.add_argument("--out", default=os.path.join(root, "fabric-lens.html"))
    ap.add_argument("--js-dir", default=os.path.join(root, "web"))
    ap.add_argument("--no-digests", action="store_true",
                    help="ne pas calculer les empreintes (build plus rapide, "
                         "mais la page ne peut plus se verifier elle-meme)")
    args = ap.parse_args(argv[1:])

    t0 = time.time()
    print("Fabric Lens - assemblage de la page (v%s, python %d.%d)"
          % (BUILDER_VERSION, sys.version_info[0], sys.version_info[1]))

    if not os.path.isfile(args.template):
        die("gabarit introuvable : %s" % args.template)
    with open(args.template, "r", encoding="utf-8") as fh:
        html = fh.read()

    # --- 1. les donnees --------------------------------------------------
    bundle, names = bundle_fabrics(args.distilled)
    nmos = sum(len(f["mos"]) for f in bundle["fabrics"])
    print("  %d fabrique(s), %d objets" % (len(bundle["fabrics"]), nmos))
    for f in bundle["fabrics"]:
        m = f["meta"]
        alias = m.get("fabricAlias") or ""
        print("      %-16s %5d objets  %s%s"
              % (m.get("fabric", "?"), len(f["mos"]), m.get("srcFile", "?"),
                 ("  (%s)" % alias) if alias else ""))
    data_json = json.dumps(bundle, ensure_ascii=False, separators=(",", ":"))
    html = replace_block(html, "fabrics",
                         '<script type="application/json" id="fl-fabrics-data">'
                         + data_json + "</script>")

    # --- 2. les empreintes ------------------------------------------------
    if args.no_digests:
        warn("empreintes non calculees : la page ne pourra pas se verifier")
        dig = {"vlan": {}, "subnet": {}}
    else:
        fabs = R.load_fabrics(args.distilled)
        dig = R.build_digests(fabs)
        print("  empreintes : %d VLAN + %d subnet"
              % (len(dig["vlan"]), len(dig["subnet"])))
    dig_json = json.dumps(dig, sort_keys=True, separators=(",", ":"))
    html = replace_block(html, "digests",
                         '<script type="application/json" id="fl-digests-data">'
                         + dig_json + "</script>")

    # --- 3. les modules JavaScript ----------------------------------------
    for nom, fichier, glob in (("resolve", "resolve.js", "FLResolve"),
                               ("selfcheck", "selfcheck.js", "FLSelfCheck")):
        path = os.path.join(args.js_dir, fichier)
        if not os.path.isfile(path):
            die("module introuvable : %s" % path)
        code, exported, n_nul = inline_js(path, glob)
        print("  %-10s %-14s %s, %d export(s)%s"
              % (nom, fichier, human(len(code)), len(exported),
                 (", %d NUL echappe(s)" % n_nul) if n_nul else ""))
        html = replace_block(html, nom, "<script>\n" + code + "\n</script>")

    # --- 4. le tampon de version ------------------------------------------
    stamp_time = time.strftime("%Y-%m-%d %H:%M")
    sig = hashlib.sha256((data_json + dig_json).encode("utf-8")).hexdigest()[:6]
    stamp = ('<span id="fl-build" title="Repere de version. Fusionne avec le '
             'resultat de l\'auto-verification du resolveur.">build %s &#183; %s</span>'
             % (stamp_time, sig))
    html = replace_block(html, "stamp", stamp)

    # --- 5. garde-fous avant d'ecrire -------------------------------------
    problemes = []
    if re.search(r"<script[^>]+\bsrc\s*=", html):
        problemes.append("un <script src=...> subsiste : la page ne serait pas autonome")
    if re.search(r"<link[^>]+\bhref\s*=", html):
        problemes.append("un <link href=...> subsiste")
    if "\0" in html:
        problemes.append("des octets NUL bruts subsistent (ils seraient corrompus "
                         "en U+FFFD par le parseur HTML)")
    for nom in ("fabrics", "digests", "resolve", "selfcheck", "stamp"):
        if ("FL:BLOCK %s" % nom) not in html:
            problemes.append("sentinelle FL:BLOCK %s perdue - la page ne sera "
                             "plus reconstructible demain" % nom)
    if problemes:
        for p in problemes:
            warn(p)
        die("%d probleme(s) : rien n'a ete ecrit" % len(problemes))

    tmp = args.out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(html)
    os.rename(tmp, args.out)          # ecriture atomique

    print("\n  %s  (%s)  build %s - %s"
          % (args.out, human(os.path.getsize(args.out)), stamp_time, sig))
    print("  assemble en %.1f s" % (time.time() - t0))
    print("RESULT_FILE=%s" % os.path.basename(args.out))
    print("FL-BUILD-OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
