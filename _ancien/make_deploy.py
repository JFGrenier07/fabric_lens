#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
make_deploy.py — fabrique le dossier à copier sur le poste Windows.

    python3 make_deploy.py            -> deploy/FabricLens/  +  FabricLens.zip

Pourquoi un script plutôt qu'un dossier versionné : `deploy/` ne contient que des
COPIES des fichiers sources. Versionner les deux, c'est garantir qu'un jour l'un
sera corrigé et pas l'autre — et le bogue apparaîtra chez l'utilisateur, pas ici.
Le dossier est donc généré à la demande et ignoré par git.

Le gabarit est copié tel quel : `web/gabarit.html` est déjà vide de données,
c'est `build_page.py` qui les injecte sur la RHEL.
"""

import os
import shutil
import sys
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))

# source → destination dans le paquet
FICHIERS = [
    ("scripts/fabric-lens-fetch.bat", "scripts/fabric-lens-fetch.bat"),
    ("scripts/fabrics.example.csv",   "scripts/fabrics.example.csv"),
    ("scripts/remote/fl_extract.py",  "scripts/remote/fl_extract.py"),
    ("fabriclens/resolve.py",         "fabriclens/resolve.py"),
    ("fabriclens/build_page.py",      "fabriclens/build_page.py"),
    ("web/resolve.js",                "web/resolve.js"),
    ("web/selfcheck.js",              "web/selfcheck.js"),
    ("web/gabarit.html",              "web/gabarit.html"),
    ("docs/LISEZ-MOI.txt",            "LISEZ-MOI.txt"),
]


def main():
    dest = os.path.join(ROOT, "deploy", "FabricLens")
    if os.path.isdir(os.path.join(ROOT, "deploy")):
        shutil.rmtree(os.path.join(ROOT, "deploy"))

    manquants = [s for s, _ in FICHIERS if not os.path.isfile(os.path.join(ROOT, s))]
    if manquants:
        sys.stderr.write("[X] fichiers source absents :\n")
        for m in manquants:
            sys.stderr.write("    %s\n" % m)
        return 2

    total = 0
    for src, rel in FICHIERS:
        cible = os.path.join(dest, rel)
        d = os.path.dirname(cible)
        if not os.path.isdir(d):
            os.makedirs(d)
        shutil.copy2(os.path.join(ROOT, src), cible)
        total += os.path.getsize(cible)
        print("  %7d o  %s" % (os.path.getsize(cible), rel))

    # le dossier ou l'application atterrira
    os.makedirs(os.path.join(dest, "data"), exist_ok=True)
    open(os.path.join(dest, "data", ".gardez-moi"), "w").write(
        "L'application (fabric-lens.html) sera deposee ici par le .bat.\n")

    # garde-fou : le gabarit ne doit contenir AUCUNE donnee
    with open(os.path.join(dest, "web", "gabarit.html"), encoding="utf-8") as fh:
        g = fh.read()
    if '"mos":[{' in g or '"fabrics":[{' in g:
        sys.stderr.write("[X] web/gabarit.html contient des donnees inlinees.\n"
                         "    Le paquet expedierait la config d'un labo chez le client.\n")
        return 2

    zpath = os.path.join(ROOT, "FabricLens.zip")
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for base, _dirs, files in os.walk(dest):
            for f in files:
                p = os.path.join(base, f)
                z.write(p, os.path.relpath(p, os.path.join(ROOT, "deploy")))

    print("\n  %d fichiers, %.0f Ko" % (len(FICHIERS), total / 1024.0))
    print("  %s (%.0f Ko)" % (zpath, os.path.getsize(zpath) / 1024.0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
