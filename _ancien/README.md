# Ancien flux « page assemblée »

Conservé, pas supprimé. Ce dossier contient le flux où la RHEL assemblait la
page HTML complète (données inline) et où le .bat la rapatriait telle quelle.

Il fonctionne toujours (`build_page.py --distilled`), mais il n'est plus le
flux recommandé. Le flux courant est plus simple :

    RHEL  : python3 fl_extract.py           -> fabriclens-data.json
    .bat  : le rapatrie
    webui : bouton « Charger »

Voir la racine du dépôt et docs/DEMARRAGE-SIMPLE.txt.
