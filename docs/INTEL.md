# Renseignement — brancher les sources et comprendre la corrélation

> v0.4. Ce document couvre les issues #6 (MISP), #7 (OTX), #8 (flux CERT) et #9
> (corrélation). Il est écrit pour être lu par quelqu'un qui doit brancher une
> source en production, pas seulement par un développeur.

## Vue d'ensemble

```
MISP ─┐
OTX  ─┼─▶ connecteurs ─▶ normalisation ─▶ `iocs` (1 ligne par (type, valeur))
CERT ─┘                                        │
   (avis) ──────────────▶ `intel_feed_items`    │
                                                ▼
                    corrélation ◀── alertes + constats observés
                          │
                          ▼
                 `alerts` source="intel", sévérité ≥ high
```

## Brancher MISP (#6)

```bash
MISP_URL=https://misp.exemple.gouv
MISP_API_KEY=<clé d'un compte de service en lecture seule>
MISP_LOOKBACK_DAYS=30
MISP_ATTRIBUTE_LIMIT=500
```

- Le connecteur interroge `POST /attributes/restSearch` (types réseau, hash et
  e-mail uniquement, indicateurs `to_ids: true`) et **place la clé dans l'en-tête
  `Authorization`**, jamais dans le corps : une clé passée en corps finit dans les
  journaux du serveur MISP.
- Le niveau de menace de l'événement MISP (`threat_level_id`) devient la sévérité
  de l'indicateur ; le nom de l'événement et ses tags sont conservés en métadonnées.
- **Dégradation propre** : instance injoignable, clé invalide ou réponse illisible
  → le cycle se termine avec 0 indicateur et une ligne de journal. Le worker ne
  tombe jamais à cause d'une source de renseignement.

## Brancher AlienVault OTX (#7)

```bash
OTX_API_KEY=<clé API OTX>
OTX_PULSE_LIMIT=20
```

Les *pulses* souscrits sont récupérés (indicateurs uniquement, pas les rapports),
puis normalisés par la **même** couche que MISP. Un indicateur présent dans un
pulse OTX et dans un événement MISP donne **une seule ligne** dont `sources`
contient `misp,otx`.

Sans clé, la tâche est marquée `skipped` — jamais en échec.

## Brancher les flux CERT (#8)

```bash
CERT_FEEDS=CERT-FR=https://www.cert.ssi.gouv.fr/feed/,CISA=https://www.cisa.gov/cybersecurity-advisories/all.xml
CERT_ITEMS_PER_FEED=50
```

- Format : `NOM=URL`, séparés par des virgules ou des retours à la ligne. Sans
  nom, l'hôte du flux sert de nom.
- RSS 2.0 et Atom sont acceptés, sans dépendance externe.
- Dédoublonnage sur le **GUID** du flux (repli : le lien) : repoller un flux ne
  duplique jamais un avis.
- **Un flux cassé n'empêche pas les autres** : le document illisible est journalisé
  et ignoré.

## La corrélation (#9)

Elle compare les indicateurs détenus à ce que la plateforme a réellement observé :
les alertes (capteur et moteurs de règles) et les constats (nmap, nuclei, CVE).

| Type d'indicateur | Ce qui est comparé |
|---|---|
| `ip` | `src_ip` et `dst_ip` des alertes |
| `domain`, `url`, `md5`, `sha1`, `sha256`, `email` | le texte de `detail` et `signature` des alertes, et `detail` des constats |

Trois règles de conception, à connaître avant de régler quoi que ce soit :

1. **Une correspondance est au minimum « élevée ».** Un indicateur publié n'est pas
   une observation anodine ; le rétrograder le noierait dans le flux. Un indicateur
   `critical` reste `critical`.
2. **Une correspondance n'est signalée qu'une fois, définitivement.** La clé de
   dédoublonnage contient l'indicateur *et* l'entité touchée ; contrairement au
   moteur de détection, il n'y a **pas** de fenêtre temporelle. Rescanner une machine
   ne re-signale pas un indicateur déjà remonté.
3. **Une alerte de renseignement ne se corrèle jamais avec elle-même.** Le filtre
   `source != "intel"` évite la boucle qui transformerait le corrélateur en
   amplificateur.

Deux garde-fous bornent le volume : au plus 25 correspondances par indicateur et
200 alertes créées par cycle. Au-delà, le compteur `alerts_skipped` le dit
explicitement dans le journal du worker.

## Planification

| Tâche | Fréquence |
|---|---|
| `sync_misp` | 4×/jour (00:20, 06:20, 12:20, 18:20) |
| `sync_otx` | 4×/jour (00:35, 06:35, 12:35, 18:35) |
| `sync_cert` | toutes les heures (à la minute 25) |
| `correlate_intel` | toutes les 15 min (05, 20, 35, 50) |

Les connecteurs sont volontairement décalés pour que deux sources ne tapent
jamais la même minute. En démonstration, `POST /api/intel/sync` déclenche un
cycle complet à la demande (réponse `202`, ou `503` avec un message explicite si
Redis n'est pas joignable).

## La carte des campagnes (#10)

La carte n'affiche que les indicateurs pour lesquels **un flux a fourni des
coordonnées** (`latitude`/`longitude`, `lat`/`lon` ou un objet `geo` dans les
métadonnées). Aucun indicateur n'est envoyé à un service de géolocalisation pour
être positionné : une plateforme souveraine n'ajoute pas un tiers dans la chaîne
juste pour dessiner un point.

Conséquence assumée : sans coordonnées dans les flux, la carte est vide. C'est
un état normal, pas une anomalie — les tuiles proviennent d'OpenStreetMap et le
message affiché le dit.

## Diagnostic

| Symptôme | Cause probable |
|---|---|
| `status: skipped` sur `sync_misp` | `MISP_URL` ou `MISP_API_KEY` non défini |
| `status: skipped` sur `sync_cert` | `CERT_FEEDS` vide |
| 0 indicateur, journal « unreachable » | réseau, DNS ou certificat côté source |
| Beaucoup de `alerts_skipped` | plafond de 200 par cycle atteint — vérifier les indicateurs trop génériques |
| Carte vide | les flux ne fournissent pas de coordonnées |
