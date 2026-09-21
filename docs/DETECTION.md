# Détection — écrire et régler une règle

> v0.3 « Défense ». Ce document est la référence pour ajouter une règle sans
> toucher au code. Il est volontairement court : si une règle ne s'explique pas
> en dix lignes, c'est qu'elle est mal conçue.

## Vue d'ensemble

```
capteur Suricata ──eve.json──▶ worker: ingest_eve (toutes les 15 s)
                                   │
                                   ├─ 1. déduplication sur event_id
                                   ├─ 2. insertion dans `sensor_events` (tout l'événement)
                                   ├─ 3. event_type == "alert" → `alerts` (source=suricata)
                                   └─ 4. moteur de règles sur la fenêtre glissante
                                          → `alerts` (source=rule, rule_name, confidence)
```

Le point important : **le moteur raisonne sur une fenêtre d'événements bruts**,
pas sur des alertes déjà produites. C'est ce qui rend le balayage de ports, la
force brute et le beaconing détectables — trois signatures qui n'existent que
dans la comparaison entre plusieurs événements.

## Où vivent les règles

`backend/rules/detection.yaml` — chargé au démarrage de chaque cycle
d'ingestion. Le chemin est surchargeable par `DETECTION_RULES_PATH`.

Si le fichier est absent, le moteur retombe sur le jeu de règles intégré :
perdre silencieusement toute capacité de détection serait le pire des scénarios.

## Les trois moteurs disponibles

| `kind` | Ce qu'il détecte | Clé de regroupement |
|---|---|---|
| `port_scan` | une même source contactant **plus de `threshold` ports distincts** | `src_ip` |
| `ssh_bruteforce` | plus de `threshold` tentatives SSH de la même source vers la même destination | `(src_ip, dst_ip)` |
| `beaconing` | au moins `min_samples` connexions vers la même destination, à intervalle **régulier** | `(src_ip, dst_ip, dst_port)` |

## Le format d'une règle

```yaml
version: 1

rules:
  - name: port_scan              # identifiant unique (repris dans les alertes)
    kind: port_scan              # moteur à utiliser
    severity: high               # info | low | medium | high | critical
    window_seconds: 60           # fenêtre glissante observée
    threshold: 20                # seuil de déclenchement (strictement supérieur)
    description: >
      Ce que la règle détecte, en une phrase exploitable par un analyste.
```

Champs spécifiques au beaconing :

```yaml
  - name: beaconing
    kind: beaconing
    severity: medium
    window_seconds: 3600
    threshold: 5                 # nombre minimal de connexions
    min_samples: 5               # échantillons requis pour tester la régularité
    max_interval_cv: 0.25        # coefficient de variation toléré des intervalles
```

### Valider avant de committer

```bash
make rules          # liste les règles effectivement chargées
cd backend && pytest tests/test_detection.py -q
```

Une erreur de frappe sur un `kind` fait **échouer le chargement** avec un
`ValueError`. Une règle silencieusement ignorée serait un angle mort invisible :
on préfère un échec bruyant.

## Comprendre la confiance

`confidence` est une **marge au-dessus du seuil**, pas une probabilité :

| Moteur | Formule | Lecture |
|---|---|---|
| `port_scan` | `min(1, ports_distincts / (2 × threshold))` | 0,5 ≈ seuil à peine franchi, 1,0 ≈ deux fois le seuil |
| `ssh_bruteforce` | `min(1, tentatives / (2 × threshold))` | idem |
| `beaconing` | `1 − coefficient_de_variation` | 1,0 = intervalle parfaitement régulier |

L'interface l'affiche en pourcentage. Une confiance basse n'est pas un faux
positif : c'est une invitation à regarder la fenêtre d'événements.

## Le cycle de vie d'une alerte

1. **Déduplication.** Une détection est identifiée par une clé stable
   (`<kind>|<src_ip>|<dst_ip>|<dst_port>`). Tant que l'activité se poursuit dans
   la fenêtre de la règle, l'alerte existante voit son compteur `occurrences`
   s'incrémenter au lieu d'en créer une nouvelle — c'est l'anti-tempête.
2. **Acquittement.** `PATCH /api/alerts/{id}` avec `{"status": "ack"}`
   enregistre l'auteur et l'horodatage. Une alerte acquittée **n'est pas
   rouverte** par le trafic suivant : un humain l'a acceptée.
3. **Rétention.** Les alertes plus vieilles que `RETENTION_DAYS` (défaut 90 j)
   sont purgées par le job quotidien. Voir `app/services/retention.py`.

Les alertes de signature Suricata (`source: suricata`) ne sont **pas**
dédupliquées : le capteur gère lui-même sa suppression, et une alerte de
signature est une observation ponctuelle, pas un compteur.

## Ajouter un moteur

1. Écrire `_eval_<kind>(rule, events, now) -> list[Detection]` dans
   `app/services/detection.py`. La fonction doit être **pure** : la fenêtre
   d'événements est son unique entrée, ce qui la rend testable sans base.
2. L'enregistrer dans `_EVALUATORS` et ajouter le `kind` à `KINDS`.
3. Documenter la règle dans la table ci-dessus.
4. Deux fixtures de test obligatoires : une qui **déclenche**, une qui **ne
   déclenche pas**.

## Régler sans se tromper

- **Faux positifs** → augmenter `threshold`, pas `window_seconds` : réduire la
  fenêtre rend la détection plus nerveuse, pas plus précise.
- **Beaconing bruyant** → baisser `max_interval_cv` (0,15 est un bon point de
  départ pour un C2 réel) et augmenter `min_samples`.
- **Scan interne légitime** (inventaire, Nessus) → exclure la source en amont
  du capteur plutôt que de relever le seuil pour tout le monde.
