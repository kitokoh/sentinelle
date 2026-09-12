# Règles d'engagement — Sentinelle

Sentinelle est une plateforme **d'audit autorisé**. Son usage est conditionné au
respect strict des règles ci-dessous. Elles ne sont pas décoratives : le
garde-fou principal est **implémenté côté serveur** (`backend/app/services/scope.py`).

## Périmètre autorisé par défaut

- Adresses privées RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
- Loopback et link-local (IPv4 & IPv6 : `127.0.0.0/8`, `169.254.0.0/16`, `::1`,
  `fe80::/10`, ULA `fc00::/7`)
- Noms d'hôte de laboratoire : `.lab`, `.local`, `.test`, `.internal`, `.example`

## Hors périmètre

Toute cible publique est **refusée** par défaut. Elle n'est acceptée qu'avec une
`authorization_reference` non vide — la référence d'une **autorisation écrite**
(contrat de pentest, bon de commande, lettre de mission) conservée par
l'opérateur. Cette référence est stockée en base avec la cible : traçabilité.

## Obligations de l'opérateur

1. Ne scanner que des systèmes que vous possédez ou pour lesquels vous détenez
   une autorisation écrite et en cours de validité.
2. Conserver les autorisations et les journaux (qui a scanné quoi, quand, avec
   quelle référence).
3. Respecter les lois applicables — en France : art. 323-1 et suivants du Code
   pénal. L'accès ou le maintien frauduleux dans un système est un délit, même
   « pour tester ».
4. Les découvertes sur des systèmes tiers se traitent en **divulgation
   responsable**, jamais en exploitation.

## Signalement d'une vulnérabilité dans Sentinelle

Ouvrir une issue GitHub **sans détail exploitable**, ou contacter le mainteneur
directement. Correctifs bienvenus via PR.
