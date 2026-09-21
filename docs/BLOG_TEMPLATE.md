# Trame d'article technique

> Une trame, pas un modèle à remplir. Les quatre sections ci-dessous sont celles
> qu'un lecteur technique vient chercher ; ce qui change d'un article à l'autre,
> c'est ce qu'on met dedans, pas l'ordre.

## Pourquoi écrire à chaque version

Un projet qu'on ne raconte pas n'existe pas. La publication a trois effets
concrets, dans cet ordre d'importance :

1. **Elle force la clarté.** Un choix d'architecture qu'on n'arrive pas à
   expliquer en trois paragraphes est souvent un choix qu'on n'a pas vraiment
   compris.
2. **Elle laisse une trace datée.** Dans six mois, « pourquoi avons-nous fait
   ça ? » trouvera une réponse écrite plutôt qu'un souvenir.
3. **Elle se voit.** Un recruteur, un jury, un pair lit un article plus vite
   qu'il ne lit un dépôt.

## Trame

### 1. Contexte — le problème avant la solution

- Quelle version livrée, quelle fonctionnalité.
- **Quel problème concret** elle résout, formulé du point de vue de l'utilisateur.
- Ce qui existait avant, et pourquoi c'était insuffisant.

À éviter : commencer par la liste des technologies. Personne ne lit un article
pour apprendre qu'un projet utilise FastAPI.

### 2. Décision d'architecture — ce qu'on a choisi, et ce qu'on a écarté

- Les 2 ou 3 options réellement envisagées.
- Le critère de décision (pas « c'est mieux », mais *mesurable* : moins de
  dépendances natives, testable sans infrastructure, réversible).
- **Ce qu'on renonce à gagner.** Une décision sans coût n'est pas une décision.
- Les libraries/technos retenues, avec la raison — pas la description.

C'est la section qui distingue un article technique d'un journal de bord.
`docs/PRA.md`, `docs/SECRETS.md` et `docs/DETECTION.md` contiennent déjà la
matière : ce sont les arbitrages écrits au moment où ils ont été pris.

### 3. Difficulté — ce qui n'a pas marché du premier coup

- Le problème imprévu, avec le **message d'erreur exact**.
- Pourquoi c'était difficile à voir (l'environnement de test masquait-il le bug ?).
- Comment on l'a trouvé, puis corrigé.
- Ce qu'on a changé pour que la classe de bug ne revienne pas.

C'est la section la plus lue, et celle que la plupart des articles sautent. Un
article qui ne raconte que des succès n'apprend rien.

### 4. Résultat — mesuré, pas affirmé

- Ce que la fonctionnalité fait, avec un **chiffre vérifiable** : tests ajoutés,
  couverture, latence, nombre de requêtes, taille d'image.
- Une commande que le lecteur peut lancer pour le constater lui-même.
- Ce qui reste ouvert, explicitement.

## Ce que la trame n'impose pas

- La longueur : 800 mots suffisent si les quatre sections tiennent.
- Le ton : le plus direct possible. « Nous avons essayé X, ça a échoué, voici
  pourquoi » vaut mieux qu'une justification rétroactive.
- Les captures : utiles, jamais décoratives.

## Où publier et comment référencer

L'article vit dans `docs/blog/<AAAA-MM>-v<version>-<sujet>.md`. Le README pointe
vers la liste, et `docs/ROADMAP.md` marque la case correspondante. Un article non
référencé ne sera pas trouvé.
