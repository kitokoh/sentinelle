{{/*
Helpers de la charte Sentinelle.
Les identifiants techniques restent en anglais ; les commentaires expliquent le
POURQUOI des choix, pas la mécanique évidente du YAML.
*/}}

{{/*
sentinelle.name — nom de la charte, surchargeable par `nameOverride`.
*/}}
{{- define "sentinelle.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{/*
sentinelle.fullname — préfixe commun de toutes les ressources.
Si la release porte déjà le nom de la charte (`helm install sentinelle …`), on
évite le doublon « sentinelle-sentinelle » qui alourdirait les noms DNS.
*/}}
{{- define "sentinelle.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end }}

{{/*
sentinelle.componentName — nom d'une ressource appartenant à un composant.
Contexte attendu : `dict "root" $ "component" "api"`.
Le composant fait partie du nom (et non seulement des libellés) pour que
`kubectl get deploy` soit lisible sans filtrage.
*/}}
{{- define "sentinelle.componentName" -}}
{{- printf "%s-%s" (include "sentinelle.fullname" .root) .component | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{/*
sentinelle.selectorLabels — libellés IMMUABLES.
Un Deployment refuse de changer son sélecteur : on n'y met donc que des valeurs
qui ne bougent jamais (ni version, ni numéro de build de la charte).
*/}}
{{- define "sentinelle.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sentinelle.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
sentinelle.labels — libellés communs recommandés par la convention Kubernetes.
Ils s'ajoutent aux sélecteurs et peuvent, eux, évoluer (version de charte,
version applicative) : c'est ce qui rend un rollout traçable dans `kubectl get`.
*/}}
{{- define "sentinelle.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "sentinelle.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: sentinelle
{{- end }}

{{/*
sentinelle.componentLabels — libellés d'un composant (sélecteurs + composant).
Contexte attendu : `dict "root" $ "component" "api"`.
*/}}
{{- define "sentinelle.componentLabels" -}}
{{ include "sentinelle.labels" .root }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/*
sentinelle.componentSelectorLabels — sélecteurs d'un composant.
`component` est immuable pour un Deployment donné, il peut donc figurer dans
`spec.selector.matchLabels` sans bloquer les mises à jour.
*/}}
{{- define "sentinelle.componentSelectorLabels" -}}
{{ include "sentinelle.selectorLabels" .root }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/*
sentinelle.serviceAccountName — compte de service réellement utilisé.
On retombe explicitement sur `default` plutôt que d'inventer un nom quand la
création est désactivée, sinon les pods ne démarrent pas.
*/}}
{{- define "sentinelle.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "sentinelle.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end }}

{{/*
sentinelle.configMapName / sentinelle.nginxConfigMapName / sentinelle.secretName
— noms des objets partagés, centralisés pour qu'un renommage ne se disperse pas
dans six fichiers.
*/}}
{{- define "sentinelle.configMapName" -}}
{{- printf "%s-config" (include "sentinelle.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{- define "sentinelle.nginxConfigMapName" -}}
{{- printf "%s-web-nginx" (include "sentinelle.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{- define "sentinelle.secretName" -}}
{{- if .Values.existingSecret -}}
{{- .Values.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "sentinelle.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end }}

{{/*
sentinelle.redisName — nom du Service Redis, partagé par le ConfigMap (REDIS_HOST)
et par le Deployment Redis : les deux doivent désigner exactement la même chose.
*/}}
{{- define "sentinelle.redisName" -}}
{{- printf "%s-redis" (include "sentinelle.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{/*
sentinelle.redisHost — hôte Redis effectif : le Service interne si le Redis de
démonstration est déployé, l'hôte externe sinon. Centraliser ce choix évite que
le ConfigMap et le Deployment divergent.
*/}}
{{- define "sentinelle.redisHost" -}}
{{- if .Values.redis.enabled -}}
{{- include "sentinelle.redisName" . -}}
{{- else -}}
{{- .Values.redis.external.host -}}
{{- end -}}
{{- end }}

{{/*
sentinelle.image — référence complète `<repository>:<tag>`.
Un tag vide retombe sur appVersion de la charte : une montée de version ne
demande donc pas de modifier quatre tags dans values.yaml.
Contexte attendu : `dict "repository" … "tag" … "appVersion" …`.
*/}}
{{- define "sentinelle.image" -}}
{{- printf "%s:%s" .repository (.tag | default .appVersion) -}}
{{- end }}

{{/*
sentinelle.imagePullPolicy — politique de pull d'un composant, avec repli sur
le réglage global.
Contexte attendu : `dict "component" "api" "root" $`.
*/}}
{{- define "sentinelle.imagePullPolicy" -}}
{{- (index .root.Values .component).image.pullPolicy | default .root.Values.image.pullPolicy -}}
{{- end }}

{{/*
sentinelle.podSecurityContext / sentinelle.containerSecurityContext — contexte
de sécurité effectif : défauts durcis de `securityContext` fusionnés avec la
surcharge éventuelle du composant.
`deepCopy` est obligatoire : `mergeOverwrite` modifie son premier argument, et
écraserait donc les défauts globaux pour les composants suivants.
Les LISTES (capabilities.drop/add) sont REMPLACÉES et non fusionnées : une
surcharge qui ajoute des capacités doit redéclarer le `drop: [ALL]`.
Contexte attendu : `dict "root" $ "component" "worker"`.
*/}}
{{- define "sentinelle.podSecurityContext" -}}
{{- $overrides := (index .root.Values .component).securityContext | default dict -}}
{{- toYaml (mergeOverwrite (deepCopy .root.Values.securityContext.pod) ($overrides.pod | default dict)) -}}
{{- end }}

{{- define "sentinelle.containerSecurityContext" -}}
{{- $overrides := (index .root.Values .component).securityContext | default dict -}}
{{- toYaml (mergeOverwrite (deepCopy .root.Values.securityContext.container) ($overrides.container | default dict)) -}}
{{- end }}

{{/*
sentinelle.commonEnv — environnement partagé par l'API et le worker.

Point d'attention : Kubernetes n'étend `$(VAR)` que vers des variables
déclarées AVANT dans la liste. Les briques (DATABASE_HOST, POSTGRES_PASSWORD…)
sont donc obligatoirement placées avant les URL composées DATABASE_URL /
REDIS_URL. C'est ce qui permet de garder le mot de passe dans le Secret sans
dupliquer l'URL complète dans values.yaml.

Le mot de passe est inséré brut dans l'URL : il doit être compatible URL
(au besoin, fournir DATABASE_URL complète via `extraEnv`).
Contexte attendu : `root` = $.
*/}}
{{- define "sentinelle.commonEnv" -}}
{{- $ssl := "" -}}
{{- if .root.Values.postgresql.sslMode -}}
{{- $ssl = printf "?ssl=%s" .root.Values.postgresql.sslMode -}}
{{- end -}}
- name: ENV
  valueFrom:
    configMapKeyRef:
      name: {{ include "sentinelle.configMapName" .root }}
      key: ENV
- name: DATABASE_HOST
  valueFrom:
    configMapKeyRef:
      name: {{ include "sentinelle.configMapName" .root }}
      key: DATABASE_HOST
- name: DATABASE_PORT
  valueFrom:
    configMapKeyRef:
      name: {{ include "sentinelle.configMapName" .root }}
      key: DATABASE_PORT
- name: DATABASE_NAME
  valueFrom:
    configMapKeyRef:
      name: {{ include "sentinelle.configMapName" .root }}
      key: DATABASE_NAME
- name: DATABASE_USER
  valueFrom:
    configMapKeyRef:
      name: {{ include "sentinelle.configMapName" .root }}
      key: DATABASE_USER
- name: POSTGRES_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "sentinelle.secretName" .root }}
      key: postgresql-password
- name: DATABASE_URL
  value: {{ printf "postgresql+asyncpg://$(DATABASE_USER):$(POSTGRES_PASSWORD)@$(DATABASE_HOST):$(DATABASE_PORT)/$(DATABASE_NAME)%s" $ssl | quote }}
  # NOTE : quand `postgresql.sslMode` est renseigné, il est ajouté ici sous la
  # forme attendue par le dialecte asyncpg (`?ssl=require`).
- name: REDIS_HOST
  valueFrom:
    configMapKeyRef:
      name: {{ include "sentinelle.configMapName" .root }}
      key: REDIS_HOST
- name: REDIS_PORT
  valueFrom:
    configMapKeyRef:
      name: {{ include "sentinelle.configMapName" .root }}
      key: REDIS_PORT
- name: REDIS_URL
  value: {{ printf "redis://$(REDIS_HOST):$(REDIS_PORT)" | quote }}
- name: JWT_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ include "sentinelle.secretName" .root }}
      key: jwt-secret
# Référence INCONDITIONNELLE, même quand la valeur n'est pas fournie à Helm :
# un opérateur qui renseigne « field-encryption-key » dans son Secret externe
# doit être pris en compte, ce que ferait rater un `if` sur .Values.secret.
# `optional: true` garantit qu'une clé absente n'empêche pas le démarrage.
- name: FIELD_ENCRYPTION_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "sentinelle.secretName" .root }}
      key: field-encryption-key
      optional: true
- name: OIDC_ISSUER
  valueFrom:
    configMapKeyRef:
      name: {{ include "sentinelle.configMapName" .root }}
      key: OIDC_ISSUER
- name: OIDC_CLIENT_ID
  valueFrom:
    configMapKeyRef:
      name: {{ include "sentinelle.configMapName" .root }}
      key: OIDC_CLIENT_ID
- name: OIDC_REDIRECT_URI
  valueFrom:
    configMapKeyRef:
      name: {{ include "sentinelle.configMapName" .root }}
      key: OIDC_REDIRECT_URI
# `optional: true` : l'absence du SSO, d'une clé d'API ou du jeton /metrics est
# un cas NOMINAL (la fonctionnalité se désactive), pas une erreur de démarrage.
- name: OIDC_CLIENT_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ include "sentinelle.secretName" .root }}
      key: oidc-client-secret
      optional: true
- name: METRICS_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ include "sentinelle.secretName" .root }}
      key: metrics-token
      optional: true
- name: MISP_URL
  valueFrom:
    configMapKeyRef:
      name: {{ include "sentinelle.configMapName" .root }}
      key: MISP_URL
- name: MISP_API_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "sentinelle.secretName" .root }}
      key: misp-api-key
      optional: true
- name: OTX_API_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "sentinelle.secretName" .root }}
      key: otx-api-key
      optional: true
- name: CERT_FEEDS
  valueFrom:
    configMapKeyRef:
      name: {{ include "sentinelle.configMapName" .root }}
      key: CERT_FEEDS
- name: RETENTION_DAYS
  valueFrom:
    configMapKeyRef:
      name: {{ include "sentinelle.configMapName" .root }}
      key: RETENTION_DAYS
- name: FRONTEND_URL
  valueFrom:
    configMapKeyRef:
      name: {{ include "sentinelle.configMapName" .root }}
      key: FRONTEND_URL
{{- end }}
