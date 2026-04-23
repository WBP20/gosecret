# gosecret

Partage de secrets **chiffre de bout en bout** avec **question contextuelle** (numero
de commande, nom du N+1, reference interne...), concu pour resister au scenario
principal : **compromission de la boite mail du destinataire**.

## Modele de securite

Deux couches independantes :

1. **E2EE (AES-256-GCM)** — Le navigateur genere une cle aleatoire, chiffre le
   secret localement, envoie uniquement le ciphertext au serveur, et place la
   cle dans le `#fragment` de l'URL. Les navigateurs ne transmettent jamais le
   fragment au serveur. Le serveur n'a donc **jamais** acces au texte clair.

2. **Question contextuelle (HMAC serveur)** — La reponse attendue est
   normalisee (trim, lowercase, strip accents) puis transformee en
   `HMAC-SHA256(server_secret, secret_id || normalized_answer)` et stockee.
   Elle n'est **jamais utilisee comme cle** — seulement comme porte d'acces au
   ciphertext. Le `server_secret` empeche toute attaque brute-force offline en
   cas de fuite de la base.

Le secret est **a usage unique** : une fois delivre il est marque consomme et
purge.

### Ce que cela protege
- Interception/forward du mail
- Acces a posteriori a la boite mail
- Fuite de la base (reponses non brute-forcables sans le `server.key`)

### Ce que cela ne protege pas
- Attaquant interne ayant le contexte metier
- Compromission du serveur *en cours* d'operation

## Flux complet

```
creation :
  navigateur  ──[ genere cle AES-256 ]──> chiffre le secret localement
  navigateur  ──[ POST /api/secrets { ciphertext, iv, question?, answer? } ]──> serveur
  serveur     ──[ genere id aleatoire 128-bit, stocke en BoltDB ]──> retourne { id, url }
  navigateur  ──[ construit url: /s/{id}#{cle_base64url} ]──> affiche le lien

lecture :
  navigateur  ──[ GET /s/{id} ]──> serveur retourne la page HTML (sans le ciphertext)
  navigateur  ──[ GET /api/secrets/{id} ]──> serveur retourne les metadonnees
              (has_question, question, remaining_attempts, expired, consumed, locked)
  si challenge :
    navigateur  ──[ POST /api/secrets/{id}/unlock { answer } ]──> serveur verifie le HMAC
  sinon :
    navigateur  ──[ POST /api/secrets/{id}/consume ]──> serveur delivre le ciphertext
  serveur     ──[ efface ciphertext+IV+answer_hash de la BDD ]──> retourne { ciphertext, iv }
  navigateur  ──[ dechiffre avec la cle du #fragment ]──> affiche le secret en clair
```

Le `#fragment` n'est **jamais transmis au serveur** (RFC 3986). Le serveur fait le
lien entre l'URL et le ciphertext uniquement via l'`id` dans le path (`/s/{id}`).

## Purge automatique

Une goroutine interne (`StartPurger`) tourne toutes les 5 minutes et :
- supprime les secrets dont `expires_at + grace` est depasse
- supprime les secrets consommes depuis plus d'1 minute (grace period)
- nettoie les buckets du rate limiter inutilises depuis 1h

Aucun cron externe n'est necessaire.

## Structure de la base (BoltDB)

Un seul bucket `secrets`, cle = `id` (string), valeur = JSON :

```json
{
  "id":    "dG9rZW4tMTIzNDU2Nzg",
  "ct":    "<ciphertext bytes>",
  "iv":    "<iv bytes>",
  "q":     "numero de commande ?",
  "ah":    "<HMAC-SHA256 de la reponse>",
  "ma":    5,
  "at":    0,
  "exp":   "2026-04-21T18:00:00Z",
  "cat":   null,
  "uat":   null,
  "ct_at": "2026-04-20T18:00:00Z"
}
```

| Champ   | Description                                                      |
|---------|------------------------------------------------------------------|
| `id`    | Identifiant aleatoire 128-bit (base64url)                        |
| `ct`    | Ciphertext AES-256-GCM (efface apres consume)                   |
| `iv`    | Vecteur d'initialisation (efface apres consume)                  |
| `q`     | Question challenge (optionnelle)                                 |
| `ah`    | `HMAC-SHA256(server_key, id \|\| answer_normalise)` (optionnel)  |
| `ma`    | Nombre max de tentatives challenge                               |
| `at`    | Nombre de tentatives echouees                                    |
| `exp`   | Date d'expiration                                                |
| `cat`   | Date de consommation (null si non consomme)                      |
| `uat`   | Date de deverrouillage (null si non deverrouille)                |
| `ct_at` | Date de creation                                                 |

Apres consommation : `ct`, `iv` et `ah` sont mis a `null` dans la BDD, puis la
purge les supprime physiquement apres la grace period.

## Compromission de `server.key`

**Risque** : un attaquant avec `server.key` + acces a la BDD peut recalculer les
HMAC et brute-forcer offline les reponses aux questions secretes. S'il devine la
reponse, il peut appeler `/unlock` et obtenir le ciphertext.

**Ce qu'il ne peut PAS faire** : dechiffrer les secrets. La cle AES est dans le
`#fragment`, jamais stockee cote serveur. Sans le lien complet, le ciphertext
est inutile.

**Mitigations** :
- Permissions fichier `0600`, auto-corrigees au chargement
- TTL court des secrets (defaut 24h) — fenetre d'exploitation reduite
- Rotation possible : generer un nouveau `server.key`, les anciens secrets
  avec challenge deviennent inverifiables (= verrouilles de fait)
- Isoler le serveur (conteneur, VM dediee)
- Monitoring des acces au fichier (`auditd`, etc.)

## Deploiement (Docker + Caddy)

Le moyen le plus simple de deployer gosecret en production avec TLS automatique.

### Prerequis

- Un VPS Linux avec Docker et Docker Compose
- Un nom de domaine pointe vers l'IP du VPS (A record)

### Lancement

```sh
git clone <repo> && cd gosecret

# Configurer le domaine
cp .env.example .env
nano .env   # DOMAIN=secret.example.com

# Lancer
docker compose up -d --build
```

Caddy obtient automatiquement un certificat Let's Encrypt au premier acces,
le renouvelle tout seul, et proxie HTTPS vers gosecret. Rien d'autre a configurer.

### Volumes persistes

| Volume          | Contenu                                |
|-----------------|----------------------------------------|
| `gosecret-data` | BoltDB (`gosecret.db`) + `server.key`  |
| `caddy-data`    | Certificats TLS (Let's Encrypt)        |
| `caddy-config`  | Configuration Caddy runtime            |

### Backup

```sh
# Sauvegarder la BDD et la cle serveur
docker compose cp gosecret:/app/data ./backup
```

**`server.key` est critique** : le perdre invalide tous les challenges existants.

### Logs

```sh
docker compose logs -f gosecret   # logs applicatifs (creations, echecs unlock)
docker compose logs -f caddy      # logs acces HTTP / TLS
```

## Lancement local (sans Docker)

```sh
go build -o gosecret .
./gosecret -addr :8080 -data ./data -base-url https://secret.example.com
```

Options :
- `-addr` : adresse d'ecoute (defaut `:8080`)
- `-data` : repertoire de stockage (BoltDB + `server.key`, defaut `./data`)
- `-base-url` : URL publique utilisee dans les liens generes
- `-trust-proxy` : faire confiance au header `X-Forwarded-For` (uniquement derriere un reverse proxy)

Au premier demarrage, un `server.key` aleatoire (32 octets) est cree dans
`-data`. **Sauvegardez-le** : le perdre invalide tous les challenges existants.

## Architecture

```
gosecret/
├── main.go                       # bootstrap, flags, shutdown propre
├── Dockerfile                    # multi-stage build (alpine ~15MB)
├── docker-compose.yml            # gosecret + Caddy TLS
├── Caddyfile                     # reverse proxy config
├── .env.example                  # DOMAIN=secret.example.com
├── internal/
│   ├── store/store.go            # persistance BoltDB
│   └── server/
│       ├── server.go             # routes HTTP + handlers
│       ├── crypto.go             # HMAC, normalisation, generation d'IDs
│       ├── ratelimit.go          # token-bucket par IP (/64 pour IPv6)
│       └── crypto_test.go
└── web/                          # frontend (embarque via //go:embed)
    ├── create.html / create.js   # page de creation
    ├── view.html   / view.js     # page de dechiffrement
    ├── crypto.js                 # helpers WebCrypto
    └── style.css
```

## API

| Methode | Chemin                          | Role                                         |
|---------|----------------------------------|----------------------------------------------|
| POST    | `/api/secrets`                   | Cree un secret, retourne `id` et `url`       |
| GET     | `/api/secrets/{id}`              | Metadonnees (question, expiration, tentatives)|
| POST    | `/api/secrets/{id}/unlock`       | Verifie la reponse, retourne le ciphertext   |
| POST    | `/api/secrets/{id}/consume`      | Recupere un secret sans question             |
| GET     | `/s/{id}`                        | Page de dechiffrement (HTML)                 |
| GET     | `/healthz`                       | Healthcheck                                  |

## Securites implementees

- E2EE AES-256-GCM, cle uniquement dans le `#fragment`
- HMAC-SHA256 avec `server.key` pour les reponses challenge
- Comparaison constant-time (`hmac.Equal`)
- IDs aleatoires 128-bit (non enumerables)
- Wipe des donnees sensibles apres consume (ciphertext, IV, answer_hash)
- Limites de tentatives par secret (defaut 5, max 20), verrouillage definitif
- Rate-limiting par IP (token bucket, normalisation IPv6 /64)
- Purge automatique des secrets expires / consommes
- CSP stricte, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, HSTS
- `Cache-Control: no-store` sur toutes les reponses
- Pas de directory listing sur `/static/`
- `MaxBytesReader` sur tous les endpoints POST
- Capacity check atomique (pas de TOCTOU)
- `history.replaceState` pour supprimer la cle de l'URL apres dechiffrement

## Tests

```sh
go test ./...
```

## Limitations connues

- BoltDB est single-writer : convient pour un serveur unique, pas pour du
  multi-instance. Migrer vers PostgreSQL pour du HA.
- Pas d'auth emetteur : toute personne pouvant atteindre l'instance peut creer
  un secret. Mettre derriere un reverse-proxy authentifie si necessaire.
- Le rate-limit en memoire disparait au redemarrage.
