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

## Limites de taille du payload

Le champ `payload` (le secret a transmettre) est cape cote serveur. Voici ce
qui passe et ce qui ne passe pas :

| Donnee                                | Taille typique | Verdict |
|---------------------------------------|----------------|---------|
| Mot de passe / passphrase             | < 100 octets   | OK      |
| Token API / JWT                       | 0.5 - 2 KB     | OK      |
| Cle SSH Ed25519 privee                | ~400 octets    | OK      |
| Cle SSH RSA-2048 privee               | ~1.7 KB        | OK      |
| Cle SSH RSA-4096 privee               | ~3.2 KB        | OK      |
| Cle SSH RSA-8192 privee (paranoide)   | ~6.5 KB        | OK      |
| Dossier `~/.ssh/` complet (concatene) | ~30 KB         | OK      |
| Certificat TLS + cle privee           | 5 - 10 KB      | OK      |
| Bloc de configuration `kubeconfig`    | 5 - 20 KB      | OK      |
| Plaintext arbitraire                  | jusqu'a ~64 KB | OK      |
| Photo / binaire / wallet              | > 64 KB        | refuse  |

**Plafond effectif : ~64 KB de plaintext.** Au-dela, le serveur retourne
`bad_ciphertext`. Pour transmettre des fichiers volumineux, le pattern
recommande reste : un canal pour le fichier (storage chiffre, S3, etc.) et
gosecret pour le mot de passe / la cle de dechiffrement.

### Bornes serveur

| Limite                  | Valeur          | Source                           |
|-------------------------|-----------------|----------------------------------|
| Body HTTP create        | 128 KB          | `MaxBytesReader` sur `/api/secrets` |
| Ciphertext (post-base64)| 64 KB           | `Config.MaxCiphertextBytes`     |
| Question                | 512 octets      | `Config.MaxQuestionBytes`       |
| Reponse challenge       | 1024 octets     | `Config.MaxAnswerBytes`         |
| Secrets actifs total    | 10 000          | `Config.MaxActiveSecrets`       |
| En-tetes HTTP           | 16 KB           | `http.Server.MaxHeaderBytes`    |

Avec `MaxActiveSecrets * MaxCiphertextBytes = 640 MB` au pire cas pour les
ciphertexts en BDD. Le hard-cap renvoie `503 capacity` une fois atteint, donc
pas de saturation disque silencieuse.

## Pistes d'amelioration

### Argon2id sur la reponse challenge

**Aujourd'hui** : la reponse au challenge est verifiee via
`HMAC-SHA256(server_secret, id || normalize(answer))`. HMAC est rapide
(~100 ns), donc si **DB et `server.key` fuitent simultanement**, un attaquant
peut tester ~1 milliard de reponses par seconde sur GPU. Pour des reponses
faibles ("Jean Dupont", "ORD-12345"), c'est cassable en quelques secondes.

**Avec Argon2id** :
`AnswerHash = Argon2id(salt=id, key=server_secret, password=normalize(answer), t=3, m=64MB, p=1)`

| Aspect              | HMAC (actuel) | Argon2id        |
|---------------------|---------------|-----------------|
| Latence par essai   | < 1 ms        | 100 - 300 ms    |
| RAM par essai       | ~0            | 64 MB           |
| Brute-force GPU     | 1e9 essais/s  | 10 - 100 essais/s |
| Gain securite       | -             | ~10^7x          |

**A considerer si** : le modele de menace inclut le dump simultane de
`/app/data` (DB + `server.key`).

**A ne pas faire si** : la menace principale reste la boite mail compromise
— HMAC + rate-limit (5 tentatives par secret + 0.2 rps par IP) suffit deja.

**Risque a prevoir** : amplification DoS RAM. Mitiger via worker-pool borne
(max N calculs Argon2 paralleles) ou parametres modestes (16 MB / 50 ms).

### Rotation de `server.key`

**Probleme** : `server.key` est unique pour tous les `AnswerHash`. La perdre
invalide tous les challenges actifs ; la voir compromise impose de tout
regenerer.

**Approche** : versioning des cles + champ `KeyVersion` sur `Secret` +
re-HMAC paresseux au unlock. Schema :

1. `/data/server.key.1`, `server.key.2`, ... avec un pointeur `current`.
2. `Secret` stocke `KeyVersion` au moment de la creation.
3. Au unlock, le serveur charge la cle correspondant a `KeyVersion`. Si la
   reponse est valide ET la version est ancienne, il re-HMAC avec la version
   courante et persiste.
4. Flag CLI `gosecret -rotate-key` genere `server.key.N+1` et bascule
   `current`.
5. Une cle ancienne peut etre supprimee une fois que tous les secrets qui
   la referencent ont expire (au plus `MaxTTL = 7j`).

Effort : ~150 lignes Go. Bonus : ouvre la voie a une migration progressive
HMAC -> Argon2id en mappant `KeyVersion -> algo`.

### Autres pistes

- **Pieces jointes chiffrees** (changement de paradigme : 2 canaux distincts).
- **Webhook de notification de lecture** pour le createur.
- **Revocation manuelle** d'un secret par son createur (token de revoke).
- **Backend pluggable** (Postgres / Redis) pour scale-out multi-instance.
- **Metriques Prometheus** (`secrets_created_total`, `unlock_failed_total`).
- **Cles HSM-backed** pour `server.key` (PKCS#11, KMS).

## Limitations connues

- BoltDB est single-writer : convient pour un serveur unique, pas pour du
  multi-instance. Migrer vers PostgreSQL pour du HA.
- Pas d'auth emetteur : toute personne pouvant atteindre l'instance peut creer
  un secret. Mettre derriere un reverse-proxy authentifie si necessaire.
- Le rate-limit en memoire disparait au redemarrage.
