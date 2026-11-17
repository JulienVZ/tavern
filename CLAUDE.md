# CLAUDE.md — Tavern

> Nom de code provisoire : **Tavern** (à renommer avant la première release publique ; ne jamais utiliser « Discord », « cord » ou « Nitro » dans les noms, logos ou identifiants — marques déposées).

Ce fichier décrit le projet, les décisions déjà prises et les règles de travail. Lis-le entièrement avant toute tâche. En cas de conflit entre une demande ponctuelle et ce fichier, signale le conflit au lieu de trancher seul.

---

## 1. Vision

Application de messagerie / réseau social **auto-hébergeable**, équivalente fonctionnellement à Discord, pour un groupe d'amis (~35–40 utilisateurs par instance). Toutes les fonctionnalités « premium » de Discord sont **natives et gratuites**, limitées uniquement par la configuration de l'instance.

Trois piliers non négociables :

1. **Chiffrement de bout en bout partout** : messages privés, groupes, channels de serveurs, fichiers, appels audio/vidéo, partages d'écran. Le serveur ne voit jamais de contenu en clair.
2. **Client léger** : faible consommation RAM/CPU, sur Windows, macOS et Linux.
3. **Auto-hébergement simple** : projet open source sur GitHub ; n'importe qui doit pouvoir déployer sa propre instance pour ses amis avec un `docker compose up -d` et un fichier `.env`.

Hors périmètre v1 : fédération entre instances, applications mobiles (mais l'architecture doit les permettre : Tauri 2 supporte iOS/Android), bots/API publique, client web navigateur.

---

## 2. Fonctionnalités cibles

### Social
- Comptes utilisateurs, profils (pseudo, avatar animé, bannière, bio, statut personnalisé).
- Système d'amis : demandes, acceptation, blocage.
- Présence (en ligne / absent / ne pas déranger / invisible) et indicateur « en train d'écrire ».

### Messagerie
- Messages privés 1:1 et groupes privés (jusqu'à ~25 personnes).
- **Serveurs** avec **channels textuels** et **channels vocaux**, catégories, rôles et permissions.
- Messages : édition, suppression, réponses, réactions, mentions, emojis personnalisés (y compris animés), Markdown, aperçu de liens **généré côté client** (jamais côté serveur, sinon fuite d'URL).
- Pièces jointes chiffrées (images, vidéos, fichiers), limite de taille configurable par l'instance (défaut : 500 Mo).
- Recherche **locale** dans l'historique (le serveur ne peut pas indexer du contenu chiffré).

### Voix / vidéo
- Appels 1:1 et de groupe, channels vocaux persistants.
- Audio Opus haute qualité (jusqu'à 128 kb/s), suppression de bruit, push-to-talk, détection de voix.
- Webcam.
- **Partage d'écran 1080p 60 fps** par défaut (1440p/4K en option selon la config de l'instance), avec audio de l'application/système quand l'OS le permet.

### Administration d'instance
- Inscription **fermée par défaut** : création de compte via codes d'invitation générés par un admin.
- Panneau admin : utilisateurs, invitations, quotas de stockage, limites (taille d'upload, qualité max de stream).
- Aucune télémétrie, aucun appel vers un service tiers (pas d'analytics, pas de CDN externe, pas de polices Google).

---

## 3. Stack technique (décisions prises)

| Composant | Choix | Raison |
|---|---|---|
| Langage principal | **Rust** (édition 2024, stable) | Performance, faible RAM, sûreté mémoire (important pour réseau + crypto) |
| Client desktop | **Tauri 2** | Webview système au lieu de Chromium embarqué → bien moins de RAM qu'Electron |
| UI | **Svelte 5 + TypeScript + Vite** | Runtime minimal, pas de virtual DOM |
| Média (audio/vidéo/écran) | **LiveKit Rust SDK** dans le cœur Rust | **Jamais via le WebRTC du webview** : WebKitGTK (Linux) n'a pas de WebRTC fiable |
| Serveur média (SFU) | **LiveKit server** (auto-hébergé) | SFU éprouvé, pas de transcodage, E2EE supporté, TURN intégré |
| API + gateway temps réel | **Rust : axum + tokio**, WebSocket | |
| Sérialisation du protocole | **Protobuf (prost)**, versionné, compilé avec **protox** (pas de `protoc` requis) | Binaire (payloads chiffrés), évolution compatible |
| Base de données | **PostgreSQL** + **sqlx** (migrations versionnées) | Pas de Redis : inutile à cette échelle, simplifie l'auto-hébergement |
| Stockage fichiers | Backend abstrait : **système de fichiers local** (défaut) ou **S3-compatible** | Blobs déjà chiffrés côté client |
| E2EE messages | **MLS (RFC 9420) via OpenMLS 0.9** (fournisseur `openmls_rust_crypto`) | Conçu pour les groupes ; un seul protocole pour DM, groupes, channels. 0.9 plutôt que 0.8 : deux avis de décodage corrigés en 0.9 seulement (ADR 0019) |
| E2EE média | **LiveKit E2EE** avec **key provider personnalisé** alimenté par l'exporter MLS | |
| Authentification | **OPAQUE** (crate `opaque-ke`, KSF Argon2id) + TOTP ; WebAuthn/passkeys plus tard | Le serveur ne voit jamais le mot de passe |
| Stockage local client | **SQLCipher 4** via `rusqlite` (`bundled-sqlcipher`) : CommonCrypto sous macOS, **OpenSSL compilé depuis les sources et lié statiquement** sous Windows et Linux, clé brute de 256 bits (ADR 0017, 0018) | Seule exception à « pas d'OpenSSL », limitée à SQLCipher dans le client et vérifiée en CI. Toute faille d'OpenSSL impose une nouvelle version du client. Repli documenté : SQLite3 Multiple Ciphers, même format |
| Reverse proxy / TLS | **Caddy** (TLS automatique) dans le docker compose | |

Avant d'ajouter une dépendance, vérifie qu'elle est maintenue, que sa licence est compatible (voir §10) et qu'elle passe `cargo deny`. Toute dépendance crypto ou réseau nouvelle doit faire l'objet d'un ADR.

**Toute nouvelle dépendance passe `cargo deny` avant d'être ajoutée** (essai sur une branche ou une copie du manifeste) ; tout avis de sécurité ou toute licence hors liste est signalé au mainteneur avant de continuer.

**Aucune exception dans `deny.toml` (avis ignoré, licence ou source ajoutée, interdiction levée) sans l'accord préalable du mainteneur.** Si `cargo deny` échoue, arrête-toi, présente l'analyse et attends la décision.

Les versions des crates évoluent : vérifie toujours la version actuelle et la doc à jour (docs.rs, changelogs) au lieu de te fier à ta mémoire, en particulier pour Tauri, OpenMLS, LiveKit et axum.

---

## 4. Architecture du dépôt (monorepo)

```
/
├── CLAUDE.md
├── README.md                  # Présentation, captures, quick start auto-hébergement
├── LICENSE                    # AGPL-3.0-or-later
├── SECURITY.md                # Politique de divulgation des vulnérabilités
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── Cargo.toml                 # Workspace Rust
├── rust-toolchain.toml
├── deny.toml                  # cargo-deny (licences, advisories, sources)
├── clippy.toml / rustfmt.toml # Lints et formatage
├── crates/
│   ├── protocol/              # Types partagés client/serveur, .proto, versionnage
│   ├── argon2-memory/         # Zone mémoire dédiée à Argon2id (mmap), effacée puis rendue au système ; seul `unsafe` du projet (ADR 0015)
│   ├── crypto/                # Wrapper OpenMLS, gestion des clés, dérivation clés média, chiffrement fichiers
│   ├── server/                # Binaire serveur : API REST, gateway WS, auth, permissions, stockage
│   ├── client-core/           # Logique client sans UI : réseau, MLS, store local, LiveKit, état
│   ├── media/                 # Capture écran/caméra/audio par OS, encodage matériel
│   └── e2e-tests/             # Tests de bout en bout : vrai client contre vrai serveur (PostgreSQL requis)
├── third_party/
│   └── sqlx-sqlite-unused/    # Remplaçant vide de sqlx-sqlite, jamais compilé (libère `links = "sqlite3"` pour SQLCipher, ADR 0018)
├── apps/
│   └── desktop/
│       ├── src-tauri/         # Glue Tauri : commandes, événements, fenêtres (mince, délègue à client-core)
│       └── ui/                # Svelte 5 + TS
├── deploy/
│   ├── docker-compose.yml     # server + postgres + livekit + caddy
│   ├── docker-compose.dev.yml # Surcharge de dév : serveur et Postgres publiés sur 127.0.0.1
│   ├── Dockerfile             # Image du serveur (multi-stage, distroless, non-root)
│   ├── .env.example           # Toutes les variables documentées
│   ├── livekit.yaml.example
│   ├── Caddyfile.example
│   └── scripts/               # init.sh, backup.sh, restore.sh, create-admin.sh
├── docs/
│   ├── architecture.md
│   ├── threat-model.md        # Ce que le serveur voit / ne voit pas, adversaires considérés
│   ├── protocol.md            # Messages gateway, flux MLS, flux d'appel
│   ├── database-schema.md     # Schéma PostgreSQL, classification de chaque colonne
│   ├── self-hosting.md        # Guide pas à pas (VPS et serveur maison), ports, DNS, sauvegardes
│   ├── configuration.md       # Référence de toutes les variables
│   └── adr/                   # Architecture Decision Records : 0001-xxx.md
└── .github/
    ├── workflows/             # CI + releases
    ├── ISSUE_TEMPLATE/
    └── dependabot.yml
```

Règles de dépendance entre crates :
- `protocol` ne dépend de rien d'interne.
- `argon2-memory` ne dépend de rien d'interne et ne contient que la zone mémoire d'Argon2id.
- `crypto` dépend de `protocol` et de `argon2-memory` uniquement.
- `server` dépend de `protocol` (et de `crypto` uniquement pour la vérification de signatures/KeyPackages, le suivi de l'état public des groupes et la signature des propositions Remove, **jamais** pour déchiffrer).
- `client-core` dépend de `protocol`, `crypto`, `media`.
- `apps/desktop/src-tauri` dépend de `client-core` et ne contient pas de logique métier.

L'UI ne touche jamais aux clés ni au contenu chiffré : elle reçoit des données déjà déchiffrées via les commandes/événements Tauri.

---

## 5. Modèle de sécurité

### Ce que le serveur peut voir (métadonnées, assumé et documenté dans `docs/threat-model.md`)
Identifiants des comptes et appareils, liste d'amis, appartenance aux serveurs/channels/groupes, horodatage et taille des messages, présence, indicateur de frappe, qui est dans quel appel. La signalisation LiveKit n'est pas chiffrée de bout en bout (seulement TLS).

Visibles aussi en v1 (décision du 2026-11-13) : les **handles**, les **noms de serveurs, de channels, de catégories et de rôles** (nécessaires aux permissions et aux invitations) et les **profils** (nom affiché, avatar, bannière, bio, statut personnalisé). Le chiffrement des profils par « profile key » est une évolution future (ADR 0008).

### Ce que le serveur ne doit JAMAIS voir
Contenu des messages, pièces jointes, noms de fichiers, emojis personnalisés, réactions, contenu des médias (audio/vidéo/écran), mots de passe, clés privées, aperçus de liens.

> Règle : si une fonctionnalité nécessite que le serveur lise du contenu, elle doit être reconçue côté client ou refusée. Ne jamais l'implémenter « temporairement » en clair.

### MLS
- Ciphersuite par défaut : `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.
- **Chaque appareil = une feuille MLS** (multi-appareil natif).
- Un groupe MLS par conversation : un par DM, un par groupe privé, **un par channel textuel** de serveur.
- Le serveur joue le rôle de **Delivery Service** et d'**Authentication Service** : stocke les KeyPackages, ordonne les commits par groupe (un seul commit accepté par epoch), relaie les messages chiffrés.
- Ajout/retrait de membres piloté par les rôles du serveur : quand un membre perd l'accès (kick, ban, retrait de rôle), un commit le retire du groupe → nouvelle epoch → il ne peut plus déchiffrer la suite.
- Retrait : le serveur coupe immédiatement la livraison au membre exclu, puis, en tant qu'**external sender** MLS déclaré dans le contexte de chaque groupe, émet la proposition `Remove` ; le premier client membre en ligne la committe automatiquement. Les clients refusent toute proposition externe autre que `Remove`.
- La clé de signature de l'external sender est une **clé dédiée**, distincte de tout autre secret d'instance, incluse dans les sauvegardes. Perte et rotation : voir ADR 0002.
- Messages de handshake (proposals, commits) en `PublicMessage` pour que le serveur puisse les valider et les ordonner ; messages applicatifs en `PrivateMessage`.
- Identité : un **secret racine de compte** (32 octets aléatoires) est la seule valeur chiffrée côté serveur, sous la clé d'export OPAQUE et sous la clé de récupération (format v2, ADR 0017). Tous les secrets à long terme du compte en dérivent par HKDF avec une étiquette propre : la graine de la clé d'identité de compte (AIK), qui signe le certificat de chaque appareil ; la part compte de la clé du store local de chaque appareil ; plus tard les clés des ADR 0008 et 0009. Ni le secret racine ni l'AIK ne sont stockés sur un appareil.
- Rotation régulière des clés (commit de mise à jour périodique).
- Un appareil déconnecté reste membre de ses conversations ; les messages l'attendent sur le serveur (`TAVERN_MESSAGE_RETENTION_DAYS`, 30 jours au plus). Un appareil resté sans connexion au-delà de `TAVERN_DEVICE_INACTIVE_DAYS` (par défaut la durée de rétention, **30 jours**, jamais plus) est retiré des groupes par une proposition `Remove` du serveur ; à son retour il rejoint par external commit, avec un trou dans l'historique que l'UI explique (décision du 2026-11-16, ADR 0019).
- Plan crypto MLS de M2 : ADR 0019 (accepté le 2026-11-16) — KeyPackages réclamables seulement entre amis (ou pour ses propres appareils) avec limite de fréquence, un seul DM par paire d'utilisateurs, DM en lecture seule après retrait d'ami ou blocage, envoi idempotent sur (appareil, `client_message_id`, conservé deux fois la rétention ; aucun renvoi d'un message plus ancien que la rétention), et après restauration d'une sauvegarde : toutes les sessions révoquées (reconnexion par mot de passe et TOTP), notice demandant de révoquer à nouveau les appareils révoqués depuis, conversations recréées. Décisions du 2026-11-17 : un participant peut n'avoir aucun appareil dans le groupe (il le rejoint ensuite par external commit) ; tout commit de membre porte les `Remove` du serveur en attente, et le serveur refuse (`REMOVAL_PENDING`) celui qui les omet ; après un external commit, le serveur réémet ses `Remove` encore applicables dans la nouvelle epoch, dans la même transaction.
- Vérification d'identité entre utilisateurs : numéros de sécurité / QR code (comparaison des clés d'identité).

### Médias
- Clé E2EE d'un appel dérivée via `MLS-Exporter` du groupe MLS associé (channel vocal ↔ groupe MLS dédié, appel DM ↔ groupe du DM), une clé par (epoch, participant), poussée via `KeyProvider::set_key` du SDK LiveKit à chaque epoch.
- Rotation de la clé média à chaque changement d'epoch (arrivée/départ d'un participant).
- Le serveur délivre les tokens LiveKit **après** vérification des permissions.

### Fichiers
- Chiffrement côté client (AES-256-GCM ou XChaCha20-Poly1305, clé aléatoire par fichier), upload du blob chiffré, la clé et les métadonnées (nom, type, dimensions) voyagent dans le message MLS.
- Les miniatures sont générées côté client et chiffrées de la même manière.

### Comptes et sessions
- Enregistrement et connexion via **OPAQUE**. Pas d'envoi du mot de passe au serveur, sous aucune forme.
- Sessions : token opaque aléatoire, stocké **haché** côté serveur, lié à un appareil, révocable depuis les paramètres.
- TOTP optionnel dès la v1, passkeys plus tard.
- Clé de récupération générée à la création du compte (affichée une seule fois) pour restaurer l'identité sur un nouvel appareil.
- Robustesse du mot de passe imposée **côté client** à l'inscription et au changement (12 caractères minimum, estimation type zxcvbn ≥ 3/4) : il protège aussi la clé d'identité du compte.
- Chaque enrôlement d'appareil est notifié à tous les appareils existants du compte (avec action de révocation) et affiché à ses contacts dans les conversations partagées.
- **Notices de sécurité** (ADR 0016) : TOTP désactivé par un admin, mot de passe changé, compte récupéré par clé, appareil révoqué, clé de récupération régénérée. Enregistrées côté serveur (type énuméré et date, aucun texte libre), rejouées à chaque connexion et acquittées appareil par appareil : un appareil hors ligne ou déconnecté est prévenu lui aussi. Un appareil n'est pas prévenu de ce qui précède son enrôlement, sauf pour le TOTP désactivé par un admin et le compte récupéré par clé, signalés aussi aux appareils enrôlés ensuite tant qu'aucun appareil du compte ne les a acquittés (et, pour le TOTP, tant qu'il n'a pas été réactivé). Tout nouvel événement sensible d'un compte passe par ce mécanisme, jamais par un simple événement gateway.
- Un nouvel appareil n'a pas d'historique en v1 : l'UI l'explique à l'enrôlement et en tête de chaque conversation (ADR 0006, ADR 0009).
- Quand le serveur répond `REMOVAL_PENDING` ou `STALE_EPOCH`, le client committe/applique ce qui est en attente puis renvoie le message automatiquement, sans erreur visible.
- Rate limiting sur toutes les routes d'auth (30/min par adresse, 5/min par handle). Derrière Caddy, l'adresse est la **dernière** entrée de `X-Forwarded-For` ; le serveur ne publie aucun port (vérifié en CI).
- Le **handle** est l'identifiant OPAQUE : non modifiable en v1, forme canonique stricte (ASCII `a–z 0–9 _ .`, 2 à 32 caractères, minuscules), implémentée une seule fois dans `tavern_protocol::handle` pour le client et le serveur.
- Changements d'identifiants (ADR 0003) : chacun est autorisé par une signature de l'AIK sur un défi à usage unique. Récupération : nouveau mot de passe, toutes les sessions révoquées, TOTP conservé. Changement de mot de passe : les autres sessions sont révoquées. La clé de récupération peut être régénérée (l'ancienne cesse de fonctionner).
- Un admin peut désactiver le TOTP d'un utilisateur (téléphone et codes perdus) : appareils notifiés, action journalisée (`admin_audit_log`).
- Argon2id : 128 Mio, t=3, p=1 (mesures dans l'ADR 0003). Dépassement transitoire assumé du budget RAM pendant une connexion ; la mémoire de travail vient d'une zone dédiée, effacée puis rendue au système dès la fin du calcul (ADR 0015, test `argon2_memory_release` en CI).
- Identité d'appareil et déconnexion (ADR 0017) : une fiche de trousseau par instance, profil et compte, plus un index des comptes connus. La déconnexion garde l'appareil et sa clé, et retire le jeton de session et la clé du store local ; la reconnexion au même compte retrouve le même appareil et son historique. « Se déconnecter et effacer cet appareil » révoque l'appareil et supprime clés et données locales. Hors connexion, la clé du store n'existe que chiffrée, sous une clé qui exige à la fois la part dérivée du secret racine (donc le mot de passe) et la part du serveur (`devices.local_store_share`, effacée à la révocation). Sessions : expiration glissante de 90 jours.

### Règles de code liées à la sécurité
- **Ne jamais implémenter de primitive cryptographique soi-même.** Utiliser OpenMLS, RustCrypto, `rustls`, `opaque-ke`.
- Pas de `unsafe` sans commentaire `// SAFETY:` justifié et revue explicite ; `#![forbid(unsafe_code)]` dans `protocol`, `crypto`, `server`. Le seul `unsafe` du projet est dans `crates/argon2-memory` (ADR 0015), testé sous Miri en CI ; toute modification de cette crate demande une revue explicite.
- Zéroïser les secrets en mémoire (`zeroize`).
- Ne jamais logger : secrets, tokens, clés, payloads chiffrés, contenu en clair.
- Toute entrée réseau est non fiable : validation stricte, tailles maximales, timeouts.
- Fuzzing (`cargo-fuzz`) sur le décodage du protocole.

---

## 6. Performance (budgets)

| Mesure | Cible |
|---|---|
| RAM client au repos (fenêtre ouverte, connecté) | < 150 Mo |
| RAM client en appel vocal | < 200 Mo |
| RAM client en partage d'écran 1080p60 | < 300 Mo |
| Démarrage à froid du client | < 2 s |
| Latence d'envoi de message (LAN) | < 100 ms de bout en bout |
| Serveur complet (API + Postgres + LiveKit) pour 40 utilisateurs | tient sur 4 vCPU / 8 Go |

Leviers : virtualisation des listes de messages dans l'UI, chargement paginé de l'historique, pas de rendu vidéo dans le webview si un rendu natif (wgpu) est possible, encodage matériel, simulcast pour les spectateurs avec une connexion plus faible.

Si une modification risque de dépasser un budget, mesure avant/après et indique-le.

---

## 7. Partage d'écran et capture (crate `media`)

- Windows : Windows Graphics Capture (repli DXGI Desktop Duplication).
- macOS : ScreenCaptureKit (demande de permission « Enregistrement de l'écran »).
- Linux : PipeWire via `xdg-desktop-portal` (obligatoire sous Wayland), X11 en repli.
- Capture via `libwebrtc::desktop_capturer` (fourni par le SDK LiveKit) en premier choix ; la crate `scap` est écartée (non maintenue). Les API ci-dessus ne sont utilisées directement, en repli par OS, que si les mesures du M7 l'exigent (ADR 0004).
- Audio système/application pendant le partage d'écran : implémenté par OS dans cette crate, au M7.
- Encodage matériel en v1 : celui du SDK LiveKit (VideoToolbox sur macOS, NVENC et VAAPI sur Linux, NVENC sur Windows) ; repli logiciel OpenH264. Un encodeur Media Foundation (QuickSync/AMF) via `NativeVideoSource::new_encoded` est à décider au M7 après mesure.
- Codecs : H.264 par défaut (compatibilité, encodage matériel partout) ; AV1/VP9 si l'encodeur matériel est disponible des deux côtés.
- Défaut 1080p60 ≈ 8 Mb/s, réglable ; mode « texte/net » (priorité résolution) vs « jeu/fluide » (priorité fps).
- Vérifier ce que le SDK Rust de LiveKit / libwebrtc gère nativement (sources vidéo, encodeurs matériels) avant de réimplémenter.

---

## 8. Auto-hébergement

L'expérience d'un admin d'instance est une fonctionnalité à part entière.

- Déploiement de référence : `deploy/docker-compose.yml` avec `server`, `postgres`, `livekit`, `caddy`. Une seule commande, un seul `.env`.
- Toute la configuration passe par variables d'environnement (avec fichier de config optionnel). **Aucun domaine, IP ou secret codé en dur.**
- Les secrets sont générés par un script (`deploy/scripts/init.sh`, qui appelle `tavern-server gen-secrets`) si absents, chacun avec un usage unique : clés LiveKit, setup serveur OPAQUE, clé de signature MLS external sender (dédiée), clé de chiffrement des secrets TOTP, clé de confidentialité des handles (réponses factices).
- Migrations de base appliquées automatiquement au démarrage du serveur (avec option pour les désactiver).
- `deploy/scripts/create-admin.sh` pour créer le premier compte admin / le premier code d'invitation.
- Endpoint `/health` et `/version` (ce dernier indique le commit du build).
- Logs de requêtes au niveau info (sauf `/health`, au niveau debug) : méthode, gabarit de route, code, durée. Jamais d'adresse IP, de handle, de jeton, d'URL brute ni de corps.
- Scripts de sauvegarde/restauration (dump Postgres + dossier des blobs + secrets d'instance, dont le setup OPAQUE et la clé external sender).
- Ports LiveKit par défaut : signalisation derrière Caddy (443), un seul port UDP en mux pour le média, 7881/TCP en repli. **TURN désactivé par défaut en v1** ; TURN/TLS sur 5349 avec le volume de certificats de Caddy partagé est une option documentée dans `docs/self-hosting.md`. `network_mode: host` avec plage UDP documenté comme option avancée sous Linux.
- Le client demande l'URL de l'instance au premier lancement (comme Element ou Mattermost). Architecture prête pour plusieurs instances dans un même client (pas obligatoire en v1).
- Documentation `docs/self-hosting.md` : prérequis matériels, ports à ouvrir (HTTPS 443 ; port UDP mux et 7881/TCP de LiveKit ; TURN/TLS 5349 en option — vérifier la doc LiveKit à jour), DNS, configuration box internet (serveur maison) vs VPS, mise à jour, sauvegarde.
- Dimensionnement de référence (40 utilisateurs) : 4 vCPU, 8 Go RAM, SSD 100 Go + stockage fichiers, **upload ≥ 500 Mb/s (idéalement 1 Gb/s symétrique)**, IPv4 publique. La bande passante est le facteur limitant (un stream 1080p60 vu par 10 personnes ≈ 80 Mb/s sortants).
- Images Docker multi-arch (amd64 + arm64) publiées sur GHCR par la CI.

---

## 9. Conventions de code et de travail

### Langue
- **Code, identifiants, commentaires, messages de commit, README, docs : en anglais** (projet open source international).
- Échanges avec moi (le mainteneur) : en français.

### Rust
- `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings` doivent passer.
- Erreurs : `thiserror` dans les bibliothèques, `anyhow` uniquement dans les binaires. Pas de `unwrap()`/`expect()` dans le code serveur hors tests et invariants documentés.
- Logs : `tracing` (structuré), niveau configurable.
- Async : `tokio` partout.
- API REST documentée en OpenAPI (`utoipa`).

### Front
- TypeScript strict, pas de `any`.
- `pnpm` comme gestionnaire de paquets.
- Composants accessibles (navigation clavier, contrastes, lecteurs d'écran).
- Thème sombre et clair ; i18n prête dès le début (anglais + français).
- **Toute API du navigateur utilisée dans l'UI doit être vérifiée comme disponible dans les trois webviews** (WKWebView sur macOS, WebView2 sur Windows, WebKitGTK sur Linux) avant d'être employée. `window.alert`, `confirm` et `prompt` sont interdits (WKWebView et WebKitGTK ne les affichent pas : `confirm` renvoie `false` sans rien montrer) ; utiliser `lib/ConfirmDialog.svelte`. Un test fait échouer la CI s'ils réapparaissent.
- Aucune action ne doit échouer en silence : chaque bouton aboutit à une confirmation ou à une erreur lisible, y compris quand le rechargement qui suit échoue.

### Tests
- Unitaires dans chaque crate.
- Intégration serveur avec une vraie base PostgreSQL (testcontainers ou service Docker en CI).
- Test « deux clients » headless dans `client-core` : création de comptes, ajout d'ami, échange de messages chiffrés, vérification que le serveur ne stocke que du chiffré.
- Tests de propriété (`proptest`) sur la sérialisation et la crypto.
- Tests de composant de l'UI (`@testing-library/svelte` + `jsdom`) pour chaque écran qui déclenche une action : la commande Tauri attendue est appelée, le succès et l'échec sont affichés.
- Une fonctionnalité n'est pas terminée sans tests.

### Git
- Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`, `security:`).
- Petits commits cohérents ; une branche par jalon ou fonctionnalité.
- Ne jamais committer de secrets, de `.env` ou de données réelles.

### Commandes utiles
```bash
# Rust (la toolchain est épinglée par rust-toolchain.toml ; protoc n'est pas requis)
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo deny check

# UI (workspace pnpm dans apps/desktop, paquet tavern-ui)
cd apps/desktop && pnpm install
pnpm --filter tavern-ui check
pnpm --filter tavern-ui test
pnpm --filter tavern-ui build

# Client desktop
cd apps/desktop && pnpm tauri dev

# Instance complète (server + postgres + livekit + caddy)
cd deploy && ./scripts/init.sh        # crée .env, Caddyfile, livekit.yaml et les secrets (--dev pour un test local)
docker compose up -d
curl https://<TAVERN_DOMAIN>/health
./scripts/create-admin.sh             # code d'invitation du premier administrateur

# Pile de développement : serveur sur http://localhost:8080, Postgres sur localhost:5432
# (init.sh --dev écrit COMPOSE_FILE dans .env : toutes les commandes compose incluent alors la surcharge de dév)
cd deploy && ./scripts/init.sh --dev && ./scripts/build.sh && docker compose up -d
curl http://localhost:8080/version    # "commit" doit être le commit courant

# Tests d'intégration et de bout en bout : base dédiée tavern_test dans le PostgreSQL de la pile de dév
# (test-db.sh la crée et affiche son URL ; les tests refusent toute base dont le nom ne finit pas par _test,
# la base de l'instance et ses comptes de test manuel ne sont donc jamais touchés)
TAVERN_TEST_DATABASE_URL=$(./deploy/scripts/test-db.sh) \
  cargo test --package tavern-server --package tavern-e2e-tests -- --ignored
./deploy/scripts/test-db.sh --reset   # repartir d'une base de test vide

# Plusieurs clients sur la même machine (un profil de trousseau = un compte et un appareil)
cd apps/desktop && pnpm tauri dev     # premier client, à laisser tourner
pnpm client bob                       # chaque client supplémentaire, dans un autre terminal
pnpm client alice-2                   # (le titre de la fenêtre indique le profil ; à relancer après un changement Rust)

# Mesure Argon2id (durée et mémoire rendue)
cargo run --release --package tavern-crypto --example argon2_memory

# Sauvegarde / restauration
cd deploy && ./scripts/backup.sh && ./scripts/restore.sh backups/<archive>.tar.gz
```

### CI (GitHub Actions)
- Sur chaque push et chaque PR : fmt, clippy, tests, `cargo deny`, `pnpm check`, Miri, image Docker, build Tauri **sur Linux uniquement**.
- Build Tauri sur Windows, macOS et Linux : **une fois par jour** (seulement si `main` a changé depuis le dernier build des trois OS) et **à la demande** (`gh workflow run ci.yml --ref main`). Décision du 2026-11-15, pour économiser les minutes Actions tant que le dépôt est privé.
- Un changement qui ne touche que la documentation (`docs/**`, `*.md`, sauf `docs/database-schema.md` lu par un test) ne lance pas la CI.
- **Quand le dépôt deviendra public : revenir au build des trois OS sur chaque PR.**
- Sur tag `v*` : builds signés des installeurs (MSI/NSIS, DMG, AppImage + .deb), images Docker sur GHCR, release GitHub avec changelog.
- Mises à jour automatiques du client via le updater Tauri (signature obligatoire).

---

## 10. Licence

- Projet sous **AGPL-3.0-or-later** : les instances modifiées et exposées en réseau doivent publier leurs modifications.
- Dépendances autorisées : MIT, Apache-2.0, BSD, ISC, MPL-2.0, Zlib, Unicode, AGPL/GPL compatibles. À configurer dans `deny.toml`.
- **BlueOak-1.0.0** : acceptée pour les dépendances de développement et de test **uniquement** (décision du 2026-11-15 ; aujourd'hui `lru-cache`, tirée par `jsdom`). Jamais pour une dépendance embarquée dans le client ou le serveur.
- **`blessing` et `WTFPL`** : acceptées pour la seule crate `sqlcipher-src` (SQLite et libtomcrypt, décision du 2026-11-16, ADR 0018).
- Ajouter un en-tête SPDX (`// SPDX-License-Identifier: AGPL-3.0-or-later`) dans chaque fichier source.

---

## 11. Jalons

| Jalon | Contenu | Critère de fin |
|---|---|---|
| **M0** | Scaffolding : workspace, crates vides, app Tauri qui démarre, docker compose qui démarre, CI verte, docs squelettes, ADR initiaux | `docker compose up` + `pnpm tauri dev` fonctionnent, CI verte sur les 3 OS |
| **M1** | Comptes : OPAQUE, sessions, appareils, invitations, admin initial, TOTP | Un utilisateur s'inscrit avec un code d'invitation et se connecte depuis 2 appareils |
| **M2** | Amis + DM 1:1 chiffrés MLS, store local chiffré, multi-appareil, identité d'appareil et déconnexion (ADR 0017). Sans présence ni indicateur de frappe | Deux utilisateurs échangent des messages ; la base serveur ne contient que du chiffré (test automatisé) |
| **M3** | Présence et indicateur « en train d'écrire » (reportés de M2 le 2026-11-15, à faire en premier), puis groupes privés | Ajout/retrait de membres avec rotation de clés vérifiée |
| **M4** | Serveurs, channels textuels, catégories, rôles, permissions, modération | Kick/ban retire l'accès cryptographique |
| **M5** | Pièces jointes chiffrées, avatars, bannières, emojis personnalisés, réactions, recherche locale | |
| **M5b** | Historique sur un nouvel appareil de l'utilisateur (ADR 0009) : transfert d'appareil à appareil | Un second appareil récupère l'historique du premier sans que le serveur détienne de clé |
| **M6** | Vocal : LiveKit, E2EE via exporter MLS, channels vocaux, appels DM | Appel à 5 personnes, E2EE actif, rotation à l'arrivée/départ |
| **M7** | Webcam + partage d'écran 1080p60 sur les 3 OS | 1080p60 stable à 8 Mb/s, avec encodage matériel quand il est disponible |
| **M8** | Finitions : notifications desktop, paramètres, thèmes, i18n, updater, packaging. À étudier : test de fumée qui pilote le vrai webview (`tauri-driver` sur Linux et Windows), les tests de composant ne voyant pas les différences entre webviews | Installeurs signés publiés par la CI |
| **M9** | Durcissement : revue du threat model, fuzzing, audit des dépendances, guide d'auto-hébergement complet | |

---

## 12. Décisions ouvertes (à trancher avec le mainteneur, ne pas décider seul)

1. **Historique pour les nouveaux membres d'un channel** : tranché pour la v1 — pas d'historique antérieur, ni pour un nouveau membre ni pour un nouvel appareil (ADR 0006). Option future : partage d'historique chiffré par un membre existant (ADR à écrire).
2. **Nom définitif du projet** : reste Tavern pour l'instant.
3. **Signature de code** des installeurs (certificat Windows, compte Apple Developer pour la notarisation macOS) : reportée au M8.
4. **Rendu vidéo** : dans le webview (simple) ou natif via wgpu (plus performant) — à décider au jalon M7 après mesure.
5. **Encodeur Media Foundation** (QuickSync/AMF sous Windows) : à décider au M7 après mesure.
6. **Mécanisme d'entrée dans les channels d'un serveur** : orientation retenue — external commit autorisé par les rôles (le nouveau membre n'attend pas), arrivée toujours affichée dans le channel, plus une option « channel privé » où l'entrée exige l'ajout par un membre. Décision finale au M4.
7. **Historique sur un nouvel appareil** : ADR 0009 (proposé), transfert d'appareil à appareil au M5b ; sauvegarde chiffrée sous la clé de récupération à évaluer ensuite.
8. **Identifiant de l'application** : `io.github.julienvz.tavern`, définitif depuis le 2026-11-14 (il nomme les entrées de trousseau et, à partir de M2, le dossier de données local). Ne plus le modifier.
9. **SQLCipher et OpenSSL** : tranché le 2026-11-16 — SQLCipher via rusqlite, OpenSSL compilé dans le client sous Windows et Linux, CommonCrypto sous macOS ; `deny.toml` n'autorise `openssl-sys` que sous `libsqlite3-sys` ; contrôles en CI (ADR 0018).
10. **Mémoire Argon2id sur macOS** : tranché le 2026-11-15 — crate dédiée `tavern-argon2-memory` (zone `mmap` effacée puis démappée), `unsafe` toujours interdit dans `protocol`, `crypto` et `server` (ADR 0015).

---

## 13. Comment travailler sur ce projet

1. **Planifie avant de coder** pour toute tâche non triviale : propose un plan, attends validation si cela touche la crypto, le protocole, le schéma de base ou l'architecture.
2. **Un jalon à la fois.** Ne commence pas le suivant sans validation.
3. **Écris un ADR** (`docs/adr/NNNN-titre.md` : contexte, décision, alternatives, conséquences) pour toute décision structurante.
4. **Mets à jour la doc dans le même commit** que le code (README, `docs/`, `.env.example`, ce fichier si une décision change).
5. **Vérifie avant de déclarer terminé** : fmt, clippy, tests, build. Dis clairement ce qui n'a pas pu être testé (ex. capture d'écran sur un OS non disponible). Avant de remettre un serveur ou un client à tester à la main, relance-le depuis le build courant et vérifie que les routes ajoutées répondent : un processus démarré avant les derniers changements fait échouer le test pour une mauvaise raison. Pour la pile Docker : `./scripts/build.sh` puis `docker compose up -d`, et `GET /version` doit renvoyer dans `commit` le commit courant (sans suffixe `-dirty`) ; donne ce commit au mainteneur. Avant de déclarer un groupe de tâches ou un jalon terminé, lance le build des trois OS à la demande (`gh workflow run ci.yml --ref main`) et attends qu'il soit vert.
8. **Version REST** : toute route ajoutée ou retirée incrémente `tavern_protocol::REST_MINOR_VERSION` (un test fige la liste des routes) ; c'est ce qui permet au client d'annoncer qu'une instance est plus ancienne que lui.
9. **Espace disque** : la machine du mainteneur est presque pleine. Préviens dès que `target/` dépasse **10 Go** (seuil relevé pour M2, 8 Go auparavant), dès que l'espace libre passe sous **8 Go**, et avant toute opération qui consomme beaucoup d'espace.
6. **Signale les risques** : si une demande affaiblit la sécurité ou le budget RAM, dis-le avant de l'implémenter.
7. Pas de code mort, pas de TODO non suivi : tout TODO référence une issue ou un jalon.
