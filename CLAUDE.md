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
| Sérialisation du protocole | **Protobuf (prost)**, versionné | Binaire (payloads chiffrés), évolution compatible |
| Base de données | **PostgreSQL** + **sqlx** (migrations versionnées) | Pas de Redis : inutile à cette échelle, simplifie l'auto-hébergement |
| Stockage fichiers | Backend abstrait : **système de fichiers local** (défaut) ou **S3-compatible** | Blobs déjà chiffrés côté client |
| E2EE messages | **MLS (RFC 9420) via OpenMLS** | Conçu pour les groupes ; un seul protocole pour DM, groupes, channels |
| E2EE média | **LiveKit E2EE** avec **key provider personnalisé** alimenté par l'exporter MLS | |
| Authentification | **OPAQUE** (crate `opaque-ke`, KSF Argon2id) + TOTP ; WebAuthn/passkeys plus tard | Le serveur ne voit jamais le mot de passe |
| Stockage local client | **SQLite chiffré (SQLCipher)** via `rusqlite`, clé dans le trousseau OS (crate `keyring`) | |
| Reverse proxy / TLS | **Caddy** (TLS automatique) dans le docker compose | |

Avant d'ajouter une dépendance, vérifie qu'elle est maintenue, que sa licence est compatible (voir §10) et qu'elle passe `cargo deny`. Toute dépendance crypto ou réseau nouvelle doit faire l'objet d'un ADR.

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
├── crates/
│   ├── protocol/              # Types partagés client/serveur, .proto, versionnage
│   ├── crypto/                # Wrapper OpenMLS, gestion des clés, dérivation clés média, chiffrement fichiers
│   ├── server/                # Binaire serveur : API REST, gateway WS, auth, permissions, stockage
│   ├── client-core/           # Logique client sans UI : réseau, MLS, store local, LiveKit, état
│   └── media/                 # Capture écran/caméra/audio par OS, encodage matériel
├── apps/
│   └── desktop/
│       ├── src-tauri/         # Glue Tauri : commandes, événements, fenêtres (mince, délègue à client-core)
│       └── ui/                # Svelte 5 + TS
├── deploy/
│   ├── docker-compose.yml     # server + postgres + livekit + caddy
│   ├── .env.example           # Toutes les variables documentées
│   ├── livekit.yaml.example
│   ├── Caddyfile.example
│   └── scripts/               # backup.sh, restore.sh, create-admin.sh
├── docs/
│   ├── architecture.md
│   ├── threat-model.md        # Ce que le serveur voit / ne voit pas, adversaires considérés
│   ├── protocol.md            # Messages gateway, flux MLS, flux d'appel
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
- `crypto` dépend de `protocol` uniquement.
- `server` dépend de `protocol` (et de `crypto` uniquement pour la vérification de signatures/KeyPackages, **jamais** pour déchiffrer).
- `client-core` dépend de `protocol`, `crypto`, `media`.
- `apps/desktop/src-tauri` dépend de `client-core` et ne contient pas de logique métier.

L'UI ne touche jamais aux clés ni au contenu chiffré : elle reçoit des données déjà déchiffrées via les commandes/événements Tauri.

---

## 5. Modèle de sécurité

### Ce que le serveur peut voir (métadonnées, assumé et documenté dans `docs/threat-model.md`)
Identifiants des comptes et appareils, liste d'amis, appartenance aux serveurs/channels/groupes, horodatage et taille des messages, présence, indicateur de frappe, qui est dans quel appel. La signalisation LiveKit n'est pas chiffrée de bout en bout (seulement TLS).

### Ce que le serveur ne doit JAMAIS voir
Contenu des messages, pièces jointes, noms de fichiers, emojis personnalisés, réactions, contenu des médias (audio/vidéo/écran), mots de passe, clés privées, aperçus de liens.

> Règle : si une fonctionnalité nécessite que le serveur lise du contenu, elle doit être reconçue côté client ou refusée. Ne jamais l'implémenter « temporairement » en clair.

### MLS
- Ciphersuite par défaut : `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.
- **Chaque appareil = une feuille MLS** (multi-appareil natif).
- Un groupe MLS par conversation : un par DM, un par groupe privé, **un par channel textuel** de serveur.
- Le serveur joue le rôle de **Delivery Service** et d'**Authentication Service** : stocke les KeyPackages, ordonne les commits par groupe (un seul commit accepté par epoch), relaie les messages chiffrés.
- Ajout/retrait de membres piloté par les rôles du serveur : quand un membre perd l'accès (kick, ban, retrait de rôle), un commit le retire du groupe → nouvelle epoch → il ne peut plus déchiffrer la suite.
- Rotation régulière des clés (commit de mise à jour périodique).
- Vérification d'identité entre utilisateurs : numéros de sécurité / QR code (comparaison des clés d'identité).

### Médias
- Clé E2EE d'un appel dérivée via `MLS-Exporter` du groupe MLS associé (channel vocal ↔ groupe MLS dédié, appel DM ↔ groupe du DM).
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
- Rate limiting sur toutes les routes d'auth.

### Règles de code liées à la sécurité
- **Ne jamais implémenter de primitive cryptographique soi-même.** Utiliser OpenMLS, RustCrypto, `rustls`, `opaque-ke`.
- Pas de `unsafe` sans commentaire `// SAFETY:` justifié et revue explicite ; `#![forbid(unsafe_code)]` dans `protocol`, `crypto`, `server`.
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
- Évaluer la crate `scap` (ou équivalent) avant d'écrire la capture à la main ; consigner le choix dans un ADR.
- Encodage matériel prioritaire : NVENC, QuickSync, AMF, VideoToolbox, VAAPI ; repli logiciel.
- Codecs : H.264 par défaut (compatibilité, encodage matériel partout) ; AV1/VP9 si l'encodeur matériel est disponible des deux côtés.
- Défaut 1080p60 ≈ 8 Mb/s, réglable ; mode « texte/net » (priorité résolution) vs « jeu/fluide » (priorité fps).
- Vérifier ce que le SDK Rust de LiveKit / libwebrtc gère nativement (sources vidéo, encodeurs matériels) avant de réimplémenter.

---

## 8. Auto-hébergement

L'expérience d'un admin d'instance est une fonctionnalité à part entière.

- Déploiement de référence : `deploy/docker-compose.yml` avec `server`, `postgres`, `livekit`, `caddy`. Une seule commande, un seul `.env`.
- Toute la configuration passe par variables d'environnement (avec fichier de config optionnel). **Aucun domaine, IP ou secret codé en dur.**
- Les secrets (clés LiveKit, clé de signature serveur) sont générés par un script (`deploy/scripts/init.sh`) si absents.
- Migrations de base appliquées automatiquement au démarrage du serveur (avec option pour les désactiver).
- `deploy/scripts/create-admin.sh` pour créer le premier compte admin / le premier code d'invitation.
- Endpoint `/health` et `/version`.
- Scripts de sauvegarde/restauration (dump Postgres + dossier des blobs).
- Le client demande l'URL de l'instance au premier lancement (comme Element ou Mattermost). Architecture prête pour plusieurs instances dans un même client (pas obligatoire en v1).
- Documentation `docs/self-hosting.md` : prérequis matériels, ports à ouvrir (HTTPS 443 ; ports RTC TCP/UDP et TURN de LiveKit — vérifier la doc LiveKit à jour), DNS, configuration box internet (serveur maison) vs VPS, mise à jour, sauvegarde.
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

### Tests
- Unitaires dans chaque crate.
- Intégration serveur avec une vraie base PostgreSQL (testcontainers ou service Docker en CI).
- Test « deux clients » headless dans `client-core` : création de comptes, ajout d'ami, échange de messages chiffrés, vérification que le serveur ne stocke que du chiffré.
- Tests de propriété (`proptest`) sur la sérialisation et la crypto.
- Une fonctionnalité n'est pas terminée sans tests.

### Git
- Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`, `security:`).
- Petits commits cohérents ; une branche par jalon ou fonctionnalité.
- Ne jamais committer de secrets, de `.env` ou de données réelles.

### Commandes utiles
```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo deny check
cd apps/desktop/ui && pnpm install && pnpm check && pnpm test
cd apps/desktop && pnpm tauri dev
cd deploy && docker compose up -d
```
(À mettre à jour dès que le scaffolding existe.)

### CI (GitHub Actions)
- Sur chaque PR : fmt, clippy, tests, `cargo deny`, `pnpm check`, build Tauri sur Windows, macOS et Linux.
- Sur tag `v*` : builds signés des installeurs (MSI/NSIS, DMG, AppImage + .deb), images Docker sur GHCR, release GitHub avec changelog.
- Mises à jour automatiques du client via le updater Tauri (signature obligatoire).

---

## 10. Licence

- Projet sous **AGPL-3.0-or-later** : les instances modifiées et exposées en réseau doivent publier leurs modifications.
- Dépendances autorisées : MIT, Apache-2.0, BSD, ISC, MPL-2.0, Zlib, Unicode, AGPL/GPL compatibles. À configurer dans `deny.toml`.
- Ajouter un en-tête SPDX (`// SPDX-License-Identifier: AGPL-3.0-or-later`) dans chaque fichier source.

---

## 11. Jalons

| Jalon | Contenu | Critère de fin |
|---|---|---|
| **M0** | Scaffolding : workspace, crates vides, app Tauri qui démarre, docker compose qui démarre, CI verte, docs squelettes, ADR initiaux | `docker compose up` + `pnpm tauri dev` fonctionnent, CI verte sur les 3 OS |
| **M1** | Comptes : OPAQUE, sessions, appareils, invitations, admin initial, TOTP | Un utilisateur s'inscrit avec un code d'invitation et se connecte depuis 2 appareils |
| **M2** | Amis + DM 1:1 chiffrés MLS, store local chiffré, multi-appareil | Deux utilisateurs échangent des messages ; la base serveur ne contient que du chiffré (test automatisé) |
| **M3** | Groupes privés | Ajout/retrait de membres avec rotation de clés vérifiée |
| **M4** | Serveurs, channels textuels, catégories, rôles, permissions, modération | Kick/ban retire l'accès cryptographique |
| **M5** | Pièces jointes chiffrées, avatars, bannières, emojis personnalisés, réactions, recherche locale | |
| **M6** | Vocal : LiveKit, E2EE via exporter MLS, channels vocaux, appels DM | Appel à 5 personnes, E2EE actif, rotation à l'arrivée/départ |
| **M7** | Webcam + partage d'écran 1080p60 sur les 3 OS | 1080p60 stable à 8 Mb/s avec encodage matériel |
| **M8** | Finitions : notifications desktop, paramètres, thèmes, i18n, updater, packaging | Installeurs signés publiés par la CI |
| **M9** | Durcissement : revue du threat model, fuzzing, audit des dépendances, guide d'auto-hébergement complet | |

---

## 12. Décisions ouvertes (à trancher avec le mainteneur, ne pas décider seul)

1. **Historique pour les nouveaux membres d'un channel** : avec MLS, un nouveau membre ne peut pas lire les messages antérieurs à son arrivée. Défaut v1 : pas d'historique antérieur (documenté). Option future : partage d'historique chiffré par un membre existant (ADR à écrire).
2. **Nom définitif du projet**.
3. **Signature de code** des installeurs (certificat Windows, compte Apple Developer pour la notarisation macOS) : coût et procédure.
4. **Rendu vidéo** : dans le webview (simple) ou natif via wgpu (plus performant) — à décider au jalon M7 après mesure.

---

## 13. Comment travailler sur ce projet

1. **Planifie avant de coder** pour toute tâche non triviale : propose un plan, attends validation si cela touche la crypto, le protocole, le schéma de base ou l'architecture.
2. **Un jalon à la fois.** Ne commence pas le suivant sans validation.
3. **Écris un ADR** (`docs/adr/NNNN-titre.md` : contexte, décision, alternatives, conséquences) pour toute décision structurante.
4. **Mets à jour la doc dans le même commit** que le code (README, `docs/`, `.env.example`, ce fichier si une décision change).
5. **Vérifie avant de déclarer terminé** : fmt, clippy, tests, build. Dis clairement ce qui n'a pas pu être testé (ex. capture d'écran sur un OS non disponible).
6. **Signale les risques** : si une demande affaiblit la sécurité ou le budget RAM, dis-le avant de l'implémenter.
7. Pas de code mort, pas de TODO non suivi : tout TODO référence une issue ou un jalon.
