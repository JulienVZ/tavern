// SPDX-License-Identifier: AGPL-3.0-or-later

// Minimal message catalogue. English is the reference; every other locale
// must define exactly the same keys (checked by the type and by a test).
// `{name}` placeholders are replaced by `t(key, { name: value })`.

const en = {
  "app.name": "Tavern",
  "common.cancel": "Cancel",
  "common.continue": "Continue",
  "common.close": "Close",
  "common.loading": "Loading…",
  "common.copy": "Copy",
  "common.copied": "Copied",
  "common.yes": "Yes",
  "common.no": "No",

  "instance.title": "Connect to an instance",
  "instance.intro":
    "Tavern is self-hosted. Enter the address of the instance run by you or by someone you trust.",
  "instance.url.label": "Instance address",
  "instance.url.placeholder": "chat.example.org",
  "instance.url.hint":
    "HTTPS is required. Plain HTTP is accepted only for a server running on this computer (localhost).",
  "instance.submit": "Connect",
  "instance.checking": "Checking…",
  "instance.unhealthy": "The instance answered, but reports a problem. Try again later.",
  "instance.change": "Use another instance",

  "auth.tab.login": "Sign in",
  "auth.tab.register": "Create an account",
  "auth.on": "On {instance}",
  "auth.handle": "Handle",
  "auth.password": "Password",
  "auth.login.submit": "Sign in",
  "auth.login.working": "Signing in…",
  "auth.login.slow": "Checking the password takes a moment: it never leaves this computer.",

  "register.invite": "Invitation code",
  "register.invite.hint": "Ask the administrator of this instance for a code.",
  "register.handle.hint":
    "2 to 32 characters: a–z, 0–9, _ and . Your handle is public and cannot be changed later.",
  "register.display_name": "Display name",
  "register.password.hint":
    "At least 12 characters. Your password never leaves this computer, and it also protects your identity key: choose a strong one.",
  "register.password.confirm": "Confirm the password",
  "register.password.mismatch": "The two passwords are different.",
  "register.strength": "Password strength",
  "register.strength.0": "Very weak",
  "register.strength.1": "Weak",
  "register.strength.2": "Fair",
  "register.strength.3": "Good",
  "register.strength.4": "Strong",
  "register.submit": "Create my account",
  "register.working": "Creating the account…",

  "recovery.title": "Save your recovery key",
  "recovery.intro":
    "This key is the only way to keep your identity if you forget your password. It is shown once and stored nowhere: not on this computer, not on the instance.",
  "recovery.where": "Write it down on paper or save it in a password manager.",
  "recovery.label": "Recovery key",
  "recovery.confirm": "I have saved my recovery key in a safe place.",
  "recovery.admin": "This account administers the instance.",

  "totp.title": "Two-factor authentication",
  "totp.intro": "Enter the 6-digit code from your authenticator app, or one of your recovery codes.",
  "totp.code": "Code",
  "totp.submit": "Verify",

  "home.signed_in_as": "Signed in as {name} (@{handle})",
  "home.admin_badge": "Administrator",
  "home.empty":
    "Your account is ready. Friends, messages and calls arrive with the next versions.",
  "home.logout": "Sign out",
  "home.connection.offline": "Connection lost. Reconnecting…",

  "history.title": "This device starts without message history",
  "history.body":
    "Messages are end-to-end encrypted: the instance cannot read them, so it cannot hand them to a new device. This device will only see what is sent from now on. Earlier messages stay on your other devices.",
  "history.dismiss": "I understand",

  "newdevice.title": "A new device signed in to your account",
  "newdevice.body.one":
    "A device was added to your account. If it was not you, revoke it and change your password.",
  "newdevice.body.many":
    "{count} devices were added to your account. If it was not you, revoke them and change your password.",
  "newdevice.ack": "It was me",
  "newdevice.review": "Review my devices",

  "notice.totp_disabled_by_admin":
    "An administrator disabled two-factor authentication on your account. Enable it again if you did not ask for this.",

  "devices.title": "Devices",
  "devices.intro": "Every computer signed in to your account. Revoke the ones you do not recognise.",
  "devices.this": "This device",
  "devices.added": "Added {date}",
  "devices.last_seen": "last active {date}",
  "devices.revoke": "Revoke",
  "devices.revoke.confirm": "Revoke this device? It will be signed out at once.",
  "devices.new": "New",
  "platform.windows": "Windows",
  "platform.macos": "macOS",
  "platform.linux": "Linux",

  "security.title": "Two-factor authentication",
  "security.totp.off": "Not enabled. A code from an authenticator app adds a second step at sign-in.",
  "security.totp.on": "Enabled.",
  "security.totp.enable": "Enable",
  "security.totp.disable": "Disable",
  "security.totp.setup":
    "Add this secret to your authenticator app (manual entry), then enter the code it shows.",
  "security.totp.secret": "Secret",
  "security.totp.url": "Setup link",
  "security.totp.confirm": "Confirm",
  "security.totp.disable.prompt": "Enter a current code or a recovery code to disable.",
  "security.totp.codes.title": "Recovery codes",
  "security.totp.codes.body":
    "Each code replaces an authenticator code once. They are shown only now: save them.",
  "security.totp.codes.done": "I have saved them",

  "admin.title": "Administration",
  "admin.invites.title": "Invitations",
  "admin.invites.create": "Create an invitation",
  "admin.invites.created": "Give this code to the person you invite. It is shown only once.",
  "admin.invites.empty": "No invitation yet.",
  "admin.invites.uses": "{uses} of {max} used",
  "admin.invites.expires": "expires {date}",
  "admin.invites.revoked": "revoked",
  "admin.invites.grants_admin": "administrator",
  "admin.invites.revoke": "Revoke",
  "admin.users.title": "Accounts",
  "admin.users.devices": "{count} device(s)",
  "admin.users.disabled": "disabled",
  "admin.users.totp": "2FA",
  "admin.users.disable": "Disable",
  "admin.users.enable": "Enable",
  "admin.users.disable_totp": "Disable 2FA",
  "admin.users.disable_totp.confirm":
    "Disable two-factor authentication for @{handle}? Do this only for someone who lost their authenticator and recovery codes. Their devices will be notified and the action is logged.",

  "ended.revoked": "This device was signed out.",
  "ended.credentials_changed": "Your password was changed on another device. Sign in again.",
  "ended.account_disabled": "Your account was disabled by an administrator.",
  "ended.invalid": "Your session expired. Sign in again.",
  "ended.replaced": "This account is now connected from another window of this device.",

  "error.invalid_url": "This is not a valid address.",
  "error.insecure_url":
    "The instance must be reached over HTTPS. Plain HTTP only works for localhost.",
  "error.unreachable": "The instance cannot be reached. Check the address and your connection.",
  "error.not_an_instance": "A server answered, but it is not a Tavern instance.",
  "error.invalid_credentials": "Wrong handle or password.",
  "error.invalid_invite": "This invitation code is not valid, or it has expired or been used.",
  "error.handle_taken": "This handle is already taken.",
  "error.invalid_handle": "This handle is not valid.",
  "error.invalid_handle.too_short": "The handle is too short (2 characters minimum).",
  "error.invalid_handle.too_long": "The handle is too long (32 characters maximum).",
  "error.invalid_handle.invalid_character":
    "The handle can only contain a–z, 0–9, _ and . (no spaces, no accents).",
  "error.invalid_handle.misplaced_dot":
    "The handle cannot start or end with a dot, or contain two dots in a row.",
  "error.weak_password": "This password is too weak.",
  "error.weak_password.too_short": "The password is too short (12 characters minimum).",
  "error.weak_password.too_long": "The password is too long.",
  "error.weak_password.too_guessable":
    "This password is too easy to guess. Use a longer passphrase of unrelated words.",
  "error.totp_invalid": "This code is not valid.",
  "error.exchange_expired": "This took too long. Start again.",
  "error.account_disabled": "This account is disabled. Contact the administrator.",
  "error.rate_limited": "Too many attempts. Wait a moment and try again.",
  "error.too_many_devices":
    "This account already has 10 devices. Revoke one from another device first.",
  "error.device_revoked":
    "This device was revoked from another device. Sign in again to add it as a new device.",
  "error.session_ended": "Your session ended. Sign in again.",
  "error.forbidden": "You are not allowed to do this.",
  "error.invalid_argument": "The instance refused this request.",
  "error.already_exists": "This already exists.",
  "error.not_found": "Not found.",
  "error.unavailable": "The instance is busy. Try again in a moment.",
  "error.keychain_unavailable":
    "The system keychain is not available, so this device cannot stay signed in.",
  "error.untrusted_key_material":
    "The instance returned keys that do not match this account. Do not continue; contact the administrator.",
  "error.internal": "Something went wrong.",
} as const;

export type MessageKey = keyof typeof en;
type Catalogue = Record<MessageKey, string>;

const fr: Catalogue = {
  "app.name": "Tavern",
  "common.cancel": "Annuler",
  "common.continue": "Continuer",
  "common.close": "Fermer",
  "common.loading": "Chargement…",
  "common.copy": "Copier",
  "common.copied": "Copié",
  "common.yes": "Oui",
  "common.no": "Non",

  "instance.title": "Se connecter à une instance",
  "instance.intro":
    "Tavern est auto-hébergé. Saisissez l'adresse de l'instance gérée par vous ou par une personne de confiance.",
  "instance.url.label": "Adresse de l'instance",
  "instance.url.placeholder": "chat.exemple.org",
  "instance.url.hint":
    "HTTPS est obligatoire. Le HTTP en clair n'est accepté que pour un serveur tournant sur cet ordinateur (localhost).",
  "instance.submit": "Se connecter",
  "instance.checking": "Vérification…",
  "instance.unhealthy": "L'instance a répondu, mais signale un problème. Réessayez plus tard.",
  "instance.change": "Utiliser une autre instance",

  "auth.tab.login": "Connexion",
  "auth.tab.register": "Créer un compte",
  "auth.on": "Sur {instance}",
  "auth.handle": "Identifiant",
  "auth.password": "Mot de passe",
  "auth.login.submit": "Se connecter",
  "auth.login.working": "Connexion…",
  "auth.login.slow":
    "La vérification du mot de passe prend un instant : il ne quitte jamais cet ordinateur.",

  "register.invite": "Code d'invitation",
  "register.invite.hint": "Demandez un code à l'administrateur de cette instance.",
  "register.handle.hint":
    "2 à 32 caractères : a–z, 0–9, _ et . Votre identifiant est public et ne pourra plus être modifié.",
  "register.display_name": "Nom affiché",
  "register.password.hint":
    "Au moins 12 caractères. Votre mot de passe ne quitte jamais cet ordinateur, et il protège aussi votre clé d'identité : choisissez-le robuste.",
  "register.password.confirm": "Confirmez le mot de passe",
  "register.password.mismatch": "Les deux mots de passe sont différents.",
  "register.strength": "Robustesse du mot de passe",
  "register.strength.0": "Très faible",
  "register.strength.1": "Faible",
  "register.strength.2": "Moyen",
  "register.strength.3": "Bon",
  "register.strength.4": "Robuste",
  "register.submit": "Créer mon compte",
  "register.working": "Création du compte…",

  "recovery.title": "Conservez votre clé de récupération",
  "recovery.intro":
    "Cette clé est le seul moyen de garder votre identité si vous oubliez votre mot de passe. Elle est affichée une seule fois et n'est stockée nulle part : ni sur cet ordinateur, ni sur l'instance.",
  "recovery.where": "Notez-la sur papier ou enregistrez-la dans un gestionnaire de mots de passe.",
  "recovery.label": "Clé de récupération",
  "recovery.confirm": "J'ai conservé ma clé de récupération en lieu sûr.",
  "recovery.admin": "Ce compte administre l'instance.",

  "totp.title": "Authentification à deux facteurs",
  "totp.intro":
    "Saisissez le code à 6 chiffres de votre application d'authentification, ou l'un de vos codes de secours.",
  "totp.code": "Code",
  "totp.submit": "Vérifier",

  "home.signed_in_as": "Connecté en tant que {name} (@{handle})",
  "home.admin_badge": "Administrateur",
  "home.empty":
    "Votre compte est prêt. Les amis, les messages et les appels arrivent avec les prochaines versions.",
  "home.logout": "Se déconnecter",
  "home.connection.offline": "Connexion perdue. Reconnexion…",

  "history.title": "Cet appareil démarre sans historique de messages",
  "history.body":
    "Les messages sont chiffrés de bout en bout : l'instance ne peut pas les lire, elle ne peut donc pas les transmettre à un nouvel appareil. Cet appareil ne verra que ce qui est envoyé à partir de maintenant. Les messages précédents restent sur vos autres appareils.",
  "history.dismiss": "J'ai compris",

  "newdevice.title": "Un nouvel appareil s'est connecté à votre compte",
  "newdevice.body.one":
    "Un appareil a été ajouté à votre compte. Si ce n'était pas vous, révoquez-le et changez votre mot de passe.",
  "newdevice.body.many":
    "{count} appareils ont été ajoutés à votre compte. Si ce n'était pas vous, révoquez-les et changez votre mot de passe.",
  "newdevice.ack": "C'était moi",
  "newdevice.review": "Voir mes appareils",

  "notice.totp_disabled_by_admin":
    "Un administrateur a désactivé l'authentification à deux facteurs sur votre compte. Réactivez-la si vous ne l'avez pas demandé.",

  "devices.title": "Appareils",
  "devices.intro":
    "Tous les ordinateurs connectés à votre compte. Révoquez ceux que vous ne reconnaissez pas.",
  "devices.this": "Cet appareil",
  "devices.added": "Ajouté le {date}",
  "devices.last_seen": "dernière activité le {date}",
  "devices.revoke": "Révoquer",
  "devices.revoke.confirm": "Révoquer cet appareil ? Il sera déconnecté immédiatement.",
  "devices.new": "Nouveau",
  "platform.windows": "Windows",
  "platform.macos": "macOS",
  "platform.linux": "Linux",

  "security.title": "Authentification à deux facteurs",
  "security.totp.off":
    "Désactivée. Un code d'application d'authentification ajoute une seconde étape à la connexion.",
  "security.totp.on": "Activée.",
  "security.totp.enable": "Activer",
  "security.totp.disable": "Désactiver",
  "security.totp.setup":
    "Ajoutez ce secret à votre application d'authentification (saisie manuelle), puis saisissez le code qu'elle affiche.",
  "security.totp.secret": "Secret",
  "security.totp.url": "Lien de configuration",
  "security.totp.confirm": "Confirmer",
  "security.totp.disable.prompt":
    "Saisissez un code actuel ou un code de secours pour désactiver.",
  "security.totp.codes.title": "Codes de secours",
  "security.totp.codes.body":
    "Chaque code remplace une fois un code d'authentification. Ils ne sont affichés que maintenant : conservez-les.",
  "security.totp.codes.done": "Je les ai conservés",

  "admin.title": "Administration",
  "admin.invites.title": "Invitations",
  "admin.invites.create": "Créer une invitation",
  "admin.invites.created":
    "Donnez ce code à la personne que vous invitez. Il n'est affiché qu'une seule fois.",
  "admin.invites.empty": "Aucune invitation pour l'instant.",
  "admin.invites.uses": "{uses} sur {max} utilisée(s)",
  "admin.invites.expires": "expire le {date}",
  "admin.invites.revoked": "révoquée",
  "admin.invites.grants_admin": "administrateur",
  "admin.invites.revoke": "Révoquer",
  "admin.users.title": "Comptes",
  "admin.users.devices": "{count} appareil(s)",
  "admin.users.disabled": "désactivé",
  "admin.users.totp": "2FA",
  "admin.users.disable": "Désactiver",
  "admin.users.enable": "Réactiver",
  "admin.users.disable_totp": "Désactiver la 2FA",
  "admin.users.disable_totp.confirm":
    "Désactiver l'authentification à deux facteurs de @{handle} ? À réserver à une personne qui a perdu son application et ses codes de secours. Ses appareils seront prévenus et l'action est journalisée.",

  "ended.revoked": "Cet appareil a été déconnecté.",
  "ended.credentials_changed":
    "Votre mot de passe a été modifié sur un autre appareil. Reconnectez-vous.",
  "ended.account_disabled": "Votre compte a été désactivé par un administrateur.",
  "ended.invalid": "Votre session a expiré. Reconnectez-vous.",
  "ended.replaced": "Ce compte est maintenant connecté depuis une autre fenêtre de cet appareil.",

  "error.invalid_url": "Cette adresse n'est pas valide.",
  "error.insecure_url":
    "L'instance doit être jointe en HTTPS. Le HTTP en clair ne fonctionne que pour localhost.",
  "error.unreachable": "L'instance est injoignable. Vérifiez l'adresse et votre connexion.",
  "error.not_an_instance": "Un serveur a répondu, mais ce n'est pas une instance Tavern.",
  "error.invalid_credentials": "Identifiant ou mot de passe incorrect.",
  "error.invalid_invite": "Ce code d'invitation n'est pas valide, a expiré ou a déjà été utilisé.",
  "error.handle_taken": "Cet identifiant est déjà pris.",
  "error.invalid_handle": "Cet identifiant n'est pas valide.",
  "error.invalid_handle.too_short": "L'identifiant est trop court (2 caractères minimum).",
  "error.invalid_handle.too_long": "L'identifiant est trop long (32 caractères maximum).",
  "error.invalid_handle.invalid_character":
    "L'identifiant ne peut contenir que a–z, 0–9, _ et . (ni espace, ni accent).",
  "error.invalid_handle.misplaced_dot":
    "L'identifiant ne peut ni commencer ni finir par un point, ni contenir deux points à la suite.",
  "error.weak_password": "Ce mot de passe est trop faible.",
  "error.weak_password.too_short": "Le mot de passe est trop court (12 caractères minimum).",
  "error.weak_password.too_long": "Le mot de passe est trop long.",
  "error.weak_password.too_guessable":
    "Ce mot de passe est trop facile à deviner. Utilisez une phrase plus longue, faite de mots sans rapport.",
  "error.totp_invalid": "Ce code n'est pas valide.",
  "error.exchange_expired": "L'opération a pris trop de temps. Recommencez.",
  "error.account_disabled": "Ce compte est désactivé. Contactez l'administrateur.",
  "error.rate_limited": "Trop de tentatives. Patientez un instant puis réessayez.",
  "error.too_many_devices":
    "Ce compte a déjà 10 appareils. Révoquez-en un depuis un autre appareil.",
  "error.device_revoked":
    "Cet appareil a été révoqué depuis un autre appareil. Reconnectez-vous pour l'ajouter comme nouvel appareil.",
  "error.session_ended": "Votre session est terminée. Reconnectez-vous.",
  "error.forbidden": "Vous n'êtes pas autorisé à faire cela.",
  "error.invalid_argument": "L'instance a refusé cette demande.",
  "error.already_exists": "Cela existe déjà.",
  "error.not_found": "Introuvable.",
  "error.unavailable": "L'instance est occupée. Réessayez dans un instant.",
  "error.keychain_unavailable":
    "Le trousseau du système est indisponible : cet appareil ne peut pas rester connecté.",
  "error.untrusted_key_material":
    "L'instance a renvoyé des clés qui ne correspondent pas à ce compte. Ne continuez pas ; contactez l'administrateur.",
  "error.internal": "Une erreur est survenue.",
};

export const catalogues = { en, fr } satisfies Record<string, Catalogue>;
export type Locale = keyof typeof catalogues;

export const DEFAULT_LOCALE: Locale = "en";

/** Picks the first supported locale among the user's preferred languages. */
export function pickLocale(preferred: readonly string[]): Locale {
  for (const tag of preferred) {
    const language = tag.toLowerCase().split("-")[0];
    if (language !== undefined && language in catalogues) {
      return language as Locale;
    }
  }
  return DEFAULT_LOCALE;
}

let locale: Locale =
  typeof navigator === "undefined" ? DEFAULT_LOCALE : pickLocale(navigator.languages);

export function currentLocale(): Locale {
  return locale;
}

export function setLocale(next: Locale): void {
  locale = next;
}

export function isMessageKey(key: string): key is MessageKey {
  return key in en;
}

/** Returns the message for `key` in the current locale, with placeholders filled. */
export function t(key: MessageKey, params?: Record<string, string | number>): string {
  let message: string = catalogues[locale][key];
  if (params !== undefined) {
    for (const [name, value] of Object.entries(params)) {
      message = message.replaceAll(`{${name}}`, String(value));
    }
  }
  return message;
}

/** Message for a command error: the most specific one that exists. */
export function errorMessage(error: { code: string; detail?: string }): string {
  if (error.detail !== undefined) {
    const detailed = `error.${error.code}.${error.detail}`;
    if (isMessageKey(detailed)) {
      return t(detailed);
    }
  }
  const general = `error.${error.code}`;
  return isMessageKey(general) ? t(general) : t("error.internal");
}

/** A date as the user's locale writes it. */
export function formatDate(ms: number): string {
  return new Intl.DateTimeFormat(locale, { dateStyle: "medium" }).format(new Date(ms));
}
