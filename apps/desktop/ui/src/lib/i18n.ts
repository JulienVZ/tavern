// SPDX-License-Identifier: AGPL-3.0-or-later

// Minimal message catalogue. English is the reference; every other locale
// must define exactly the same keys (checked by the type and by a test).

const en = {
  "app.name": "Tavern",
  "instance.title": "Connect to an instance",
  "instance.intro":
    "Tavern is self-hosted. Enter the address of the instance run by you or by someone you trust.",
  "instance.url.label": "Instance address",
  "instance.url.placeholder": "chat.example.org",
  "instance.url.hint": "The connection always uses HTTPS.",
  "instance.submit": "Check instance",
  "instance.checking": "Checking…",
  "instance.result.title": "Instance status",
  "instance.result.url": "Address",
  "instance.result.server": "Server",
  "instance.result.database": "Database",
  "status.ok": "OK",
  "status.unavailable": "Unavailable",
  "error.invalid_url": "This is not a valid address.",
  "error.insecure_url": "The instance must be reached over HTTPS.",
  "error.unreachable": "The instance cannot be reached. Check the address and your connection.",
  "error.not_an_instance": "A server answered, but it is not a Tavern instance.",
  "error.unknown": "Something went wrong.",
} as const;

export type MessageKey = keyof typeof en;
type Catalogue = Record<MessageKey, string>;

const fr: Catalogue = {
  "app.name": "Tavern",
  "instance.title": "Se connecter à une instance",
  "instance.intro":
    "Tavern est auto-hébergé. Saisissez l'adresse de l'instance gérée par vous ou par une personne de confiance.",
  "instance.url.label": "Adresse de l'instance",
  "instance.url.placeholder": "chat.exemple.org",
  "instance.url.hint": "La connexion utilise toujours HTTPS.",
  "instance.submit": "Vérifier l'instance",
  "instance.checking": "Vérification…",
  "instance.result.title": "État de l'instance",
  "instance.result.url": "Adresse",
  "instance.result.server": "Serveur",
  "instance.result.database": "Base de données",
  "status.ok": "OK",
  "status.unavailable": "Indisponible",
  "error.invalid_url": "Cette adresse n'est pas valide.",
  "error.insecure_url": "L'instance doit être jointe en HTTPS.",
  "error.unreachable": "L'instance est injoignable. Vérifiez l'adresse et votre connexion.",
  "error.not_an_instance": "Un serveur a répondu, mais ce n'est pas une instance Tavern.",
  "error.unknown": "Une erreur est survenue.",
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

/** Returns the message for `key` in the current locale. */
export function t(key: MessageKey): string {
  return catalogues[locale][key];
}
