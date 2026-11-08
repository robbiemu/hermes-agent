# Apple Keychain secret source for Hermes

This plugin lets Hermes get configured secrets from macOS Keychain. The active profile's `config.yaml` holds settings and references, not secret values. Hermes still applies its usual secret-source ordering and precedence.

I shared an early version in [this gist](https://gist.github.com/robbiemu/0cc8d63115c15dd3363f0adc3770a666). This is the updated one.

## Get started

You’ll need macOS, Hermes 0.23.0 or later, and Apple’s command-line developer tools (including `clang`).

Copy the whole `apple-keychain` source folder, including its Python files, C sources, headers and manifest, into the active profile’s plugin directory:

- Default profile: `~/.hermes/plugins/apple-keychain/`
- Named `work` profile: `~/.hermes/profiles/work/plugins/apple-keychain/`

For `work`, use `hermes -p work` in the commands below. If `HERMES_HOME` sets the active profile home, use `$HERMES_HOME/plugins/apple-keychain/`. Leave out generated `__pycache__` directories and compiled helpers. Then enable the plugin and start setup:

```sh
hermes plugins enable apple-keychain
hermes keychain setup
hermes keychain doctor
```

Setup defaults to your Mac's login keychain and gets its path from macOS. For a service, choose the headless option or run `hermes keychain setup --headless` and enter the path to an **existing** keychain. Setup shows the profile config and target, explains access for new items or replacements, and asks for confirmation before writing.

Choose an environment-variable name, such as `OPENAI_API_KEY`. Setup looks for a usable value with that name in the active profile's `.env` and checks the Keychain target.

If the default Keychain account already exists and a usable `.env` value is available, setup asks:

```text
'OPENAI_API_KEY' already exists in Keychain.
1. Keep the value already in Keychain
2. Replace it with the value being imported
3. Save the imported value under a different name
Enter 1, 2 or 3:
```

Choose 1 to check the existing value and save its reference without rewriting the item or removing anything from `.env`. Setup warns if `override_existing: false` or `secrets.preserve_existing` lets that `.env` value take priority. Choose 2 to replace it: setup saves a backup, updates the item and verifies it before removing the backup. The existing item's access controls stay in place. Choose 3 to pick a different Keychain account name while keeping the `OPENAI_API_KEY` mapping in Hermes. If that account also exists, setup shows its name and asks again. Without a usable `.env` value, choices 2 and 3 refer to a new value instead. Setup asks for confirmation before writing; the default is no.

If you're saving a value and setup found one in `.env`, it asks:

```text
Found OPENAI_API_KEY in your .env. Use it? [Y/n]:
```

Press Enter to use it. If you decline, or no usable value is present, setup asks you to enter the secret with input hidden. An `op://` secret reference is not imported as a value; enter the secret instead.

After an `.env` value is saved to Keychain and read back successfully, setup offers:

```text
Saved and checked. Remove OPENAI_API_KEY from .env? [y/N]:
```

The default is no. If you choose yes, removal happens only if the profile, target and source file are still unchanged and managed settings permit it. A failed import or check leaves `.env` alone. The check confirms local Keychain storage; it does not authenticate with the provider.

For a named profile, select it through Hermes:

```sh
hermes -p work keychain setup
hermes -p work keychain doctor
```

Setup adds or changes only the chosen reference and preserves existing source ordering and `override_existing` settings. A personal setup stores an explicit login-keychain path so reads and writes target the same file. Existing references keep their configured service and account unless you choose a different account during setup.

## Gateway / headless setup

For a gateway that runs without a logged-in user, the System keychain can be useful. Install the plugin files in the gateway’s profile first. Then, in a direct interactive terminal as the gateway’s macOS user, enable it and run setup with the same profile, so it uses the gateway’s config and `.env`:

```sh
hermes -p work plugins enable apple-keychain
hermes -p work keychain setup --headless
```

Replace `work` with the gateway’s profile name, or use `-p default` for its default profile. When asked for an existing keychain file, enter `/Library/Keychains/System.keychain`. Choose the variable name; setup can use its `.env` value or hidden input when saving. If the item already exists, the same keep, replace or different-name choices above apply.

Writing to the System keychain requires appropriate macOS authorization or administrator rights. If access is denied, an administrator needs to arrange provisioning and item access for the gateway’s identity. Avoid running the whole `hermes` command under `sudo`: it may select root’s profile or helper cache. The plugin does not elevate privileges, create or unlock keychains, or automatically widen access.

The System keychain path alone does not grant access; unlock state and the gateway’s execution context also matter. Run this check as the actual gateway account and in its execution context, not just from an administrator’s desktop terminal:

```sh
hermes -p work keychain doctor
```

Use the gateway’s profile here too, then restart the gateway after configuration changes.

Login and System keychain items are separate, even if their names match. If you keep both copies, update each through its configured profile and target, then run `doctor` in each actual context. Rotating one copy does not update the other.

## Add or change one secret

The setup wizard is the easy starting point. These commands are optional when you want to add or change a single secret manually:

```sh
hermes keychain set OPENAI_API_KEY
hermes keychain set OPENAI_API_KEY --replace-existing
hermes keychain set OPENAI_API_KEY --replace-existing --keep-backup
```

`set` reads a secret through a hidden prompt. Setup and hidden-input commands require a direct interactive terminal and reject known unattended Hermes sessions before accessing Keychain. Each prompt times out after 120 seconds. `--stdin` accepts up to 1 MiB of UTF-8 secret data from standard input for automation, waits at most 120 seconds, and removes one final line ending. Never put the secret itself in a command argument.

New names use the configured default keychain and service; existing references retain their configured service, account and keychain. To change an existing item with `set`, pass `--replace-existing`. This permits overwriting the Keychain destination, but does not select or import a value from `.env`. Rotation preserves the item's access controls, saves the old value and access controls first, updates and verifies the new value, then removes the backup unless `--keep-backup` is given. `--allow-any-app` is a deliberate opt-in for **new** items and does not alter an existing item's access controls.

### Manual add / smoke test

Once this name has a configured reference, or setup has selected a default keychain for new names, add a secret and check it:

```sh
hermes keychain set OPENROUTER_API_KEY
hermes keychain doctor
```

`set` prompts for the value with input hidden. `doctor` checks all configured references and reports their status without printing secret values. These commands use the configured Keychain target, so you don’t need to enter its service or account labels. If the item already exists, add `--replace-existing` to the `set` command to change it.

For automation, pipe the value from your own trusted secret reader:

```sh
trusted-secret-reader | hermes keychain set OPENROUTER_API_KEY --stdin
```

Here `trusted-secret-reader` is a placeholder for your own secret source.

### Recovery

If a rotation is interrupted or verification fails, inspect saved old values before another write:

```sh
hermes keychain recovery list
hermes keychain recovery restore OPENAI_API_KEY RECOVERY_ID
hermes keychain recovery discard OPENAI_API_KEY RECOVERY_ID
```

Use the ID displayed by `list`. Restoring writes the saved value back into the existing item and retains the saved copy until you discard it. Restore refuses if the original item is missing or its access controls changed; discarding deletes the saved copy without changing the current item. A pending recovery must be resolved before another write to the same item. A deliberately retained backup also appears in the list and can be restored or discarded. No command prints the secret value.

## Access and compatibility

New items trust the plugin helper and `/usr/bin/security`. Other programs can invoke `/usr/bin/security`, so this does not restrict access to Hermes alone. For a new item, setup also asks whether to allow any application to access it; the default is no. Existing items keep their access controls. The keychain selection alone does not determine who can read an item: the execution context, keychain state, permissions and item access controls all matter. Run `doctor` as the actual service identity to test access. Setup does not create keychains, change unlock settings, configure services or elevate privileges; arrange permissions and unlock behavior separately.

The plugin builds a local helper using the Apple Security framework. The helper is cached in a private per-user macOS cache shared by that user's profiles. After an upgrade changes the helper, Keychain may deny access until you authorize the new helper in Keychain Access. The helper does not show interactive Keychain dialogs, and old helper executables are not used automatically.

In normal in-process plugin mode, the commands above are available as `hermes keychain`. With `isolation: host`, Hermes still loads the secret source but skips the local CLI command. The compatibility `provision-secrets.sh` wrapper can provision already-configured references in that mode; use in-process mode for setup, doctor and recovery.

## References and existing configurations

`config.yaml` contains references only. For a new mapping with default settings:

| Field | Default | Example |
| --- | --- | --- |
| Environment variable | The name you choose | `OPENROUTER_API_KEY` |
| Keychain service | `hermes` | `hermes` |
| Keychain account | The environment-variable name | `OPENROUTER_API_KEY` |
| Keychain | Explicit path selected in setup | Your chosen login keychain |

Service and account are Keychain labels, not a hostname or provider selection. You can use custom labels to point at an existing item without copying its value. `accounts` uses the environment-variable name as the account; `items` allows per-reference `service`, `account` and `keychain` overrides. Hermes reads Keychain target fields literally; environment-variable templates are not expanded there.

For example, once a default keychain has been configured, merge these entries into the existing `secrets.apple_keychain.items` list in the active profile’s `config.yaml`, replacing any existing `items` entry for the same name. Remove those names from `accounts` if they’re listed there:

```yaml
secrets:
  apple_keychain:
    items:
      - env: OPENROUTER_API_KEY
        account: openrouter-main
      - env: DISCORD_BOT_TOKEN
        keychain: /Library/Keychains/System.keychain
```

See [config.yaml](config.yaml) and [config-advanced.yaml](config-advanced.yaml) for more examples. The source-level `keychain` alias remains supported for existing configurations; `default_keychain` takes precedence when present.

Existing configurations with no keychain path continue to read through the macOS Keychain search list. Management commands refuse to write such ambiguous targets. Run setup for each reference to choose its explicit target; setup previews each change and leaves other legacy mappings alone. A previous non-default `binary_path` selected the old `security` reader and is no longer used; remove that setting after reviewing the switch to native Keychain access.

Hermes normally lets this source override an existing environment or `.env` value (`override_existing: true`); `false` preserves that existing value. Keychain mappings take precedence over bulk secret sources even when a bulk source appears first in `secrets.sources`. Other configured secret sources and `secrets.preserve_existing` also affect which value Hermes applies. The startup fetch is read-only and noninteractive, and this plugin adds no model-callable secret-reader tool. Hermes still holds resolved values in its process environment, so an authorized process can access its own credentials.

## Using keys with models and subagents

Set up a name such as `LOCAL_INFERENCE_API_KEY` in Keychain. For an existing custom-endpoint delegation setup, the key can stay a reference in the active profile’s `config.yaml`:

```yaml
delegation:
  api_key: ${LOCAL_INFERENCE_API_KEY}
```

This is only the credential part: keep your existing `delegation.base_url` and `delegation.model` settings. A consumer’s config can expand a reference like this when it supports environment variables; Keychain’s service, account and keychain fields are literal. The value could be a local OpenAI-compatible endpoint key; the same idea can supply provider keys or bot tokens to integrations that support them. The plugin supplies values, not providers or models, so follow the consumer’s own configuration docs.

## Restart and check

Run `hermes keychain doctor` for the right profile, then fully restart the CLI or gateway after changes. Opening a new chat does not restart the process. Hermes 0.23.0 and later reload secret sources after plugin discovery, so you don’t need to copy the plugin into the Hermes source tree, patch core files or run a post-install helper.

If `doctor` reports the item available but a request gets a 401, check the same profile and execution context, the consumer’s key name and endpoint, and the precedence settings above, then try a normal request again. `doctor` checks Keychain access, not authentication with the provider.

## Compatibility provisioner

`provision-secrets.sh` delegates to the same configuration, target resolution and Keychain writer. It supports `--only ENV`, `--stdin ENV`, `--replace-existing`, `--keep-backup` and `--allow-any-app`. Without `--stdin`, it uses values explicitly inherited from the calling shell, not a standalone `.env` import. It validates every selected reference and value before the first write and captures that inherited environment before Hermes can hydrate credentials. Prefer hidden input or a trusted pipe when practical. Set `HERMES_PY` to the Python interpreter used by Hermes if the wrapper cannot find it.

For example, supply one value on standard input without putting it in an argument:

```sh
trusted-secret-reader | ./provision-secrets.sh --stdin OPENAI_API_KEY
```

`KEYCHAIN`, if inherited for legacy compatibility, must match **every** selected configured target; it never changes the runtime target. `HERMES_CONFIG`, if set, must match the active profile's config. A mismatch is rejected with guidance. The wrapper honors a named `HERMES_HOME` or the sticky active profile; use the normal `hermes -p work keychain ...` commands for one-off profile selection.

`doctor` checks the same runtime resolution path and reports names and status, not values. A missing, locked, denied, timed-out or empty item and an unfinished update produce a nonzero exit status. Deliberately retained backups are reported for information. Authorize the helper deliberately when access is denied; do not widen access merely to make a check pass.

## Catalog policy

This plugin intentionally implements the OS-keystore backend described in the [SecretSource guide](https://hermes-agent.nousresearch.com/docs/developer-guide/secret-source-plugin). At runtime, `fetch()` reads the configured Keychain items and returns values to Hermes; it does not write to Keychain or import or remove `.env` entries. Operator-invoked setup can import a value from the active profile’s `.env` and remove that entry only after a verified import and your confirmation. Keychain writes and recovery deletes occur through operator-invoked provisioning and management commands. [Catalog rule 11](https://hermes-agent.nousresearch.com/docs/developer-guide/plugins/catalog-submission) restricts direct credential-store reads, so how it applies to a secret-source backend is a question for catalog review.

The plugin validator warns about private Hermes core imports, which may change between releases:

- `hermes_platform.host.facts` gates runtime access and native helper builds to macOS, following Hermes' machine-facts guidance.
- `hermes_cli.env_loader.get_secret_source` prevents accidental reprovisioning of values already hydrated by Hermes.
- `hermes_cli.managed_scope` prevents configuration rewrites from discarding administrator-managed leaves.
- `hermes_cli.profiles` resolves the sticky active profile for the legacy provisioner wrapper only.
- `hermes_cli.config._env_write_lock`, `_env_line_defines_key`, `_write_env_lines` and `_publish_env_value` support the checked, optional removal of an imported `.env` entry.
