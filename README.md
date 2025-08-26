
# Nostr_Key_Generator

A lightweight Python script to create and manage **Nostr identities** — no libraries, no clipboard, no external dependencies.

<img width="459" height="245" alt="grafik" src="https://github.com/user-attachments/assets/b006e9d6-59e7-4074-a3ff-d589ec56a20c" />



## What this script does

- ✅ Create a new Nostr identity (`nsec`, `npub`, private/public keys)
- ✅ Show your keys in multiple formats
- ✅ Convert between formats (`npub`, `nsec`, hex)
- ✅ Export to JSON (with safe permissions on Linux/macOS)
- ❌ No clipboard
- ❌ No external libraries


## How to use

### Recommended: Interactive mode

```
python nostr_identity_generator.py
````

You'll get a clean menu with all options explained.



### Optional: Non-interactive mode

Generate new key instantly:

```
python nostr_identity_generator.py --new
```

Import existing identity from `nsec`:

```
python nostr_identity_generator.py --import nsec1yourkeyhere
```

Import from raw 64-character private key:

```
python nostr_identity_generator.py --import abc123...yourprivkey
```

Export result to JSON:

```
python nostr_identity_generator.py --new --out mykeys.json
```



## Example Output

```
Your Nostr Identity

npub (public):         npub1abcd...
pubkey (hex, x-only):  7f9d4c...
pubkey (compressed):   02c3f1...
nsec (PRIVATE):        [hidden]
privkey (hex):         [hidden]
```



## Format Converter

You can also convert keys between:

* `npub` → public key hex
* `nsec` → private key hex
* `privkey hex` → `nsec`, `npub`, pubkey (compressed)
* `pubkey hex (x-only)` → `npub`

Useful if you're working across different Nostr tools.



## Security Notes

* Never share your **nsec** or **private key**. Anyone who has it can impersonate you.
* JSON export is written with restricted file permissions (`chmod 600`) on supported systems.
* This script is for **identity generation and format conversion only** — not for message signing or relays.
* Bech32 encoding/decoding follows [NIP-19](https://github.com/nostr-protocol/nips/blob/master/19.md)


## License

MIT

