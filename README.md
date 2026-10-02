# Internet Defender and Virus Scanner

A Windows security app with Mission Control, internet connection checks, ad and tracker blocking, Sample Lab file checks, Local Detective, quarantine, and guided account recovery.

## Run

```powershell
python internet_defender.py
```

The project uses Python's standard library and Tkinter. It does not install VirusTotal. VirusTotal is an online safety database, and support for talking to it is already built into the app.

## Connect VirusTotal

A free personal VirusTotal API key enables online reputation checks. Without a key, the local features still work, but online results show `UNKNOWN`.

1. Open **REQUISITIONS** in the app.
2. Click **CREATE ACCOUNT / GET FREE VIRUSTOTAL KEY**.
3. Sign in or create a free VirusTotal Community account.
4. Copy the API key. Keep it private and do not put it in GitHub, messages, or screenshots.
5. Paste it into the app and click **Save Key Securely**.

The official account and key page is:

```text
https://www.virustotal.com/gui/my-apikey
```

For file checks, the app sends the file's SHA-256 fingerprint to VirusTotal, not the whole file. Connection checks send the public internet address being investigated. Windows encrypts the saved key for the current Windows account.

## Check a GitHub release before publishing

Scan the exact finished `.exe`, installer, or `.zip` that people will download. In this HQ workspace, ask Devin to run the project `virus-scan` skill on that final file before it is uploaded.

- Do not upload a file reported as `NOT SAFE`.
- Treat `UNKNOWN` as unconfirmed, not safe.
- Do not rebuild or change the file after scanning it. If it changes, scan the new version again.
- A clean scan lowers risk but cannot guarantee that a file is safe.

This release check protects the downloadable file. It is separate from the personal VirusTotal key that each app user may connect in Requisitions.
