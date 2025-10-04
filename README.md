# AppMaker WebView Studio

AppMaker WebView Studio is a lightweight Python + HTML tool that generates fully configured
Android WebView wrapper projects. Each generated project contains a self-updating policy
manifest so you can stay compliant when Google updates their SDK or Play policy
requirements.

## Features

- Intuitive web UI powered by Flask for configuring your Android WebView app.
- In-memory ZIP generation of a Gradle project with Kotlin activity boilerplate.
- Optional signed release builder that bundles a keystore, certificate summary, and ready-to-upload APK/AAB outputs when Android tooling is available.
- Bundled update script and `/api/sdk-rules` endpoint to keep Google policy data current.
- Automatic refresh mechanism that caches the latest rules locally with graceful fallbacks.

## Getting started

1. Create a virtual environment and install dependencies:

   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. Launch the development server:

   ```bash
   flask --app app run --reload
   ```

3. Open `http://127.0.0.1:5000` and fill out the form to generate a project.
4. Use the **Build signed release package** button after expanding the advanced signing panel to request a keystore, certificate summary, and release artifacts.
5. Use the **Refresh rules from Google** button to pull down the most recent SDK guidance.
6. Each generated ZIP includes `tools/update_rules.py` so the Android project can update itself
   before release.

## Generating signed releases

AppMaker can attempt to build a signed release bundle directly from the web UI. When you provide
keystore credentials in the advanced section and click **Build signed release package**, the server:

1. Generates a secure PKCS#12 keystore and `keystore.properties` wired into the Gradle project.
2. Produces a certificate summary (`RELEASE_CERTIFICATE.txt`) so you can archive signing
   fingerprints.
3. Runs `assembleRelease` and `bundleRelease` (if Gradle and the Android SDK are installed on the
   host) and packages any resulting APK/AAB files inside the download alongside the build log.

If the host environment lacks the Android toolchain, the download still includes the full project,
keystore, and a `tools/build_release.sh` helper script. Install Android Studio or the command line
SDK tools, set `ANDROID_HOME`/`ANDROID_SDK_ROOT`, then execute:

```bash
cd project
./tools/build_release.sh
```

The script prefers the Gradle wrapper when available and falls back to a system-wide `gradle`
binary.

### Environment variables

- `SDK_RULE_SOURCE` – Override the remote JSON manifest endpoint.
- `APPMAKER_SECRET` – Secret key for Flask session/flash support.
- `PORT` and `FLASK_DEBUG` – Override server defaults when running `python app.py` directly.

## API

`GET /api/sdk-rules` returns the cached manifest, making it easy to integrate automated
compliance checks into your pipeline.

```json
{
  "rules": {
    "version": "2024.04",
    "updated": "2024-04-10T12:00:00Z",
    "requirements": [
      "Target API level 34 or above for new submissions.",
      "Declare data safety information for WebView usage in Play Console.",
      "Audit embedded web content for third-party cookies and trackers."
    ],
    "notes": [
      "This offline cache is bundled so AppMaker can start even without network access.",
      "Use the Refresh rules button to download the latest Android policy manifest."
    ]
  },
  "source": "https://raw.githubusercontent.com/GoogleChromeLabs/llms/main/android_webview_rules.json"
}
```

> **Tip:** Deploy AppMaker behind a scheduler (such as cron or GitHub Actions) that hits
> `/refresh-rules` so the manifest automatically updates whenever Google publishes new rules.

## License

This project is provided under the MIT license.
