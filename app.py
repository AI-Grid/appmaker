import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.error import URLError
from urllib.request import Request, urlopen

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    Response,
    request,
    send_file,
    url_for,
)

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

APP_ROOT = Path(__file__).parent
DATA_PATH = APP_ROOT / "data" / "sdk_rules.json"
DEFAULT_RULE_SOURCE = (
    "https://raw.githubusercontent.com/GoogleChromeLabs/llms/main/android_webview_rules.json"
)

app = Flask(__name__)
app.secret_key = os.environ.get("APPMAKER_SECRET", "change-me")


class RuleMonitor:
    """Simple helper that keeps a cached copy of the Android policy manifest."""

    def __init__(self, local_path: Path, remote_source: str) -> None:
        self.local_path = local_path
        self.remote_source = remote_source
        self._cache: Dict[str, object] | None = None

    def load(self) -> Dict[str, object]:
        if self._cache is not None:
            return self._cache
        self._cache = self._load_from_disk()
        return self._cache

    def refresh(self) -> Dict[str, object]:
        """Attempt to refresh rules from the remote source, falling back to disk."""
        try:
            data = self._download_remote_manifest()
            self.local_path.parent.mkdir(parents=True, exist_ok=True)
            self.local_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            self._cache = data
            return data
        except URLError as exc:
            app.logger.warning("Network issue refreshing SDK rules: %s", exc)
        except Exception as exc:  # noqa: BLE001 - we want to surface the error message
            app.logger.warning("Failed to refresh SDK rules: %s", exc)
        data = self._load_from_disk()
        self._cache = data
        return data

    def _load_from_disk(self) -> Dict[str, object]:
        if not self.local_path.exists():
            return {
                "version": "0.0.0",
                "updated": datetime.utcnow().isoformat() + "Z",
                "notes": [
                    "No official rules available. Check your network connection or set ``SDK_RULE_SOURCE``.",
                ],
                "requirements": [],
            }
        return json.loads(self.local_path.read_text(encoding="utf-8"))

    def _download_remote_manifest(self) -> Dict[str, object]:
        headers = {"User-Agent": "AppMakerWebViewStudio/1.0"}
        request = Request(self.remote_source, headers=headers)
        with urlopen(request, timeout=5) as response:  # noqa: S310 - controlled URL
            charset = response.headers.get_content_charset() or "utf-8"
            data = json.loads(response.read().decode(charset))
        return data


rule_monitor = RuleMonitor(
    DATA_PATH,
    os.environ.get("SDK_RULE_SOURCE", DEFAULT_RULE_SOURCE),
)


def validate_package_name(package_name: str) -> bool:
    pattern = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)+$")
    return bool(pattern.match(package_name))


def sanitize_class_name(app_name: str) -> str:
    cleaned = re.sub(r"[^0-9a-zA-Z]+", " ", app_name).title().replace(" ", "")
    if not cleaned:
        cleaned = "AppShell"
    if cleaned[0].isdigit():
        cleaned = f"App{cleaned}"
    return cleaned


def create_project_files(
    app_name: str,
    package_name: str,
    start_url: str,
    rules: Dict[str, object],
    signing_config: Dict[str, str] | None = None,
    rule_source: str | None = None,
) -> Dict[str, str]:
    files: Dict[str, str] = {}
    rules_summary = "\n".join(
        f"- {item}" for item in rules.get("requirements", [])
    ) or "- Stay informed by reviewing the Android developer blog regularly."
    resolved_rule_source = rule_source or rule_monitor.remote_source
    class_base = sanitize_class_name(app_name)
    activity_class = f"{class_base}Activity"

    files["settings.gradle"] = f"""\
rootProject.name = \"{app_name}\"
include(\":app\")
"""

    files["gradle.properties"] = """\
android.useAndroidX=true
android.enableJetifier=true
org.gradle.jvmargs=-Xmx2048m -Dfile.encoding=UTF-8
"""

    files["build.gradle"] = """\
buildscript {
    repositories {
        google()
        mavenCentral()
    }
    dependencies {
        classpath 'com.android.tools.build:gradle:8.3.2'
        classpath "org.jetbrains.kotlin:kotlin-gradle-plugin:1.9.23"
    }
}

allprojects {
    repositories {
        google()
        mavenCentral()
    }
}
"""

    files["app/build.gradle"] = f"""\
import java.io.FileInputStream
import java.util.Properties

plugins {{
    id 'com.android.application'
    id 'org.jetbrains.kotlin.android'
}}

def keystorePropertiesFile = rootProject.file("keystore.properties")
def keystoreProperties = new Properties()
if (keystorePropertiesFile.exists()) {{
    keystoreProperties.load(new FileInputStream(keystorePropertiesFile))
}}

android {{
    namespace '{package_name}'
    compileSdk 34

    defaultConfig {{
        applicationId '{package_name}'
        minSdk 24
        targetSdk 34
        versionCode 1
        versionName "1.0"

        vectorDrawables {{
            useSupportLibrary true
        }}
    }}

    signingConfigs {{
        release {{
            if (keystoreProperties.containsKey("storeFile")) {{
                storeFile = file(keystoreProperties.getProperty("storeFile"))
                storePassword = keystoreProperties.getProperty("storePassword")
                keyAlias = keystoreProperties.getProperty("keyAlias")
                keyPassword = keystoreProperties.getProperty(
                    "keyPassword",
                    keystoreProperties.getProperty("storePassword"),
                )
                storeType = keystoreProperties.getProperty("storeType", "pkcs12")
                enableV1Signing = true
                enableV2Signing = true
            }}
        }}
    }}

    buildTypes {{
        release {{
            minifyEnabled false
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
            if (keystoreProperties.containsKey("storeFile")) {{
                signingConfig signingConfigs.release
            }}
        }}
        debug {{
            applicationIdSuffix ".debug"
            versionNameSuffix "-debug"
        }}
    }}

    compileOptions {{
        sourceCompatibility JavaVersion.VERSION_17
        targetCompatibility JavaVersion.VERSION_17
    }}
    kotlinOptions {{
        jvmTarget = '17'
    }}
}}

dependencies {{
    implementation 'androidx.core:core-ktx:1.12.0'
    implementation 'androidx.appcompat:appcompat:1.6.1'
    implementation 'com.google.android.material:material:1.11.0'
}}
"""

    files["app/src/main/AndroidManifest.xml"] = f"""\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{package_name}">

    <uses-permission android:name="android.permission.INTERNET" />

    <application
        android:allowBackup="true"
        android:dataExtractionRules="@xml/data_extraction_rules"
        android:fullBackupContent="@xml/backup_rules"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:usesCleartextTraffic="true"
        android:theme="@style/Theme.AppMaker">
        <activity
            android:name=".{activity_class}"
            android:exported="true"
            android:configChanges="keyboardHidden|orientation|screenSize"
            android:usesCleartextTraffic="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />

                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"""

    files["app/src/main/java/{}/{}.kt".format(
        package_name.replace(".", "/"), activity_class
    )] = f"""\
package {package_name}

import android.annotation.SuppressLint
import android.os.Bundle
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity

class {activity_class} : AppCompatActivity() {{

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {{
        super.onCreate(savedInstanceState)
        val webView = WebView(this)
        setContentView(webView)

        val settings: WebSettings = webView.settings
        settings.javaScriptEnabled = true
        settings.domStorageEnabled = true
        settings.loadsImagesAutomatically = true

        webView.webViewClient = WebViewClient()
        webView.loadUrl("{start_url}")
    }}
}}
"""

    files["app/src/main/res/values/strings.xml"] = f"""\
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">{app_name}</string>
</resources>
"""

    files["app/src/main/res/values/themes.xml"] = """\
<?xml version="1.0" encoding="utf-8"?>
<resources xmlns:tools="http://schemas.android.com/tools">
    <style name="Theme.AppMaker" parent="Theme.MaterialComponents.DayNight.NoActionBar">
        <item name="android:statusBarColor">@android:color/transparent</item>
        <item name="android:windowLightStatusBar">true</item>
        <item name="android:windowBackground">@color/app_background</item>
        <item name="android:navigationBarColor">@android:color/black</item>
        <item name="android:navigationBarIconColor">@android:color/white</item>
        <item name="android:forceDarkAllowed">false</item>
        <item name="windowActionBar">false</item>
        <item name="windowNoTitle">true</item>
    </style>
</resources>
"""

    files["app/src/main/res/values-night/themes.xml"] = """\
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <style name="Theme.AppMaker" parent="Theme.MaterialComponents.DayNight.NoActionBar">
        <item name="android:statusBarColor">@android:color/transparent</item>
        <item name="android:forceDarkAllowed">true</item>
        <item name="android:windowBackground">@android:color/black</item>
    </style>
</resources>
"""

    files["app/src/main/res/values/colors.xml"] = """\
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <color name="app_background">#FFFFFFFF</color>
</resources>
"""

    files["app/src/main/res/xml/data_extraction_rules.xml"] = """\
<?xml version="1.0" encoding="utf-8"?>
<data-extraction-rules>
    <cloud-backup>
        <include domain="file" path="." />
    </cloud-backup>
</data-extraction-rules>
"""

    files["app/src/main/res/xml/backup_rules.xml"] = """\
<?xml version="1.0" encoding="utf-8"?>
<full-backup-content>
    <include domain="file" path="." />
</full-backup-content>
"""

    files["app/proguard-rules.pro"] = "# Keep default ProGuard rules.\n"

    files["README.md"] = f"""\
# {app_name}

Generated with **AppMaker WebView Studio**.

## Getting Started

1. Install [Android Studio](https://developer.android.com/studio).
2. Open this project folder.
3. Update the application ID if you rename the package.
4. Customize icons under `app/src/main/res/mipmap-*`.
5. Build and run on a device or emulator.

## WebView configuration

- Launch URL: `{start_url}`
- JavaScript and DOM storage enabled by default.

## Compliance and Google Play rules

This project bundles the latest policy manifest that the AppMaker backend was aware of when
it generated your project. Run the included script to refresh the requirements before
shipping:

```bash
python tools/update_rules.py
```

Latest known requirements:
{rules_summary}
"""

    files["tools/update_rules.py"] = f"""\
#!/usr/bin/env python3
\"\"\"Refresh Android rules for this template.\"\"\"

from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

REMOTE_SOURCE = os.environ.get(
    "SDK_RULE_SOURCE",
    "{resolved_rule_source}",
)
OUTPUT = Path(__file__).resolve().parents[1] / "android_rules.json"


def fetch_rules() -> dict:
    headers = {"User-Agent": "AppMakerWebViewStudio/1.0"}
    request = Request(REMOTE_SOURCE, headers=headers)
    with urlopen(request, timeout=10) as response:  # noqa: S310 - controlled URL
        charset = response.headers.get_content_charset() or "utf-8"
        return json.loads(response.read().decode(charset))


def main() -> None:
    try:
        data = fetch_rules()
    except URLError as exc:
        raise SystemExit(f"Failed to download rules: {exc}")
    OUTPUT.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"Updated rules: version={{data.get('version')}}")


if __name__ == "__main__":
    main()
"""

    files["android_rules.json"] = json.dumps(rules, indent=2)

    files["tools/build_release.sh"] = """\
#!/usr/bin/env bash
set -euo pipefail

if [ -x "./gradlew" ]; then
  ./gradlew assembleRelease bundleRelease
elif command -v gradle >/dev/null 2>&1; then
  gradle assembleRelease bundleRelease
else
  echo "Gradle is not available. Install Gradle or Android Studio to build releases." >&2
  exit 1
fi
"""

    if signing_config:
        keystore_lines = [
            f"storeFile={signing_config['store_file']}",
            f"storePassword={signing_config['store_password']}",
            f"keyAlias={signing_config['key_alias']}",
            f"keyPassword={signing_config['key_password']}",
            f"storeType={signing_config.get('store_type', 'pkcs12')}",
        ]
        files["keystore.properties"] = "\n".join(keystore_lines) + "\n"

    return files


def build_project_zip(app_name: str, package_name: str, start_url: str, rules: Dict[str, object]) -> io.BytesIO:
    """Create an Android project zip configured for the provided parameters."""
    files = create_project_files(
        app_name,
        package_name,
        start_url,
        rules,
        rule_source=rule_monitor.remote_source,
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w") as archive:
        for path, content in files.items():
            archive.writestr(path, content)
    buffer.seek(0)
    return buffer


def create_release_keystore(
    alias: str,
    password: str,
    common_name: str,
    organization: str,
    country: str,
    validity_days: int,
) -> Tuple[bytes, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name_attributes = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if organization:
        name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    if country:
        name_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
    subject = x509.Name(name_attributes)
    now = datetime.utcnow()
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    keystore_bytes = pkcs12.serialize_key_and_certificates(
        name=alias.encode("utf-8"),
        key=key,
        cert=certificate,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
    )
    return keystore_bytes, certificate


def materialize_project(files: Dict[str, str], destination: Path) -> None:
    for relative, content in files.items():
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        if target.suffix == ".sh":
            target.chmod(0o755)


def run_gradle_tasks(project_dir: Path, tasks: List[str]) -> Tuple[List[Path], str, int]:
    command: List[str] | None = None
    wrapper = project_dir / "gradlew"
    if wrapper.exists():
        command = ["./gradlew", *tasks]
    elif shutil.which("gradle"):
        command = ["gradle", *tasks]
    else:
        message = (
            "Gradle wrapper not found and 'gradle' command is unavailable. Install Android Studio "
            "or Gradle, then run tools/build_release.sh."
        )
        return [], message, 127

    try:
        result = subprocess.run(
            command,
            cwd=project_dir,
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        return [], f"Failed to execute {' '.join(command)}: {exc}", 127

    log_output = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
    artifacts: List[Path] = []
    if result.returncode == 0:
        candidates = [
            project_dir / "app" / "build" / "outputs" / "apk" / "release" / "app-release.apk",
            project_dir / "app" / "build" / "outputs" / "bundle" / "release" / "app-release.aab",
        ]
        for candidate in candidates:
            if candidate.exists():
                artifacts.append(candidate)
    return artifacts, log_output.strip(), result.returncode


def certificate_summary(certificate: x509.Certificate) -> str:
    fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
    lines = [
        f"Subject: {certificate.subject.rfc4514_string()}",
        f"Issuer: {certificate.issuer.rfc4514_string()}",
        f"Serial: {certificate.serial_number}",
        f"Valid from: {certificate.not_valid_before.isoformat()}",
        f"Valid to: {certificate.not_valid_after.isoformat()}",
        f"Signature hash: {certificate.signature_hash_algorithm.name}",
        "",
        f"SHA-256 fingerprint: {fingerprint}",
    ]
    return "\n".join(lines)


def generate_release_package(
    app_name: str,
    package_name: str,
    start_url: str,
    rules: Dict[str, object],
    signing_details: Dict[str, str],
) -> Tuple[io.BytesIO, str, List[str], int]:
    signing_config = {
        "store_file": "release.keystore",
        "store_password": signing_details["store_password"],
        "key_alias": signing_details["key_alias"],
        "key_password": signing_details["key_password"],
        "store_type": "pkcs12",
    }
    files = create_project_files(
        app_name,
        package_name,
        start_url,
        rules,
        signing_config=signing_config,
        rule_source=rule_monitor.remote_source,
    )
    keystore_bytes, cert = create_release_keystore(
        signing_details["key_alias"],
        signing_details["store_password"],
        signing_details["common_name"],
        signing_details.get("organization", ""),
        signing_details.get("country", ""),
        signing_details.get("validity_days", 3650),
    )

    certificate_info = certificate_summary(cert)

    with tempfile.TemporaryDirectory() as tmpdir_str:
        tmpdir = Path(tmpdir_str)
        materialize_project(files, tmpdir)
        keystore_path = tmpdir / signing_config["store_file"]
        keystore_path.write_bytes(keystore_bytes)
        keystore_path.chmod(0o600)

        artifacts, log_output, exit_code = run_gradle_tasks(
            tmpdir, ["assembleRelease", "bundleRelease"]
        )

        bundle = io.BytesIO()
        with zipfile.ZipFile(bundle, mode="w") as archive:
            for root, _, filenames in os.walk(tmpdir):
                for filename in filenames:
                    file_path = Path(root) / filename
                    arcname = Path("project") / file_path.relative_to(tmpdir)
                    archive.write(file_path, str(arcname))
            archive.writestr("project/RELEASE_CERTIFICATE.txt", certificate_info + "\n")

            if log_output:
                archive.writestr("outputs/build.log", log_output + "\n")
            for artifact in artifacts:
                archive.write(artifact, f"outputs/{artifact.name}")

        bundle.seek(0)
    artifact_names = [artifact.name for artifact in artifacts]
    return bundle, certificate_info, artifact_names, exit_code


def form_errors(app_name: str, package_name: str, start_url: str) -> List[str]:
    errors: List[str] = []
    if not app_name.strip():
        errors.append("App name is required.")
    if not package_name.strip():
        errors.append("Package name is required.")
    elif not validate_package_name(package_name):
        errors.append(
            "Package name must follow the Java package naming convention (e.g. com.example.app)."
        )
    if not start_url.strip():
        errors.append("A start URL is required for the WebView to load.")
    return errors


@app.before_request
def ensure_rules_loaded() -> None:
    """Make sure we have the latest cached rule manifest."""
    rule_monitor.load()


@app.route("/", methods=["GET"])
def index() -> str:
    rules = rule_monitor.load()
    return render_template(
        "index.html",
        rules=rules,
    )


@app.route("/generate", methods=["POST"])
def generate() -> Response:
    app_name = request.form.get("app_name", "").strip()
    package_name = request.form.get("package_name", "").strip()
    start_url = request.form.get("start_url", "").strip()

    errors = form_errors(app_name, package_name, start_url)
    if errors:
        for message in errors:
            flash(message, "error")
        return redirect(url_for("index"))

    rules = rule_monitor.load()
    archive = build_project_zip(app_name, package_name, start_url, rules)
    filename = f"{package_name.split('.')[-1]}-webview-app.zip"
    return send_file(
        archive,
        mimetype="application/zip",
        as_attachment=True,
        download_name=filename,
    )


@app.route("/generate-release", methods=["POST"])
def generate_release() -> Response:
    app_name = request.form.get("app_name", "").strip()
    package_name = request.form.get("package_name", "").strip()
    start_url = request.form.get("start_url", "").strip()

    errors = form_errors(app_name, package_name, start_url)

    alias = request.form.get("key_alias", "release").strip() or "release"
    store_password = request.form.get("keystore_password", "").strip()
    key_password = request.form.get("key_password", "").strip() or store_password
    common_name = request.form.get("signing_common_name", app_name).strip() or app_name
    organization = request.form.get("signing_organization", "").strip()
    country = request.form.get("signing_country", "").strip().upper()
    validity_raw = request.form.get("signing_validity", "3650").strip()

    if not store_password:
        errors.append("A keystore password is required for signing.")
    if not key_password:
        errors.append("A key password is required for signing.")
    if country and (len(country) != 2 or not country.isalpha()):
        errors.append("Country code must be a two-letter ISO code (e.g. US).")
    try:
        validity_days = max(1, int(validity_raw or "3650"))
    except ValueError:
        errors.append("Certificate validity must be a number of days.")
        validity_days = 3650

    if errors:
        for message in errors:
            flash(message, "error")
        return redirect(url_for("index"))

    rules = rule_monitor.load()

    signing_details = {
        "key_alias": alias,
        "store_password": store_password,
        "key_password": key_password,
        "common_name": common_name,
        "organization": organization,
        "country": country,
        "validity_days": validity_days,
    }

    try:
        bundle, _certificate_info, artifact_names, exit_code = generate_release_package(
            app_name,
            package_name,
            start_url,
            rules,
            signing_details,
        )
    except Exception as exc:  # noqa: BLE001 - surface for user feedback
        app.logger.exception("Failed to generate release bundle")
        flash(f"Failed to generate release bundle: {exc}", "error")
        return redirect(url_for("index"))

    if exit_code == 0 and artifact_names:
        artifact_list = ", ".join(artifact_names)
        flash(f"Release bundle ready with artifacts: {artifact_list}.", "success")
    else:
        flash(
            "Release bundle generated. Check outputs/build.log inside the archive for build details.",
            "warning",
        )

    filename = f"{package_name.split('.')[-1]}-release-package.zip"
    return send_file(
        bundle,
        mimetype="application/zip",
        as_attachment=True,
        download_name=filename,
    )


@app.route("/refresh-rules", methods=["POST"])
def refresh_rules() -> Response:
    rules = rule_monitor.refresh()
    flash(
        f"Rules refreshed: version {rules.get('version', 'unknown')} (source: {rule_monitor.remote_source})",
        "success",
    )
    return redirect(url_for("index"))


@app.route("/api/sdk-rules", methods=["GET"])
def api_rules() -> Response:
    rules = rule_monitor.load()
    return jsonify({
        "rules": rules,
        "source": rule_monitor.remote_source,
    })


@app.route("/health", methods=["GET"])
def health() -> Response:
    return jsonify({"status": "ok", "updated": rule_monitor.load().get("updated")})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
