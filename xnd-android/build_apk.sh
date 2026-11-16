#!/usr/bin/env bash
set -euo pipefail

export PATH="/home/librarianist/java/17.0.13+11/bin:$PATH"
DIR="$(cd "$(dirname "$0")" && pwd)"
SDK="${ANDROID_HOME:-$HOME/Android/Sdk}"
BT="$SDK/build-tools/35.0.0"
PLATFORM="$SDK/platforms/android-35/android.jar"
KEYSTORE="$HOME/.android/debug.keystore"

rm -rf "$DIR/build" "$DIR/assets"
mkdir -p "$DIR/build/classes" "$DIR/build/dex" "$DIR/assets/xnd-ui"
cp -r "$DIR/../xnd-ui/." "$DIR/assets/xnd-ui/"

"$BT/aapt" package -f -m \
  -J "$DIR/build" \
  -M "$DIR/AndroidManifest.xml" \
  -S "$DIR/res" \
  -A "$DIR/assets" \
  -I "$PLATFORM"

javac --release 11 -cp "$PLATFORM" -d "$DIR/build/classes" \
  "$DIR/src/com/xanadu/browser/Bip340.java" \
  "$DIR/src/com/xanadu/browser/Ed25519.java" \
  "$DIR/src/com/xanadu/browser/E2eeSpaces.java" \
  "$DIR/src/com/xanadu/browser/TransclusionEngine.java" \
  "$DIR/src/com/xanadu/browser/GitHubHosting.java" \
  "$DIR/src/com/xanadu/browser/NatTunnel.java" \
  "$DIR/src/com/xanadu/browser/WifiDirectMesh.java" \
  "$DIR/src/com/xanadu/browser/LocalNodeServer.java" \
  "$DIR/src/com/xanadu/browser/MeshSyncJobService.java" \
  "$DIR/src/com/xanadu/browser/MainActivity.java"

"$BT/d8" --lib "$PLATFORM" --output "$DIR/build/dex" \
  $(find "$DIR/build/classes" -name '*.class')

"$BT/aapt" package -f \
  -M "$DIR/AndroidManifest.xml" \
  -S "$DIR/res" \
  -A "$DIR/assets" \
  -I "$PLATFORM" \
  -F "$DIR/build/unaligned.apk"

(cd "$DIR/build/dex" && zip -q "$DIR/build/unaligned.apk" classes.dex)

"$BT/zipalign" -f 4 "$DIR/build/unaligned.apk" "$DIR/build/aligned.apk"

"$BT/apksigner" sign \
  --ks "$KEYSTORE" \
  --ks-pass pass:android \
  --key-pass pass:android \
  --out "$DIR/xanadu-browser.apk" \
  "$DIR/build/aligned.apk"

ls -lh "$DIR/xanadu-browser.apk"
