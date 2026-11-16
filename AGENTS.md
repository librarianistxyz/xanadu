# XANADU Build & Deployment Rules

Whenever Desktop (`xnd-hub/`, `xnd-ui/`, `xnd-desktop/`) or Android (`xnd-android/`, `xnd-ui/`) code is modified:

1. **Desktop Rebuild & Deploy:**
   - Rebuild the PyInstaller backend binary **before** packaging Electron:
     ```bash
     cd /home/librarianist/pcGDM/XANADU/xnd-desktop
     pyinstaller --distpath bin --noconfirm xnd-hub-bin.spec
     rm -f dist/*.deb
     npm run dist
     ```
   - Replace the installed AppImage:
     ```bash
     rm -f /home/librarianist/Applications/Xanadu-Browser-0.1.0.AppImage
     cp "dist/Xanadu Browser-0.1.0.AppImage" /home/librarianist/Applications/Xanadu-Browser-0.1.0.AppImage
     chmod +x /home/librarianist/Applications/Xanadu-Browser-0.1.0.AppImage
     ```
   - **Always push the new `.deb` to Desktop** (and remove any old `.deb` there):
     ```bash
     rm -f /home/librarianist/Desktop/xanadu-desktop*.deb
     cp dist/xanadu-desktop_0.1.0_amd64.deb /home/librarianist/Desktop/xanadu-desktop_0.1.0_amd64.deb
     ```

2. **Android Rebuild & Deploy:**
   - Rebuild the APK and install it onto any connected `adb` device:
     ```bash
     cd /home/librarianist/pcGDM/XANADU/xnd-android
     ./build_apk.sh
     adb install -r ./xanadu-browser.apk
     ```

3. **UI Icon Rule:**
   - **Never use emojis in UI/components** — always use real inline SVGs.
