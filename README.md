# Qualys Client voor macOS

Open de zelfstandige SwiftUI-app op macOS 14 of hoger met een volledige Xcode-installatie:

```sh
app="$(./macos/build-qualys-app.sh)" && open "$app"
```

Open **Instellingen** met **⌘,** en vul de HTTPS-basis-URL van de Qualys API voor je platform, je VM/VMDR API-inloggegevens en de exacte naam van één asset-tag in. Klik op **Bewaar en laad QID’s**. De app bewaart het wachtwoord in de macOS-sleutelhanger.

De catalogus zoekt naar macOS-detecties binnen de opgegeven tag die de afgelopen 30 dagen zijn gezien. De Qualys KnowledgeBase API 4.0 levert de titels, producten, CVE’s en ernst van de gevonden QID’s. De app toont ernst 5 en sorteert standaard op het aantal unieke Macs. Met **Ververs** haal je deze selectie opnieuw op.
