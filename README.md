# Qualys Client voor macOS

Open de zelfstandige SwiftUI-app op macOS 14 of hoger met een volledige Xcode-installatie:

```sh
app="$(./macos/build-qualys-app.sh)" && open "$app"
```

Open **Instellingen** met **⌘,** en vul de HTTPS-basis-URL van de Qualys API voor je platform, je VM/VMDR API-inloggegevens en de exacte naam van één asset-tag in. Klik op **Bewaar en laad QID’s**. De app bewaart het wachtwoord in de macOS-sleutelhanger.

De catalogus leest detecties voor de ingestelde tag en vult titels, producten en CVE’s aan via de Qualys KnowledgeBase. Gebruik **Ververs** om opnieuw op te halen, de zoekbalk voor QID, CVE, titel of product, de zijbalk voor ernst en de kolomkoppen om te sorteren.
