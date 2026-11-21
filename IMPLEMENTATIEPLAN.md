# Implementatieplan Werkplekupdates voor macOS

Bouw een interne beheertool voor circa 1.000 Macs en ongeveer 10.000 open Qualys-detecties. De beheerder ziet welke **oplossingen** nodig zijn, voert centrale patches uit in Jamf Pro en geeft voor de overige oplossingen één taak per getroffen Mac. De SwiftUI-app toont die taken en laat de gebruiker melden dat een instructie is uitgevoerd. Qualys bevestigt de uitkomst per detectie.

## 1. Opdracht voor het uitvoerende model

Voer de bouwfasen in volgorde uit. De projectmap start leeg, afgezien van dit plan. Lever een uitvoerbare webapp, een Xcode-project, tests en lokale startinstructies op. Begin met fictieve Macs, QID’s, CVE’s en scanresultaten. Houd de tests reproduceerbaar zonder externe accounts. Voer de echte proefimport en Jamf-uitrol uit zodra de organisatie de benodigde toegang en proefgroep heeft verstrekt.

| Onderdeel | Vastgelegde keuze |
| --- | --- |
| Backend | Python 3.12, Django 5.2 LTS, PostgreSQL 16. Eén service voor HTML en JSON. Django-templates en gewone JavaScript voor de beheerinterface. |
| Desktop | Een native app in Swift en SwiftUI. Kies macOS 14 als voorlopig minimum en verifieer dit bij de proefgroep. |
| Netwerk | De webapp is intern bereikbaar via het verplichte bedrijfs-VPN. Gebruik de bestaande interne HTTPS-ingang. De Mac-app gebruikt het serienummer als toegangstoken. |
| Beheerders | Voor de eerste versie krijgt iedere beheerder een eigen Django-account met de rol `remediation_admin`, een sessie en CSRF-bescherming. |
| Koppelingen | Lees Qualys centraal uit onder één toegewezen tag. Jamf Pro verzorgt pakketdistributie en patches. De beheerder configureert Jamf-uitrollen daar en registreert ze in dit beheerscherm. |
| Lokale start | Docker Compose met `db` en `web`, een named volume, migraties en demodata. De Mac-app draait vanuit Xcode. |

Een serienummer is opvraagbaar. Met de afgesproken toegang kunnen VPN-gebruikers die een ander geldig serienummer kennen de taken van die Mac ophalen en afvinken. Beperk deze toegang tot de taakroutes uit §8. Houd inventaris, detecties, beheerdersfuncties en Qualys-inloggegevens achter hun eigen toegang. Gebruik standaard HTTPS-serververtrouwen en het serienummer als enige toegangstoken voor de Mac-app.

De voorlopige platformversies, de lokale beheerdersaccounts en het importinterval hieronder zijn implementatiekeuzes voor de eerste versie. Bevestig de werkelijke macOS-versies, de Qualys API-rechten en de interne publicatieroute bij de proef. [Django-platformvereisten](https://docs.djangoproject.com/en/5.2/faq/install/) · [SwiftUI](https://developer.apple.com/documentation/swiftui)

## 2. Indeling en lokaal startpunt

```text
compose.yaml
.env.example
README.md
server/
  manage.py
  config/                Django-instellingen en hoofd-URL’s
  workupdates/           Datamodel, services, routes en migraties
    qualys/              API-client, XML-parsers, genormaliseerde import
    management/commands/ seed_demo en sync_qualys
    templates/           Beheerschermen
    static/              CSS en gedrag van formulieren
    tests/               Domein-, import- en endpointtests
macos/
  Werkplekupdates.xcodeproj
  Werkplekupdates/       SwiftUI, API-client, opslag en meldingen
  WerkplekupdatesTests/  Codable-, opslag- en meldingstests
```

- Leg reproduceerbare releases vast voor Django, `psycopg`, de HTTP-client, `defusedxml` en Gunicorn. Gebruik in Compose PostgreSQL voor ontwikkeling en tests, zodat databaseconstraints en locks ook lokaal worden uitgeoefend.
- Documenteer `docker compose up --build -d`, `docker compose exec web python manage.py migrate`, `docker compose exec web python manage.py createsuperuser`, `docker compose exec web python manage.py seed_demo` en `docker compose exec web python manage.py test`. Geef het lokale beheerscherm op `/beheer/` en een fictief serienummer op in de README. Geef de Django-groep `remediation_admin` toegang tot `/beheer/` en laat het lokale superuseraccount daar ook in. `seed_demo` is herhaalbaar, vereist `DEMO_MODE=1` en gebruikt vaste fictieve ID’s.
- Gebruik omgevingsvariabelen voor database, Django-secret, toegestane hosts en Qualys-gegevens. Neem per variabele een lege of fictieve waarde op in `.env.example`. Geef echte waarden door via de bestaande secretvoorziening. Gebruik Gunicorn achter de interne ingress voor de proef en Django `runserver` voor lokale ontwikkeling.
- Voeg een beperkte `GET /healthz` toe die de databaseverbinding controleert. Toon de tijd van de laatste **succesvolle Qualys-import** en de laatste importfout alleen in het beheerscherm.

## 3. Gegevensmodel en invarianten

Gebruik UUID’s voor oplossing, revisie en taak. Gebruik interne hoofdsleutels voor apparaten en bevindingen. Sla tijden op in UTC met timezone-ondersteuning. Het beheerscherm hanteert `Europe/Amsterdam` voor invoer en presentatie. Gebruik foreign keys en databaseconstraints voor onderstaande uniekheden.

| Entiteit | Gegevens en invarianten |
| --- | --- |
| `ImportRun` | Start, einde, status `RUNNING`, `SUCCEEDED` of `FAILED`, aantal pagina’s, aantallen records en een opgeschoonde foutmelding. Bewaar de ingestelde tag per import. |
| `Device` | Qualys-host-ID uniek, optioneel asset-ID, genormaliseerd serienummer, naam, macOS-indicatie en `in_scope`. Een serienummer is uniek voor apparaten die voor app-toegang actief zijn. Markeer ontbrekende en conflicterende koppelingen voor onderzoek. |
| `Qid` | QID als unieke numerieke sleutel, titel, Qualys-ernst 1–5, lijst met CVE-ID’s, gestructureerde vendor/productgegevens en reparatiereferenties voor zover de bron ze levert. Een lege CVE-lijst is geldig. |
| `Detection` | Apparaat, QID, unieke detectiesleutel van Qualys, status, `last_test_at`, `last_found_at`, `last_fixed_at`, `last_processed_at` waar beschikbaar, en de import waarmee het record voor het laatst is ontvangen. Uniek op `(device, qid, source_detection_key)`. |
| `Solution` | Eén blijvende rij met een herkenbare naam en één route `USER` of `JAMF`. Voor Chrome geldt één oplossing voor het beheerde Chrome-kanaal. Houd eventuele afzonderlijke kanalen of werkelijk verschillende ingrepen expliciet apart. |
| `Revision` | Oplossing, volgnummer, titel, optionele doelversie en status `DRAFT`, `ACTIVE`, `SUPERSEDED` of `CLOSED`. Bij `USER` ook instructietekst, optioneel actietype, knoplabel, link en deadline. Bij `JAMF` markeert `jamf_started_at` de handmatige bevestiging dat de uitrol loopt. Bewaar publicatietijd, vervangingsrelatie en de stand bij vervanging. Uniek op `(solution, number)` en een partiële unieke constraint voor één `ACTIVE` revisie per oplossing. |
| `RevisionQid` | Koppeling tussen revisie en QID, uniek per paar, met herkomst `MANUAL` of `RULE`. Leg per revisie vast of automatisch koppelen is goedgekeurd en welke exacte product- en reparatiereferentie mogen matchen. |
| `WorkItem` | Eén record per `(revision, device)`, ongeacht hoeveel bevindingen het apparaat heeft. Status `OPEN`, `PENDING_VERIFICATION`, `VERIFIED` of `OUT_OF_SCOPE`. Bewaar aanmaaktijd, afvinktijd voor de huidige meldingsgeneratie, laatst gecontroleerde tijd en `notification_generation`, initieel `1`. De auditlog bewaart eerdere afvinkmeldingen. |
| `WorkItemEvidence` | Unieke koppeling tussen taak en concrete detectie. Bewaar de laatst geziene positieve test voor de beoordelingslogica. Historische taken en hun koppelingen blijven raadpleegbaar. |
| `AuditEvent` | Tijd, actor, object en gebeurtenis voor publicatie, vervanging, handmatige en automatische koppelingen, afvinken en statusovergangen. Gebruik interne apparaat-ID’s in gebeurtenisrecords. |

Gebruik als detectiesleutel de Qualys `UNIQUE_VULN_ID` wanneer aanwezig. Als de gekozen API-versie die niet levert, gebruik een stabiele sleutel op basis van poort, protocol en SSL-indicatie. Als de response daarmee twee verschillende detecties op dezelfde sleutel zet, toon dit als importafwijking en houd die taak bij IT ter beoordeling. Bewaar host-ID en QID altijd naast die sleutel. De status van een detectie blijft leidend per concrete installatie; één CVE kan aan meerdere QID’s hangen. [Qualys Host Detection List](https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects/qapi-assets/host_lists/host_detection.htm) · [Qualys KnowledgeBase](https://docs.qualys.com/en/vmdr/latest/knowledgebase/win_vulnerability_information.htm)

## 4. Qualys-import

Maak één adapter met een fixturebron en een livebron. Beide leveren dezelfde interne records voor hosts, QID-metadata en detecties. Gebruik voor de livebron drie reeds gedocumenteerde VM-endpoints op de eigen Qualys-pod.

1. **Host List.** Lees de volledige ingestelde tag uit via `/api/2.0/fo/asset/host/` met `action=list`, `details=All`, `host_metadata=all`, `show_asset_id=1`, `use_tags=1`, `tag_set_by=id` en `tag_set_include=<tag-id>`. Lees host-ID en `SERIAL_NUMBER`, en koppel de detecties via host-ID. Verifieer deze join voor meerdere Macs met een export uit de eigen tenant. Als het serienummer voor een host ontbreekt in de API, mag een geautoriseerde CSV met `qualys_host_id,serial_number` de koppeling aanvullen voor hosts die aantoonbaar binnen de tag vallen. Ken toestelrechten alleen toe aan unieke, bevestigde macOS-koppelingen. Gebruik `trim` en hoofdletters voor serienummers aan beide kanten. [Qualys Host List](https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects/qapi-assets/host_lists/host_list.htm)
2. **Host List Detection.** Gebruik `/api/2.0/fo/asset/host/vm/detection/` met `action=list`, `status=New,Active,Re-Opened,Fixed`, de geconfigureerde tag en XML-uitvoer. Gebruik voor de tagfilter `use_tags=1`, `tag_set_by=id` en `tag_set_include=<tag-id>`. Importeer alle ernstniveaus. Bewaar ook `FIXED` voor verificatie. Gebruik `NEW`, `ACTIVE` en de genormaliseerde `REOPENED` als open statussen. Behandel genegeerde, uitgeschakelde en informatiebevindingen als buiten de actieselectie. [Qualys Host Detection List](https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects/qapi-assets/host_lists/host_detection.htm)
3. **KnowledgeBase.** Verrijk ontbrekende of verouderde QID’s in batches van 100 via `/api/2.0/fo/knowledge_base/vuln/` met `action=list`, `details=All` en `ids`. Ververs bekende metadata wekelijks. Gebruik gestructureerde CVE’s en productgegevens wanneer aanwezig. Toon bij ontbrekende metadata de QID als handmatig te beoordelen. [Qualys KnowledgeBase API](https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects/qapi-scan/kbase/knowledgebase.htm)

- Begin voor de VM-v2-paden met Basic-auth en `X-Requested-With: Werkplekupdates` volgens de documentatie. Controleer met de Qualys-beheerder welke API-inloggegevens en host bij de tag horen. Vereis leesrechten voor de genoemde endpoints. Controleer vóór de liveproef of een scan `FIXED` en een bruikbare test- of verificatietijd teruggeeft. Leg de bevestigde vorm vast als geschoonde fixture. [Qualys VM API-authenticatie](https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects/qapi-user/get_started/get_started.htm)
- Volg een geldige vervolg-URL uit de XML-waarschuwing tot alle pagina’s zijn gelezen. Controleer HTTPS, dezelfde geconfigureerde host en hetzelfde API-pad vóór vervolgverzoeken. Detecteer herhaalde vervolg-URL’s. Gebruik time-outs en maximaal drie tijdelijke retries voor time-outs, `429` en `5xx`, met respect voor een geldige `Retry-After`. Zet daarnaast bij de scheduler een bovengrens passend bij de tenantlimiet.
- Importeer elk uur via `python manage.py sync_qualys`, handmatig of vanuit de bestaande interne scheduler. Laat maximaal één import tegelijk lopen met een PostgreSQL advisory lock. Lees en valideer eerst beide volledige host- en detectiefeeds en pas gegevens vervolgens transactioneel toe. Bewaar de vorige succesvolle stand bij een onvolledige, mislukte of structureel ongeldige feed. Een tijdelijke KnowledgeBase-fout mag alleen de metadata-update uitstellen.
- Houd de bestaande toestand bij gelijke of oudere brontijden aan. Gebruik voor een nieuwe positieve bevinding `last_test_at`, met `last_found_at` als terugval. Volg voor definitieve verificatie §7. Beperk records en apparaatstatus tot de geconfigureerde tag. Zet een apparaat dat aantoonbaar uit de **volledige hostlijst** is verdwenen buiten de scope, met behoud van historie. Een ontbrekende detectie of onvolledige response levert op zichzelf geen herstelbewijs.
- Log aantallen per status, looptijd, pagina’s, conflicten en bruikbare versus ontbrekende koppelingen. Houd autorisatieheaders, volledige Qualys-antwoorden en serienummers uit algemene logs en foutmeldingen.

## 5. Beheerscherm, koppelen en publiceren

### Overzicht

Gebruik **Oplossingen** als startpagina. Standaard open ernst 4 en 5, met filters voor alle ernstniveaus, status en route. Sorteer eerst op de hoogste open ernst, daarna op getroffen Macs. Tel binnen een oplossing unieke Macs. Toon route, actuele doelversie en voortgang. Toon de gekozen revisie en historie wanneer een beheerder op de rij klikt. Reserveer **Te beoordelen** voor ongekoppelde of dubbelzinnige bevindingen. Toon per groep de betrokken QID’s en CVE’s en bij uitklappen de betreffende Macs.

### Nieuwe oplossing

1. Open **+ Nieuwe oplossing** vanuit het overzicht of vanuit **Te beoordelen**. Bied groepsvoorstellen op basis van exact bekende vendor/productmetadata. Toon dubbelzinnige of onbekende metadata als handmatige selectie. Een groepsvoorstel helpt selecteren en wijzigt nog geen koppelingen.
2. Toon de QID’s met bijbehorende CVE’s en het aantal getroffen Macs per QID. De beheerder vinkt de passende QID’s aan. Bepaal de doelgroep als de verzameling unieke apparaten met ten minste één open geselecteerde detectie binnen de tag. Toon als voorbeeld dat twee QID’s op elk vier Macs samen zes Macs kunnen raken.
3. Laat de beheerder **Via Jamf** of **Door gebruiker** kiezen. Vraag een titel en geef een optionele doelversie. Bij **Door gebruiker** is de instructie een vrij tekstveld. Voeg optioneel één link en deadline toe. Laat naast de invoer een kaart zien zoals de gebruiker die krijgt, inclusief knoplabel. Ondersteun een gewone `https`-link, een goedgekeurde Jamf Self Service-link of de ingebouwde bestemming **Software-update**. Valideer Jamf-links tegen de toegestane vaste URL-structuur van de organisatie. Behandel instructies als tekst en eventuele commando’s als kopieerbare tekst.
4. **Bewaar concept** slaat de selectie op. **Publiceer** vereist ten minste één QID en een titel, plus een instructie bij `USER`. Voor `JAMF` heet de actie **Registreer voor Jamf**. Activeer de revisie transactioneel, maak de betreffende `WorkItem`-records aan en leg bij elk record de onderliggende detecties vast. Herhaal hetzelfde verzoek veilig via dezelfde revisie-ID. Jamf-items verschijnen in het beheer als **Uit te rollen**. De beheerder kan ze na instelling in Jamf Pro op **Uitrol actief** zetten.
5. Toon na publicatie de gekoppelde QID’s en CVE’s bij de oplossing. Bewaar tekstwijzigingen als een conceptrevisie en laat de beheerder bewust opnieuw publiceren als de instructie voor gebruikers wijzigt. Het lopende werk blijft aan de actuele revisie gekoppeld tot de overstap is bevestigd.

### Automatische koppeling voor vertrouwde oplossingen

Een gepubliceerde revisie kan automatisch nieuwe QID’s ontvangen zodra de beheerder de regel heeft goedgekeurd. Gebruik voor een automatische match een exacte genormaliseerde vendor/productcombinatie én dezelfde goedgekeurde gestructureerde patch- of bulletinreferentie. Laat de beheerder die combinatie uit de geselecteerde metadata bevestigen. Gebruik bij Microsoft, Java-varianten of andere compatibiliteitsverschillen een aparte oplossing als de instructie verschilt. Informatie uit een titel of vrij oplossingstekstvak is alleen een voorstel voor menselijke beoordeling.

Als een QID geen eenduidige metadata heeft, meerdere regels matcht of om een andere fix vraagt, blijft hij bij **Te beoordelen**. Bewaar de reden. Een al goedgekeurde QID mag nieuwe in-scope Macs opleveren zodra Qualys die detectie daar meldt. Voeg bij een nieuwe passende QID de aanvullende detecties toe aan bestaande taken van die revisie. Maak hooguit één taak per apparaat aan. Voor gelijktijdige actieve oplossingen kan één concrete detectie aan hooguit één oplossing zijn toegewezen. Controleer conflicten bij publicatie, vervanging en automatische koppeling binnen dezelfde transacties als de taakwijzigingen.

## 6. Een lopende Jamf-uitrol vervangen

Gebruik Chrome als vaste oplossing en versies 15 en 16 als testnamen. Een nieuwe versie wordt een aparte revisie. De beheerder kan een vervanger voorbereiden terwijl de vorige actief blijft.

1. Open **Vervang uitrol** en vul doelversie 16 in. Neem de nog toepasselijke QID’s mee en laat de beheerder nieuwe QID’s selecteren die versie 16 vereisen of oplost. Toon eventuele weggelaten open QID’s ter beoordeling. Baseer het nieuwe bereik op open detecties van die herziene QID-set in de hele tag, inclusief Macs die al eerder klaar waren als de nieuwe bevindingen hen raken.
2. Toon vóór bevestigen het totale nieuwe bereik en drie elkaar uitsluitende groepen: nog open in de oude revisie, eerder bevestigd in de oude revisie en overige Macs. De verdeling in de demodata is 50, 50 en 200, samen 300. Gebruik uitkomst van eerdere verificatie voor het tweede label. Toon een werkelijk geïnstalleerde versie alleen wanneer beschikbare inventaris die aantoont.
3. De beheerder stelt de nieuwe uitrol in Jamf Pro in en bevestigt vervolgens **Vervang uitrol**. Vergrendel de `Solution`-rij in PostgreSQL, controleer de verwachte actieve revisie, herbereken de doelgroep en vergelijk met de laatst getoonde preview. Bij verschillende selectie of doelgroep toon je de nieuwe preview opnieuw. Markeer de oude revisie als `SUPERSEDED`, sla de oude voortgang op, activeer de nieuwe revisie en maak de nieuwe taken aan in één transactie.
4. Toon in de vaste Chrome-rij vanaf dat moment versie 16. Start voortgang voor de nieuwe doelgroep op nul bevestigingen. De historie vermeldt versie 15 als **Vervangen door 16** met de stand **50 van 100** op het moment van vervanging. Een dubbel bevestigingsverzoek levert dezelfde uitkomst op. Een verzoek met inmiddels verouderde revisie krijgt een conflictmelding.

## 7. Afvinken en door Qualys bevestigen

Gebruik dezelfde centrale statuslogica voor handmatige taken en Jamf-voortgang. De geschiedenis van een oude revisie blijft bevroren in het overzicht. Het afvinken van een huidige gebruikerstaak plaatst hem op `PENDING_VERIFICATION`, met `reported_at` op de server. De Mac toont hem grijs onder **Wacht op controle**.

| Gebeurtenis | Uitkomst |
| --- | --- |
| Eerste melding door gebruiker | `OPEN` wordt `PENDING_VERIFICATION`. Bewaar het tijdstip en pauzeer herinneringen. Herhalen behoudt dat tijdstip. |
| Nieuwe import met oude scan, ontbrekende detectie of onvoldoende brongegevens | Behoud de huidige taakstatus. Maak verouderde informatie zichtbaar als **Wacht op actuele scan** in het beheerscherm. |
| Een echte nieuwe positieve test voor een geselecteerde detectie, na `reported_at` | Zet een taak die wacht op controle terug op `OPEN`, verhoog `notification_generation` eenmaal en maak `reported_at` leeg voor de nieuwe generatie. Baseer deze tijdvergelijking op de gemeten testtijd en gebruik het importtijdstip alleen voor weergave. |
| Alle gekoppelde detecties geven expliciet `FIXED` | Zet de taak op `VERIFIED` als per detectie het vastgestelde `last_fixed_at` of de tijd van de test met die status strikt nieuwer is dan de laatst vastgelegde positieve observatie. Als het bewijs van herstel al aanwezig is bij een offline nagestuurde melding, blijft `VERIFIED` behouden. |
| Verse `REOPENED` of overeenkomende nieuwe open detectie op een bevestigd apparaat | Open voor de actuele revisie hetzelfde werkitem opnieuw of maak het aan als er nog geen was. Verhoog bij heropenen de meldingsgeneratie. |
| Apparaat aantoonbaar buiten de tag | Markeer het werkitem `OUT_OF_SCOPE` en stop levering van taken aan dat serienummer. Houd historie en herstelstatus apart. |
| Apparaat keert aantoonbaar terug in de tag | Evalueer de huidige detecties opnieuw. Als er een open detectie aan een actieve revisie is gekoppeld, activeer hetzelfde werkitem opnieuw als `OPEN` en verhoog de meldingsgeneratie. |

Gebruik als beslisvolgorde eerst scope, daarna nieuw herstelbewijs of bestaande bevestiging, daarna bewijs dat een gekoppelde bevinding nog open staat. De server reageert op een afvinkverzoek voor een al bevestigd werkitem met de bevestigde status. Deze eerste versie behandelt een expliciete, tijdig bevestigde `FIXED` als bewijs voor het verdwijnen uit de open lijst. Afwezigheid zonder bevestiging is onvoldoende, ook bij een complete import.

## 8. Contract voor de macOS-app

Gebruik `Authorization: Bearer <serienummer>` op de twee API-routes. Leid apparaat en scope uitsluitend af uit die header en de intern bijgehouden apparaatkoppeling. Verstuur het serienummer nooit in de URL. Retourneer `401` bij ontbrekende, onbekende, conflicterende of buiten-scope toegang. Geef bij een taak-ID die niet bij het apparaat hoort dezelfde `404` als bij een onbekende taak-ID. Gebruik `Cache-Control: no-store`. De webinterface gebruikt de afzonderlijke beheerderssessie.

### `GET /api/v1/tasks`

Retourneer alleen actuele `USER`-taken voor deze Mac met status `open` of `pending_verification`. Sorteer eerst op status, daarna op deadline met lege deadlines achteraan en ten slotte op titel. Stuur voor een geldige Mac zonder taken `tasks: []` terug. Alle tijden gebruiken RFC 3339 in UTC. Een vaste payload voor het Xcode-contract:

```json
{
  "last_qualys_import_at": "2026-11-21T09:40:00Z",
  "tasks": [
    {
      "id": "7c355dae-5c91-4a78-8ccf-a770ef39b30b",
      "title": "Werk Java 21 bij",
      "instructions": "Volg de handleiding en herstart daarna je IDE.",
      "action": {
        "kind": "url",
        "label": "Open handleiding",
        "url": "https://confluence.example/java-21"
      },
      "deadline_at": "2026-11-27T16:00:00Z",
      "status": "open",
      "notification_generation": 1
    }
  ]
}
```

`last_qualys_import_at`, `deadline_at` en `action` mogen `null` zijn. `action.kind` is `url`, `jamf_self_service` of `software_update`. Bij `software_update` is `url` `null` en kiest de app de ingebouwde route naar Systeeminstellingen. Controleer de werking op de oudste macOS-versie in de proef. Houd QID’s, CVE’s en inventaris buiten de apparaatpayload.

### `POST /api/v1/tasks/{id}/done`

Verwacht `{"notification_generation":1}` met de generatie uit de laatst opgehaalde taak. Vergrendel het werkitem en verifieer apparaat, route, revisie en generatie. Retourneer `200` met `{"id":"<uuid>","status":"pending_verification"}` of `"verified"`. Geef `409` met `{"error":"stale_task"}` bij een vervangen revisie of andere generatie en laat de client opnieuw ophalen. Geef `400` bij een ontbrekende of ongeldige generatie. Een herhaalde aflevering voor dezelfde generatie behoudt de eerste afvinktijd. Na heropening kan de gebruiker opnieuw afvinken met de nieuwe generatie. Het verzoek werkt uitsluitend de interne taakstatus bij.

## 9. De SwiftUI-app en meldingen

- Maak een venster **Acties op deze Mac** met **Te doen** en **Wacht op controle**. Toon instructies als tekst met één actieknop en **Ik heb dit gedaan**. De gebruiker ziet alleen eigen taken. Gebruik `URLSession` voor de interne API, `Codable` voor de gegevenstypen en een apart testbaar model voor status en meldingen. Gebruik een klein IOKit-onderdeel voor het eigen hardwareserienummer en een injecteerbare leverancier voor tests. Geef een duidelijke foutstatus zonder taken als serienummer of configuratie ontbreekt.
- Lees de vaste bedrijfs-URL uit de beheerde voorkeur `ServerURL`. Gebruik een expliciete lokale URL-override in de Xcode-debugconfiguratie voor de ontwikkeling. Gebruik de start bij login die via jullie Jamf-pakket wordt ingesteld. Voor de proef gebruikt een Jamf-beheerde gebruikers-LaunchAgent `/usr/bin/open -g -a /Applications/Werkplekupdates.app` bij login. Test de pakketinstallatie, Apple silicon, de oudste ondersteunde macOS-versie en voortzetting na slaapstand. Gebruik de bestaande goedgekeurde distributieprocedure. [Apple Service Management](https://developer.apple.com/documentation/servicemanagement) · [Jamf-pakketdistributie](https://learn.jamf.com/r/en-US/jamf-pro-documentation-11.21.0/Package_Deployment)
- Haal taken op bij start, bij handmatig verversen, bij terugkeer naar het venster en vervolgens eens per 15 minuten zolang de app draait. Bewaar de laatst opgehaalde lijst, verzendwachtrij en meldingsadministratie in de lokale Application Support-map van de gebruiker. Schrijf deze atomair naar een bestand. Bind die opslag aan de huidige server en Mac. Toon bij verbindingsverlies de laatste succesvolle synchronisatie. Een offline afvinkmelding gaat in een duurzame wachtrij; verwijder die na `200`, of na `404` of `409` gevolgd door een succesvolle verversing. Bij een netwerkfout blijft hij ingepland voor de volgende cyclus. Overweeg een servermelding over verouderde gegevens alleen wanneer de verversing werkelijk mislukt.
- Gebruik `UserNotifications` met een gebundelde melding voor nieuwe of heropende taken en een gebundelde herinnering zodra een deadline is bereikt. Geef na iedere succesvolle synchronisatie hooguit één melding per type. Bewaar deduplicatie op `(task.id, notification_generation, type)` en voor een deadline ook de deadlinewaarde. Geef meldingen alleen voor serverstatus `open` zonder lokaal wachtende afvinkmelding. Bij een verse eerste installatie mag de eerste opgehaalde lijst één gebundelde melding opleveren. Een tik opent de takenlijst. [Apple User Notifications](https://developer.apple.com/documentation/usernotifications)
- Valideer linktypen ook aan de clientkant voordat de app de URL opent. Open Confluence in de browser, Jamf-items via het goedgekeurde Self Service-schema en de OS-update via de ingebouwde bestemming. De gebruiker voert de instructie uit. [Jamf Self Service URL-schema’s](https://learn.jamf.com/r/en-US/jamf-pro-documentation-11.25.0/Jamf_Self_Service_for_macOS_URL_Schemes?contentId=7Ojl0FC6DCSez3ZMEfoPEA)

## 10. Bouwvolgorde en acceptatietests

| Fase | Bouw en verifieer |
| --- | --- |
| 1. Fundering en demo | Start Compose op een lege checkout. Migrate, maak een beheerder en laad fictieve data. De beheerder ziet Chrome, Java en VLC. Filters voor ernst 4/5 en alle niveaus werken. Een apparaat buiten de tag krijgt geen taaktoegang. Voeg fixtures toe voor de gebruikelijke en falende imports. |
| 2. QID-koppeling en publicatie | Twee geselecteerde QID’s op elk vier Macs met twee overlappende Macs geven zes taken. Uitvinken past de preview aan. QID zonder CVE blijft selecteerbaar. Route `JAMF` levert geen gebruikerstaak op. Publiceren en opnieuw verzenden levert hetzelfde aantal werkitems. Een nieuwe match uit een goedgekeurde regel gaat naar de juiste oplossing; ontbrekende of dubbele match gaat naar beoordeling. |
| 3. Uitrolvervanging | Begin met Chrome 15, 50 van 100 bevestigd. Kies de nieuwe QID-set voor versie 16, zie het bereik van 300 met de verdeling 50/50/200. Bevestig en controleer één actieve Chrome-revisie, de behouden historische stand en 300 actuele werkitems. Test twee gelijktijdige bevestigingen, een herhaald verzoek en een gewijzigde doelgroep na preview. |
| 4. Verificatie en apparaat-API | Een afgevinkte taak blijft grijs na een import met oude data. Test daarna een nieuwe positieve scan, herstel van slechts één van twee detecties en uiteindelijk `FIXED` op beide. Een kwijtraakte pagina of verdwenen detectie laat de taakstatus intact. Oefen verlopen scope, verkeerd taak-ID, herhaalde `done`, een oude melding na heropening en een vervangen revisie. Gebruik `curl` of de Django-testclient voor het contract. |
| 5. Mac-app | Bouw in Xcode, laad taken via de fixture-API, open hulpbestemmingen, vink af en controleer de grijze rij. Test offline afvinken, herstellen van de wachtrij na herstart, terugkomen vanuit slaapstand, `409`, geen taken, geweigerde meldingen en deduplicatie van nieuwe en verlopen taken. Controleer de globale melding en de daaropvolgende navigatie op een echte Mac. |
| 6. Live proef | Importeer eerst binnen één afgebakende Qualys-tag. Vergelijk voor enkele Macs serienummer, QID/CVE, ernst, actuele status en testtijden met de Qualys-weergave. Test daarna met twee Macs en breid uit naar circa twintig. Gebruik een Java-gebruikerstaak, een eenmalige actie voor een paar Macs en een centrale Jamf-uitrol. Controleer bereik alleen via het bedrijfsnetwerk/VPN en de eigen takenlijst per aangeboden serienummer. |

Automatiseer het domeingedrag en het servercontract met Django-tests op PostgreSQL. Gebruik Swift XCTest voor het JSON-contract, de offline wachtrij en de beslislogica van meldingen. Test de beheerschermen minstens met een browserworkflow voor aanmaken, QID’s aan- en uitvinken, publiceren en Chrome vervangen. Maak de testfixtures en een voorbeeldrespons van de apparaat-API herbruikbaar. Laat de README de exacte test- en startcommando’s en de uitkomst per fase vermelden.

## 11. Overdracht en beheer van de proef

- Leg in de README vast waar de beheerder inlogt, hoe `sync_qualys` wordt gepland, waar de applicatie de laatste volledige import toont en hoe een foutopsporing begint. Leg ook vast waar een interne beheerder bij een fout de vorige actieve stand en uitrolhistorie kan inzien.
- Monitor importfouten en ouderdom van de laatste geslaagde import. Start met een waarschuwing na twee gemiste intervallen. Documenteer wie de waarschuwing ontvangt en hoe de import wordt gepauzeerd. Bewaar en test een PostgreSQL-back-up vóór de proef.
- Gebruik een eigen Jamf-proefgroep. Terugrol bestaat uit pauzeren van de Jamf-appinstallatie, uitschakelen van de proefplanning en terugvallen op de laatste goedgekeurde release van de webapp. Software-uitrollen zelf blijven beheerd vanuit Jamf Pro.
- Lever eerst de lokale demonstratie op. Voor de liveproef zijn een werkende Qualys-API-toegang tot de tag, verifieerbare serienummerkoppelingen, een interne URL en toestemming voor de Jamf-proefgroep nodig. Geef expliciet aan welke controles zijn geslaagd en welke op toegang of een proefapparaat wachten.

Ontwerpdetail voor uitvoering: gebruik de zichtbare termen **Oplossingen**, **Te beoordelen**, **Nieuwe oplossing**, **Te koppelen detecties**, **Vervang uitrol**, **Ik heb dit gedaan** en **Wacht op controle**. De beheerinterface volgt oplossingen en voortgang per groep. De Mac-interface toont een korte persoonlijke actielijst met links en status.
