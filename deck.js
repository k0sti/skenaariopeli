const ilmiöt = [
    {
      "Gen": true,
      "Lähde": "Yle Teknologian Ilmiökartta 2018/1",
      "Ilmiö": "Puettava teknologia",
      "Mistä on kyse?": "Teknologia integroituu osaksi ihmisen vaatteita, koruja, keholla pidettäviä esineitä."
    },
    {
      "Gen": false,
      "Lähde": "Yle Teknologian Ilmiökartta 2018/1",
      "Ilmiö": "Kontekstitietoisuus",
      "Mistä on kyse?": "Palvelua tarjottaessa tunnistetaan käyttäjän käyttökonteksti. Tilanne ja asiayhteydet, ympäristö, tausta ja olosuhteet vaikuttavat käyttäjän saamaan palveluun."
    },
    {
      "Gen": true,
      "Lähde": "Yle Teknologian Ilmiökartta 2018/1",
      "Ilmiö": "Verkkojen yhdistyminen",
      "Mistä on kyse?": "Eri teknologioilla toteutetut verkot yhdentyvät käyttäjän kannalta yhdeksi verkoksi, joka tarjoaa katkeamattomia palveluita."
    },
    {
      "Gen": false,
      "Lähde": "Yle Teknologian Ilmiökartta 2019/1",
      "Ilmiö": "Lisätty todellisuus",
      "Mistä on kyse?": "Lisätyn todellisuuden avulla tuodaan käyttäjälle saumattomasti näkö- ja kuulokentässä olevaan kohteeseen liittyvää lisäinformaatiota. Todellinen ja lisätty näkymä ilmaantuvat yhtä aikaa."
    },
    {
      "Gen": true,
      "Lähde": "Yle Teknologian Ilmiökartta 2019/1",
      "Ilmiö": "Älykäyttöpinnat",
      "Mistä on kyse?": "Uusi teknologia mahdollistaa jopa pöydän tai seinän kokoiset älykäyttöpinnat. Kuva, ääni, kosketus, henkilön ja kehon kielen tunnistus. Virtuaalitodellisuutta ilman laseja. Fotorealistiset ikkunat haluttuun maailmaan."
    },
    {
      "Gen": false,
      "Lähde": "Yle Teknologian Ilmiökartta 2019/1",
      "Ilmiö": "Käyttöliittymätön käyttöliittymä",
      "Mistä on kyse?": "Häiritsemättömän teknologian avulla ihmisen liityntä digitaaliseen ympäristöön. Eleiden, puheen ja muiden aistien kautta."
    },
    {
      "Gen": false,
      "Lähde": "Yle Teknologian Ilmiökartta 2019/1",
      "Ilmiö": "Laajennetut aistihavainnot",
      "Mistä on kyse?": "Tuotetaan laajennettuja aistihavaintoja, jossa mukana tuoksu, tunto, maku, kosteus, lämpötila, ilmavirta."
    },
    {
      "Gen": false,
      "Lähde": "Yle Teknologian Ilmiökartta 2019/1",
      "Ilmiö": "Ihmisen digitaalinen kaksonen",
      "Mistä on kyse?": "Kehittynyt avustaja, joka tuntee käyttäjän ja osaa ennakoida tilanteita. Aina hereillä. Viestii käyttäjän kanssa inhimillisellä tavalla. Tekee asioita käyttäjän puolesta, pyynnöstä ja pyytämättä."
    },
    {
      "Gen": false,
      "Lähde": "Yle Teknologian Ilmiökartta 2019/1",
      "Ilmiö": "Ajatusten tunnistaminen",
      "Mistä on kyse?": "Tunteita voi mitata. Laitteita voi ohjata pelkillä ajatuksilla. Tunnemaailma avautuu aivosensoreilla, ilmeistä, äänestä, pulssista, ihon sähkönjohtavuudesta, tai välillisesti tekemisistä, e.g. aktiivisuudesta verkossa"
    },
    {
      "Gen": false,
      "Lähde": "Yle Teknologian Ilmiökartta 2019/1",
      "Ilmiö": "Ihmisen parantelu",
      "Mistä on kyse?": "Ihmisten puutteiden korjaaminen ja jopa normaalien kykyjen ylittäminen. Apuvälineitä, jotka integroituvat ihmiseen, ovat aina mukana. Tehostetut aistit, sokealle silmälasit joilla näkee, kuurot kuulemaan. Geenimanipulaatio."
    },
    {
      "Gen": false,
      "Lähde": "Yle Teknologian Ilmiökartta 2019/1",
      "Ilmiö": "Manipuloitu video",
      "Mistä on kyse?": "Kasvonilmeet, puheen ja jopa puhujan voi vaihtaa livenä toiseksi"
    },
    {
      "Gen": false,
      "Lähde": "Yle Teknologian Ilmiökartta 2019/1",
      "Ilmiö": "Tekoälyn tuottama sisältö",
      "Mistä on kyse?": "Automaattista sisällöntuotantoa, -rikastusta ja visualisointia (myös pelkkä audio). Sisällön luonti ja koostaminen suuresta määrästä lähtömateriaaleja."
    },
    {
      "Gen": false,
      "Lähde": "Yle Teknologian Ilmiökartta 2019/1",
      "Ilmiö": "Tekoälypandemia",
      "Mistä on kyse?": "Tekoäly tulee kapea-alaisina palasina mukaan kaikkiin prosesseihin. Pan ’kaikki’ ja demos ’ihmiset’."
    },
    {
      "Gen": false,
      "Lähde": "Yle Teknologian Ilmiökartta 2019/1",
      "Ilmiö": "3D:n uudet muodot",
      "Mistä on kyse?": "Robotisaation sivuvaikutuksena kertyy huomattava määrä 3D-dataa ympäristöstä. Data tulee hyödynnettäväksi myös muuhun. Pelimaailmassa virtuaaliset 3D-maailmat ovat mainstreamia ja osaaminen laajaa."
    },
    {
      "Gen": false,
      "Lähde": "Yle Teknologian Ilmiökartta 2019/1",
      "Ilmiö": "Robotiikka",
      "Mistä on kyse?": "Robottien fyysiset kyvyt kehittyvät hyvin nopeasti. Robottien kokokirjo on laaja, hyönteisistä valtamerialuksiin. Niistä on tullut sujuvasti itsenäisesti sekä laumassa toimivia."
    },
    {
      "Gen": false,
      "Lähde": "Yle Teknologian Ilmiökartta 2019/1",
      "Ilmiö": "Puheen ymmärrys",
      "Mistä on kyse?": "Kone ymmärtää sujuvasti suomenkielistä puhetta ja puheen todellisia merkityksiä."
    },
    {
      "Gen": false,
      "Lähde": "Yle Teknologian Ilmiökartta 2019/1",
      "Ilmiö": "Tekoäly työkaverina",
      "Mistä on kyse?": "Tekoäly työryhmässä tai prosessissa yhdenvertaisena työntekijänä. Ilmentyy esim. älykaiuttimena, applikaationa tai robottina."
    },
    {
      "Gen": false,
      "Lähde": "Yle Teknologian Ilmiökartta 2019/1",
      "Ilmiö": "Ihmismäinen tekoäly",
      "Mistä on kyse?": "Älykkäät ja ihmisen kanssa luonnollisella kielellä kommunikoivat koneet hoitavat ihmiselle vaativia tehtäviä ja monilla alueilla voittavat ihmisen. Tekoäly osaa hyödyntää vapaamuotoista informaatiota sekä oppii itse."
    },
    {
      "Gen": true,
      "Lähde": "Yle Teknologian Ilmiökartta 2019/1",
      "Ilmiö": "Älykäs liikkuminen",
      "Mistä on kyse?": "Liikennevälineet ovat älykkäitä, ja verkkoon ja toisiinsa kytkettyjä, ja tunnistavat käyttäjien ja tavaran liikkumistarpeet."
    },
    {
      "Gen": false,
      "Lähde": "Yle Teknologian Ilmiökartta 2019/1",
      "Ilmiö": "Yksilöllisyyden korostuminen",
      "Mistä on kyse?": "Käyttäjä päättää omista yksilöllisyyden tavoistaan. Yksityinen data on omassa hallussa, kulkee mukana ja on helposti hyödynnettävissä."
    },
    {
      "Gen": false,
      "Lähde": "Yle Teknologian Ilmiökartta 2019/1",
      "Ilmiö": "Pimeä puoli",
      "Mistä on kyse?": "Verkossa kaikki on käännettävissä pimeiden voimien hyödyksi. Kyberuhka on kaikkialla. E.g. haitanteko, tietojen vääristely, kiristys, varkaus, uskottavuuden murentaminen, valtiollinen vaikuttaminen. Tai odottamattomat ei-aiotut vaikutukset tai pelkkä vahinko, hupsis, kävikin näin."
    },
    {
      "Gen": false,
      "Lähde": "Yle Teknologian Ilmiökartta 2019/1",
      "Ilmiö": "Teknologian etiikka",
      "Mistä on kyse?": "Ihmiskunnan on tärkeää linjata mihin teknologian mahdollisuuksia on sallittua käyttää."
    },
    {
      "Gen": false,
      "Lähde": "Yle Teknologian Ilmiökartta 2019/1",
      "Ilmiö": "Digitalisaation kritiikki",
      "Mistä on kyse?": "Digitalisaatio etenee nopeammin kuin ihmisten muutoskyky ja -halukkuus sallii. Aiemmin digitalisaatio nähtiin positiivisena; kännykät, tekoäly, robotiikka. Onko tämä hyvä?"
    },
    {
      "Gen": true,
      "Lähde": "Yle Teknologian ilmiökartta 2019/11",
      "Ilmiö": "Ihminen ja kone yhdessä",
      "Mistä on kyse?": "Ihmisen ja koneen kohtaamisen näkökulma: \nKäyttöliittymien kirjo kasvaa, kun kuva-, ääni- ja painikepohjaisuudesta siirrytään kohti monimuotoisempia tapoja. Tulevaisuuden kone toimii luontevasti ja ihmistä ymmärtäen.\n\nKoneen status tulee nostaa lähemmäksi ihmistä, ja vaatia samoja kanssakäymisen ominaisuuksia kuin ihmisessäkin on.\nJotta yhteistoiminta olisi sujuvaa, ihmisenkin on opeteltava uusia tapoja toimia koneympäristöissä."
    },
    {
      "Gen": true,
      "Lähde": "Yle Teknologian ilmiökartta 2019/11",
      "Ilmiö": "Käyttöliittymätön käyttöliittymä",
      "Mistä on kyse?": "Ihminen liittyy saumattomasti digitaaliseen ympäristöön, teknologian häiritsemättä. Eleiden, puheen ja muiden aistien kautta. Kosketusnäytöistä siirrytään luonteviin käyttöliittymiin.\n\nKäyttöliittymän käyttö “alentumatta” kommunikoimaan koneen kanssa muuttaa ihmisten käyttäytymismalleja. Käyttöpinta seuraa käyttäjää paikasta toiseen. Huoneen kokoisia palveluita.\n\nNäkyy arjessa: 2022"
    },
    {
      "Gen": true,
      "Lähde": "Yle Teknologian ilmiökartta 2019/11",
      "Ilmiö": "Ihminen anturina",
      "Mistä on kyse?": "Käytetään ihmistä hyväksi asioiden mittarina. Sijainti, biometrinen data, mielentila, alitajuinen toiminta ja muut ihmisestä havainnoidut asiat toimivat tulkkina muille kiinnostuksen kohteille, esim. tuoksu, tunto, maku, mukavuus, ympäristön laatu ja käyttökelpoisuus, jne. \n\nKorvaa sellaista osiota, johon teknologia ei vielä kykene. Otettava huomioon, että kaikilla ihmisillä on omat mieltymykset ja erilainen sietokyky, jokainen sensori on uniikki.\n\nNäkyy arjessa: 2023"
    },
    {
      "Gen": true,
      "Lähde": "Yle Teknologian ilmiökartta 2019/11",
      "Ilmiö": "Lisätty todellisuus",
      "Mistä on kyse?": "Lisätyn todellisuuden avulla tuodaan käyttäjälle saumattomasti tosimaailmassa olevaan kohteeseen liittyviä aistimuksia ja kokemuksia. Todellinen ja lisätty ilmaantuvat yhtä aikaa.\n\nEnsimmäisiä kokeiluja tehty kapeille alueille, laajaa läpilyöntiä ei ole vielä tapahtunut. Kiinnostavin vaihe alkaa, kun päästään nykyisistä päätelaitteista seuraaviin versioihin. Uusi sisällön tekemisen tapa läpi ketjun tuotannosta käyttäjälle. Millaista on tarinankerronta kaikille aisteille?\n\nNäkyy arjessa: 2023"
    },
    {
      "Gen": true,
      "Lähde": "Yle Teknologian ilmiökartta 2019/11",
      "Ilmiö": "Toinen minä",
      "Mistä on kyse?": "Kehittynyt assistentti, joka tuntee käyttäjän ja osaa ennakoida tilanteita. Aina hereillä. Viestii käyttäjän kanssa inhimillisellä tavalla. Tekee asioita käyttäjän puolesta, pyynnöstä ja pyytämättä, luottamuksella.\n\nIhmiselle mahdollisuus olla offline, kun avustaja on aina online. Työminä ja yksityisminä voivat olla erillään. Tulevaisuudessa nämä assistentit ovat tie kuluttajien tietoisuuteen. Ne valikoivat ympäröivän maailman tarjontaa kuluttajan puolesta. Mitä on toisen minän lobbaaminen?\n\nNäkyy arjessa: 2024"
    },
    {
      "Gen": true,
      "Lähde": "Yle Teknologian ilmiökartta 2019/11",
      "Ilmiö": "Ajatusten tunnistaminen",
      "Mistä on kyse?": "Tunteita voi mitata, ympäristöä voi ohjata pelkillä ajatuksilla. Ajatukset ja tunnemaailma avautuvat aivosensoreilla, ilmeistä, äänestä, pulssista, ihon sähkönjohtavuudesta, tai välillisesti ihmisen tekemisistä.\n\nLaitteiden ohjaus toimii kuin ajatus, ilman fyysisesti käytettävää ohjainta. Ihmisen tunteita voi mitata suoraan tai epäsuorasti, ilman ihmisen omaa tietoista päätöstä kertoa tunteistaan. Onko opittava uusi taito, joka erottelee omat ajatukset ja syvät tuntemukset siitä, mitä haluaa kertoa ulos?\n\nNäkyy arjessa: 2026"
    },
    {
      "Gen": true,
      "Lähde": "Yle Teknologian ilmiökartta 2019/11",
      "Ilmiö": "Ihmisen parantelu",
      "Mistä on kyse?": "Ihmisten puutteiden korjaaminen ja jopa normaalien kykyjen ylittäminen. Apuvälineitä, jotka integroituvat ihmiseen, ovat aina mukana. Tehostetut aistit, etätunto, sokealle tekosilmät, joilla näkee, terveille siru niskaan, jolla voidaan tuottaa aistikokemuksia ohi aistien. \n\nIhmisten fyysisistä puutteista johtuvia toimintakyvyn alenemia voidaan paikata. Mediaa ihmisryhmille tavoilla, joilla se ei ole aiemmin ollut mahdollista. Voidaan hakea myös luonnolliset kyvyt ylittäviä kokemuksia.\n\nNäkyy arjessa: 2026"
    },
    {
      "Gen": true,
      "Lähde": "Yle Teknologian ilmiökartta 2019/11",
      "Ilmiö": "Empaattinen käyttöympäristö",
      "Mistä on kyse?": "Käyttöympäristöllä on sielu. Miellyttävä ja oppiva, se tuntee minut ja muovautuu sen mukaan mikä minulle on tärkeää. Ja jos ei tunne, se noudattaa hyviä tapoja. Parhaimmillaan, kun käyttöympäristöstä ei tiedosta, että se on kone. \n\nKommunikointi käyttöympäristön kanssa toimii luotettavasti ja ihmiselle luontevasti. Käyttökokemus toimii ihmisen, ei koneen ehdoilla. Väärinymmärrykset ja selittämisen tarve on minimoitu.\n\nNäkyy arjessa: 2026"
    },
    {
      "Gen": true,
      "Lähde": "Yle Teknologian ilmiökartta 2019/11",
      "Ilmiö": "Tekoälypandemia",
      "Mistä on kyse?": "Koneellisen älykkyyden näkökulma: Tekoäly tulee pieninä palasina mukaan kaikkiin prosesseihin. Pan ’kaikki’ ja demos ’ihmiset’.\n\nTekoäly oppii eri aihealueiden substanssia ja integroituu osaksi prosesseja, haastaen myös ihmisten osaamisen. Tekoäly mullistaa eri toiminta-alueiden tekemistä. Roolijakoa ihmisen, koneiden ja tekoälyn välillä määriteltävä jatkuvasti uudelleen. Tekoäly antaa ihmiselle ylennyksen."
    },
    {
      "Gen": true,
      "Lähde": "Yle Teknologian ilmiökartta 2019/11",
      "Ilmiö": "Maailman mallinnus",
      "Mistä on kyse?": "Kaikkialla tapahtuvan tiedonkeruun sivuvaikutuksena kertyy huomattava määrä maailmaa ja sen toimintaa mallintavaa tietoa. Data tulee hyödynnettäväksi myös johonkin ihan muuhun kuin alkuperäiseen käyttötarkoitukseen.\n\nReaalimaailmaa kuvaava datamatto, joka mahdollistaa synteettiset seikkailuympäristöt, aikamatkailun, Kiinan sosiaaliset pisteytykset, personoidut vakuutukset...\n\nNäkyy arjessa: 2020"
    },
    {
      "Gen": true,
      "Lähde": "Yle Teknologian ilmiökartta 2019/11",
      "Ilmiö": "Robotit",
      "Mistä on kyse?": "Robottien fyysiset kyvyt kehittyvät hyvin nopeasti. Kokokirjo on laaja, hyönteisistä valtamerialuksiin. Tekoälyn myötä niistä on tullut sujuvasti sekä itsenäisesti että laumassa toimivia. \n\nArkipäivän robotiikan osalta on nähty vasta alku. Hyvinkin arkinen ja tuttu väline, joka saa tekoälyn avukseen muuttuu aivan toiseksi. Autonominen auto on tekoäly, joka näyttää tavalliselta autolta. Kun tekoäly osaa myös kommunikoida, se voi toimia suuremman systeemin osana. Millaisia fyysisiä muotoja tekoäly vielä saakaan?\n\nNäkyy arjessa: 2021"
    },
    {
      "Gen": true,
      "Lähde": "Yle Teknologian ilmiökartta 2019/11",
      "Ilmiö": "Manipuloitu video",
      "Mistä on kyse?": "Deep fake: kasvonilmeet, puheen, henkilön identiteetin, ympäristön tai koko tilanteen voi vaihtaa livenä toiseksi. Siitä tulee ilmaista, helppoa, ja sitä voivat tehdä kaikki.\n\nManipulointia käytetään sekä hyötyyn, viihteeseen että vääriin käyttötarkoituksiin. Luotettavat sisällöt todetaan varmenteella. Manipulointia voi käyttää suunnitteluun, ajatusten visualisointiin ja kommunikointiin. Myös kuolleen voi tehdä eläväksi, esim. Einstein voisi pitää verkkokursseja.\n\nNäkyy arjessa: 2022"
    },
    {
      "Gen": true,
      "Lähde": "Yle Teknologian ilmiökartta 2019/11",
      "Ilmiö": "Tekoälyn tuottama sisältö",
      "Mistä on kyse?": "Automaattinen sisällön luonti, koostaminen, rikastus ja variointi suuresta määrästä lähtömateriaaleja. Itsenäisesti tai tilauksesta.\n\nHenkilökohtaisesti sovitettuja versioita tarinoista. Interaktiivisesti tuotettua, keskustelunomaista ja käyttötilanteeseen sovitettua sisältöä. Tekoälyn tuottama sisältö on uuden oppimisen väline, mentori, tieto- ja näsäviisas.\n\nNäkyy arjessa: 2022"
    },
    {
      "Gen": true,
      "Lähde": "Yle Teknologian ilmiökartta 2019/11",
      "Ilmiö": "Luonnollisen kielen ymmärtäminen",
      "Mistä on kyse?": "Kone ymmärtää sujuvasti suomenkielistä puhetta tai tekstiä, sekä lauseiden todellisia merkityksiä.\n\nIhmisen ja koneen välinen rajapinta toimii ihmisen ehdoilla luonnollisen kielen välityksellä. Kone pystyy ymmärtämään kaiken puhutun ja kirjoitetun. Puhekieltä voi käyttää vaivatta erilaisissa palveluissa ilman pelkoa väärinkäsityksistä. Äänikäyttöliittymät, reaaliaikainen kielenkäännös, selkokielitulkkaus, laadukas automaattinen tekstitys, poliitikoiden aiempien puheiden nopea skannaus.\n\nNäkyy arjessa: 2023"
    },
    {
      "Gen": true,
      "Lähde": "Yle Teknologian ilmiökartta 2019/11",
      "Ilmiö": "Tekoäly työkaverina",
      "Mistä on kyse?": "Tekoäly työryhmässä tai prosessissa yhdenvertaisena työntekijänä. Ilmentyy esim. älykaiuttimena, applikaationa tai robottina.\n\n Tekoäly on oman alueensa huippuasiantuntija tai avustaja, auttaa aina tarvittaessa. Tunnistaa mitä tietoa tai taitoa tilanteessa tarvitaan ja tuo sen pöytään heti. Pohdittavaksi: koska tekoäly ei ole ihminen, millaisia virheitä annat sille anteeksi? Kuka kantaa juridisen vastuun?\n\nNäkyy arjessa: 2023"
    },
    {
      "Gen": true,
      "Lähde": "Yle Teknologian ilmiökartta 2019/11",
      "Ilmiö": "Ihmismäinen tekoäly",
      "Mistä on kyse?": "Älykkäät ja ihmisen kanssa luonnollisella kielellä kommunikoivat koneet voittavat monilla alueilla ihmisen. Tekoäly osaa hyödyntää vapaamuotoista informaatiota. Tekoälyt vaihtavat keskenään kokemuksia, ja siten oppivat lisää.\n\nIhmisille mahdollisuus hyödyntää ääretöntä määrää tietoa ja tehdä asioita ilman ihmisen rajoitteita. Kun ihmisen ja tekoälyn välinen luottamus on vahva, pysyy kehityskulku nopeana. Onko tekoäly yksilö ja myös vastuussa tekemisistään? Tekoälylle pitää opettaa etiikkaa, mutta kenen?\n\nNäkyy arjessa: 2030+"
    },
    {
      "Gen": true,
      "Lähde": "Yle Teknologian ilmiökartta 2019/11",
      "Ilmiö": "Teknologian etiikka",
      "Mistä on kyse?": "Ihmisen ja inhimillisyyden näkökulma: Autonominen teknologia osaa optimoida asioita saarekkeensa sisällä, mutta ei osaa katsoa sen ulkopuolelle. Se ei tunne katumusta. Siksi meidän on kysyttävä itseltämme, miten kehitämme teknologiaa.\n\nMikä on hyvää teknologian käyttöä, mikä on huonoa? Miten algoritmit toimivat? Kuinka syvälle ihmiseen voidaan teknologian avulla puuttua? Tuleeko tekoälyillekin määrätä lepoaikaa, jotta ne eivät olisi ylivoimaisia?"
    },
    {
      "Gen": true,
      "Lähde": "Yle Teknologian ilmiökartta 2019/11",
      "Ilmiö": "Poliittinen voima",
      "Mistä on kyse?": "Poliittinen ja tekninen kehitys ovat yhä enemmän nivoutuneet sekä konfliktissa. Reguloimattomilla alueilla on tilaa kehittää vapaasti, mutta, jos kehitys koetaan uhkaksi, sääntely voi iskeä yllättävänkin suurella voimalla ja nopeudella.\n\nPoliittisen vaikuttamisen motiiveja on monenlaisia ja ne voivat olla ennakoimattomia. Esteiden poistamisella, hankkeiden tukemisella, ja toisaalta säännöksillä, sakotuksella, lobbauksella, propagandalla ja jopa korruptiolla pyritään vaikuttamaan eri teknologioiden kehittymiseen."
    },
    {
      "Gen": true,
      "Lähde": "Yle Teknologian ilmiökartta 2019/11",
      "Ilmiö": "Kenen data?",
      "Mistä on kyse?": "Kuka omistaa sinut? Missä sijaitsee sinun digitaalinen kaksosesi (data-duplikaatti)? Koko elämän mittaisen datan eheys mahdollistaa koko ihmisen elinkaaren kertomisen. Mitä olet tehnyt, missä olet ollut, keitä olet tavannut, mitä olet tuntenut?\n\nKoko elämän mittaisen datan hallinta tulee ihmisyyden perustaidoksi. Ihmisyyteen kuuluu myös kyky unohtaa asioita ja muistaa asioita väärin. Tietoja voi tulkita tunteeton kone tai ihminen, ilman inhimillisyyttä. Yksilön datan käyttö vaatii molemminpuolista luottamusta."
    },
    {
      "Gen": true,
      "Lähde": "Yle Teknologian ilmiökartta 2019/11",
      "Ilmiö": "Digitalisaation kritiikki",
      "Mistä on kyse?": "Digitalisaatio etenee nopeammin kuin ihmisten muutoskyky ja -halukkuus sallii. Kritiikki nostaa asioita keskusteluun.\n\nTaloudelliset tavoitteet ja kapeakatseiset voitot/edut ajavat pitkän ajan kuluessa tulevien riskien/haittojen edelle. Liian nopeasti kehittyvät palvelut aiheuttavat syrjintää, koska kaikki eivät kykene mukaan. Osa ihmisistä haluaa olla enemmän offline, osa luonnollisempaa ja luontoa säästävää ympäristöä, ja sen takia ottaa etäisyyttä teknologiasta."
    },
    {
      "Gen": true,
      "Lähde": "Yle Teknologian ilmiökartta 2019/11",
      "Ilmiö": "Pimeä puoli",
      "Mistä on kyse?": "Haitanteko, tietojen vääristely, uskottavuuden murentaminen, valtiollinen vaikuttaminen ja korruptio näkyvät ihmisten elämässä entistä enemmän. Tekoälykin voi kehittää ihmiseltä salassa asioita, jotka ovat jopa tuhoisia. Tai käy pelkkä vahinko, hupsis, kävikin näin.\n\nKuka nykyisessä moniarvoisessa maailmassa määrittää, mikä on pimeää puolta? Osaa asioista ei voi selkeästi määrittää kummallekaan puolelle. Entä jos toisinajattelijoiden ainoana yhteytenä \"vapaaseen maailmaan\" on pimeä puoli, niin pitäisikö Ylenkin olla siellä?"
    },
    {
      "Gen": true,
      "Lähde": "Yle Toimintaympäristöhavainnot kevät 2019",
      "Ilmiö": "Omistaja voi haluta pienentää Yleä tai muuttaa sen roolia",
      "Mistä on kyse?": "Ylen rooli, tehtävät ja niiden laajuus voivat muuttua. Omistaja – tässä tapauksessa eduskunta – voi tehdä asiasta päätöksiä nopeastikin. Ylen ja omistajan suhde voi olla herkkä. Ja herkkyys voi vaihdella. Tanskan esimerkki, jossa DR:n budjettia leikattiin 20 %:lla, osoittaa, että hyväkään yleisösuhde ei ole tae siitä, että muutoksia ei tule."
    },
    {
      "Gen": true,
      "Lähde": "Yle Toimintaympäristöhavainnot kevät 2019",
      "Ilmiö": "Musta joutsen",
      "Mistä on kyse?": "Erittäin epätodennäköinen tapahtuma, jolla on isot vaikutukset. Ei ole ennustettavissa – vaikka monesti jälkeenpäin kehitellään loogisia selityksiä, että tietenkin näin piti tapahtua. Nämä ovat yleensä negatiivisia. Positiivisiakin on.\n\nEsimerkkejä, joita pidetään mustina joutsenina: Internetin suosion ja merkityksen kasvu, uskontojen nousut, PC, ensimmäinen maailmansota, Neuvostoliiton kaatuminen, kaksoistornien terrori-iskut 11.9.2001, Googlen hämmästyttävä menestys, sub-prime -velkakriisi jenkeissä -00-vuosikymmenen lopussa. Mustilla joutsenilla tarkoitetaan yleensä laajasti vaikuttavia asioita, mutta jokainen voi myös miettiä esimerkkejä omasta elämästään."
    },
    {
      "Gen": true,
      "Lähde": "Yle Toimintaympäristöhavainnot kevät 2019",
      "Ilmiö": "Tietoisuus maapallon kantokyvystä näkyy kaikkialla, mm. elämäntapa- ja kulutuspäätöksissä",
      "Mistä on kyse?": "Kestävän kuluttamisen paine kasvaa. On yhä laajempi yksimielisyys siitä, että nykyinen elämänmeno Suomessa ja maailmalla ei ole enää kestävällä pohjalla. Maapallon resursseja käytetään nopeammin kuin ne uusiutuvat. Nykymeno vaikuttaa yhä voimakkaammin ilmastoon ja sen lämpenemiseen, joka voi muuttaa maailman ympäristön tilaa vaarallisella tavalla, mahdollisesti katastrofaalisin seurauksin."
    },
    {
      "Gen": true,
      "Lähde": "Yle Toimintaympäristöhavainnot kevät 2019",
      "Ilmiö": "Diversiteetti - erilaisten äänten kirjo kuuluviin",
      "Mistä on kyse?": "Monimuotoisuuden ja moniäänisyyden tarve korostuvat kaikkialla yhteiskunnassa. Suomi ei ole enää pitkään aikaan ollut yhtenäiskulttuuri. Nyt viimeistään pitää ymmärtää erilaisia tapoja elää, eikä katsoa maailmaa minkään yksittäisen ryhmän kuvakulmasta."
    },
    {
      "Gen": true,
      "Lähde": "Yle Toimintaympäristöhavainnot kevät 2019",
      "Ilmiö": "Z-sukupolvi muuttaa asiat ja uskoo tulevaisuuteen",
      "Mistä on kyse?": "Z-sukupolvella tarkoitetaan yleensä n. 1995–2010 syntyneitä. Ensimmäisiä digitaaliseen maailmaan syntyneitä, joille netti ja sosiaalinen media ovat itsestäänselvyyksiä. Heille suuria kysymyksiä ovat ilmastonmuutos, koulutus, tulevaisuuden työelämä ja epäluulo nykyisen järjestelmän kykyyn ratkaista asioita. Merkityksellisyys, vaatimus läpinäkyvyydestä ja kriittisyys korostuvat. Kulutuksessa Z-nuoret eivät välitä omistamisesta vanhempien sukupolvien lailla. Riittää, kun voi käyttää (Spotify, jakamistalous laajemmin). Kulutuksella ilmaistaan omaa identiteettiä. Kulutus on tälle sukupolvelle eettinen kysymys ja huoli. Z-miehet ovat uusia suomenruotsalaisia: hekin suhtautuivat tulevaisuuteen selvästi muita positiivisemmin."
    },
    {
      "Gen": true,
      "Lähde": "Yle Toimintaympäristöhavainnot kevät 2019",
      "Ilmiö": "Maaseutu tyhjenee, kasvu keskittyy muutamaan kaupunkiin",
      "Mistä on kyse?": "Kaupunkien imu vetää väkeä maaseudulta kiihtyvää vauhtia pääkaupunkiseudulle ja muutamiin kasvukeskuksiin. Syrjäseutujen autioituminen kiihtyy, haja-asutusalueiden väkimäärä vähenee ja ikääntyy, alueelliset erot kasvavat. Työpaikat karkaavat tai syntyvät kasvukeskuksiin. Urbaanit yhteisöt luovat kasvupohjaa kokeiluille, innovaatioille ja uusille palveluille - toisaalta myös samassa kaupungissa voi olla kukoistavia ja kurjistuvia alueita. Suomi on iso maa – kaikki kehityskulut eivät näy pääkaupunkiseudun ja menestyvien kaupunkiseutujen näkökulmasta."
    },
    {
      "Gen": true,
      "Lähde": "Yle Toimintaympäristöhavainnot kevät 2019",
      "Ilmiö": "Maailma muuttuu koko ajan paremmaksi, mutta joillakin menee tosi huonosti",
      "Mistä on kyse?": "Historiallisesti suomalaisilla (ja maailmassa) menee paremmin kuin koskaan, elinikä pitenee ja elintaso nousee. Samaan aikaan on ihmisiä, joiden mahdollisuudet turvalliseen ja hyvään elämään ovat entistä heikommat. Näissä ryhmissä vähävaraisuus ja elämänhallinnan ongelmat ruokkivat toisiaan."
    },
    {
      "Gen": true,
      "Lähde": "Yle Toimintaympäristöhavainnot kevät 2019",
      "Ilmiö": "Median ja politiikan instituutiot helisemässä",
      "Mistä on kyse?": "Perinteiset poliittiset instituutiot ja media joutuvat miettimään toimintatapojaan uusiksi, kun maailma muuttuu nopeasti. Politiikkaa ja mediaa muuttavat mm. uuden teknologian läpimurto, työelämän muutokset, vaikuttamisen uudet muodot, kansainvälinen epävakaus ja että talouskasvun kestävyyttä epäilee yhä useampi. Kaikissa näissä piilee sekä mahdollisuuksia että uhkia, joita ei pysty vielä millään näkemään."
    },
    {
      "Gen": true,
      "Lähde": "Yle Toimintaympäristöhavainnot kevät 2019",
      "Ilmiö": "Identiteettipolitiikka ja populismi nousevat",
      "Mistä on kyse?": "Identiteettipolitiikka nostaa päätään ja on populismin käyttövoima. Asioiden sijaan politiikan agendalle nousee tunteisiin vetoavia persoonia, vastakkainasettelua ruokkivia näkemyksiä ja mielipiteitä. “Henkilökohtainen on poliittista” -slogan tulee taas. Identiteettipolitiikka nojaa esimerkiksi uskontoon, kansallisuuteen, seksuaalisuutta koskeviin kysymyksiin, yhteiskunnalliseen asemaan, taustaan jne. Mielipiteet ja omat näkemykset jylläävät faktojen kustannuksella, viholliskuvia rakennellaan oman aseman pönkittämiseksi, uhriksi on tungosta. Populismi kanavoi yhteiskunnallista tyytymättömyyttä. Some tarjoaa kaikupohjaa kärjistäville mielipiteille omissa heimoissa."
    },
    {
      "Gen": true,
      "Lähde": "Yle Toimintaympäristöhavainnot kevät 2019",
      "Ilmiö": "Valeuutiset ja disinformaatio – mikä on totta?",
      "Mistä on kyse?": "Tarkoituksellisen harhaanjohtavan tiedon ja valeuutisten avulla pyritään vaikuttamaan yleiseen mielepiteeseen, myös vaaleihin. Taustalla voi olla poliittisia, taloudellisia tai muita intressejä. Tekoälyn aikakaudella kuvan ja äänen väärentäminen käy entistä helpommaksi."
    },
    {
      "Gen": true,
      "Lähde": "Yle Toimintaympäristöhavainnot kevät 2019",
      "Ilmiö": "Näennäisen pienet asiat paisuvat tolkuttoman isoiksi (some)",
      "Mistä on kyse?": "Nopeatempoinen somekeskustelu ja median kilpailu nostavat julkiseen keskusteluun teemoja, joilta puuttuvat konteksti ja mittasuhteet. Nopeita tunnereaktoita nostattavat yksittäiset teemat leviävät salamannopeasti, tai media tarttuu itse kuumaan aiheeseen, joka vääristää tai antaa puutteellisen kuvan monimutkaisista ilmiöistä. Negatiiviset ilmiöt/uutiset korostuvat. Tässä myös mielipidevaikuttajilla tai disinformaatiolla on sauma iskeä. Monimutkaisten syy-seuraussuhteiden käsittely vaatii aikaa ja paneutumista, joilta kohut ja laiska pikajournalismi syövät ilmatilaa."
    },
    {
      "Gen": true,
      "Lähde": "Yle Toimintaympäristöhavainnot kevät 2019",
      "Ilmiö": "Yksittäisillä (uus)mediapersoonilla on jatkuvasti enemmän vaikutusvaltaa",
      "Mistä on kyse?": "Tehokas vuorovaikutus asiakkaiden ja kohderyhmien kanssa tapahtuu entistä henkilökohtaisemmalla tasolla. Ns. mikrovaikuttajat eivät tarvitse tuekseen perinteisiä mediabrändejä – he pystyvät rakentamaan vahvan, tiiviin ja henkilökohtaisen yhteyden seuraajiinsa. Myös yritykset pyrkivät hyödyntämään eri tason vaikuttajia."
    },
    {
      "Gen": true,
      "Lähde": "Yle Toimintaympäristöhavainnot kevät 2019",
      "Ilmiö": "Teknologiajättien imperiumit jyräävät",
      "Mistä on kyse?": "Kansainvälisten teknologiajättien rynnistys Pohjois-Amerikasta ja Kiinasta jatkuu (Amazon, Google, Facebook, Tencent, Baidu, Alibaba, Microsoft, IBM ja Apple). Ne pyrkivät levittäytymään mahdollisimman laajalle ja rakentamaan täysin omia ekosysteemejä pitääkseen asiakkaat koko ajan itsellään – ja pyrkivät jopa kuuhun."
    },
    {
      "Gen": true,
      "Lähde": "Yle Toimintaympäristöhavainnot kevät 2019",
      "Ilmiö": "Digitaalinen laatuaika korostuu",
      "Mistä on kyse?": "hmiset ovat aiempaa tietoisempia ns. digitaalisesta ruokavaliostaan ja tarkkailevat aktiivisemmin ruutuaikaansa. Miten olla digimaailmassa terveemmin ja järkevämmin? Isojen toimijoiden psykologiset kikat käyttäjien koukuttamiseen ja digi-riippuvuuden rakentamiseen herättävät pahennusta. Äärimmäinen vastareaktio ruutuajalle on digipaasto (digital detox), jolloin ei käytetä älypuhelinta, tablettia tai tietokonetta. Mutta ei ruutuaika ole aina pahaa. Kyse on pitkälti käyttömotiivista: mitä olisi vaihtoehtoinen tekeminen? Esimerkiksi digitaalinen elämä mahdollisuutena: Vasta kun 25-vuotias Mats Steen kuoli, vanhemmat ymmärsivät, että tällä oli ystäviä – \"Pelimaailmassa tyttö ei näe pyörätuoliani vaan sieluni\"."
    },
    {
      "Gen": true,
      "Lähde": "Yle Toimintaympäristöhavainnot kevät 2019",
      "Ilmiö": "Yksityisyys meni jo",
      "Mistä on kyse?": "Digitaalisessa maailmassa ei voi piiloutua. Ihmisestä jää jälkeen dataa jo siitä, kun on olemassa. Tällä tiedolla suunnitellaan, rakennetaan, ymmärretään ja ennen kaikkea sillä tienataan rahaa. Data määrittelee usein sen mitä ja miten asiakasta verkossa palvellaan. Onkin siis lähes mahdotonta tietää missä kohtaa päätöksiä tehdään puolestasi perustuen dataan, jota sinusta on aiemmin kerätty."
    },
    {
      "Gen": true,
      "Lähde": "Yle Toimintaympäristöhavainnot kevät 2019",
      "Ilmiö": "Teknologia-Kiina tavoittelee lisää valtaa",
      "Mistä on kyse?": "Kiinassa tuotetaan valtava määrä kilpailukykyisiä palvelu-, tekoäly- ja teknologiaratkaisuja. Huimat taloudelliset resurssit mahdollistavat nopean kehitystyön. Yhtiöt pelaavat myös eri säännöillä kuin länsimaiset toimijat: niitä eivät aina rajoita lännestä tutut lait tai etiikka. Merkittävät pelurit: Baidu, Alibaba, Tencent ja Bytedance (mm. TikTok)."
    },
    {
      "Gen": true,
      "Lähde": "Yle Toimintaympäristöhavainnot kevät 2019",
      "Ilmiö": "Mediabisneksen perinteiset rajat ryskyvät Suomessa",
      "Mistä on kyse?": "Perinteiset yhden alueen mediayhtiöt laajentavat toimintaansa mm. musiikki-, viihde- ja tapahtumabisnekseen ja toimivat monien eri nimien alla. Tämä on yritystä etsiä uusia tulovirtoja, kun kansainvälinen kilpailu kovenee. Myös uusilta aloilta tulee toimijoita suomalaiseen mediabisnekseen tekemään sisältöjä ja kilpailemaan esitysoikeuksista. “Kotimaiset toimijat” ovat harvemmin enää kansallisia, vaan osa kansainvälisiä yrityskokonaisuuksia."
    },
    {
      "Gen": true,
      "Lähde": "Yle Toimintaympäristöhavainnot kevät 2019",
      "Ilmiö": "Broadcastin äkkikuolema",
      "Mistä on kyse?": "Mediankulutus muuttuu edelleen radikaalisti kaikissa ikäluokissa. Jos tämä ei heti näy, kannattaa katsoa pidempiä aikasarjoja. Valmiiksi paketoidun antenni- tai kaapeliverkossa jaettavan tv- tai radiokanavan tulevaisuusnäkymät ovat laskusuuntaiset – etenkin kun niitä ylläpitävät suuret ikäluokat ns. poistuvat yleisöistä.\n\nOn 1) sisältöjä, joita halutaan katsella ja kuunnella silloin, kun itselle sopii parhaiten (VOD) ja sitten on 2) live-sisältöjä, joita halutaan seurata ja kokea samaan aikaan muiden kanssa (yhteenkuuluvuuden tunne, olla osana jotain suurempaa), kuten vaalien tulosseuranta, urheilutapahtumat, Euroviisut, Notre Damen palo, se mikä tapahtuu juuri nyt."
    },
    {
      "Gen": true,
      "Lähde": "Yle Toimintaympäristöhavainnot kevät 2019",
      "Ilmiö": "Empatia - syvempi ymmärrys ihmisistä korostuu",
      "Mistä on kyse?": "Kykyä ymmärtää mitä toinen kokee ja kykyä asettua hänen asemaansa, asiakasymmärryksen näkökulmasta syvempää ymmärrystä ihmisistä ja liiketoiminnan kannalta empatian hyödyntämistä yrityskuvan luomisessa."
    },
    {
      "Gen": true,
      "Lähde": "Yle Toimintaympäristöhavainnot kevät 2019",
      "Ilmiö": "Maailmankuvaa näytetään avoimesti teoissa ja kulutuksessa",
      "Mistä on kyse?": "Yritykset tekevät yhä enemmän ja näkyvämmin arvopohjaisia valintoja ja toimivat missiovetoisesti. Nämä arviot tai missiot saattavat liittyä esimerkiksi ihmisoikeuksiin tai ympäristöasioihin. Tällainen vaatii läpinäkyvyyttä ja johdonmukaisuutta – epäuskottavat tapaukset leimataan helposti viherpesuksi tai kaksinaamaiseksi toiminnaksi."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Taitojen merkitys kasvaa",
      "Mistä on kyse?": "Taidot haastavat tiedot, kun internet mahdollistaa valtavien tietomäärien saamisen käyttöön helposti ja tekoäly auttaa tiedon hallinnassa. Samalla kriittinen ajattelu ja kyky hahmottaa kokonaisuuksia korostuu. Koulutuksessa kasvaa tarve hahmottaa verkottunutta ja datan lävistämää aikaa, sekä syventää luovuutta ja vuorovaikutustaitoja."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Verkon joukkovoima lisääntyy",
      "Mistä on kyse?": "Teknologian luoma yhteisöllisyys ja kyky toimia suoraan muiden kanssa mahdollistaa ihmisten osallistumisen ja toimijuuden yhteiskunnassa ennennäkemättömällä tavalla. Jakamistalous, joukkoistus ja joukkorahoitus luovat tilaa uusille organisoitumisen ja innovaatioiden muodoille. Toisaalta länsimaiset yhteiskunnat ovat perustuneet instituutioiden ja oikeusvaltion periaatteisiin ja instituutioiden ohittaminen ja “oikeuden” jakaminen verkossa joukkovoimalla luovat yhteiskuntaan epävakauttavia voimia ja pelkoa."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Eliniät pitenevät ja väestö vanhenee",
      "Mistä on kyse?": "Ihmiset elävät pidempään ja väestörakenne vanhenee. Läntisissä yhteiskunnissa nuorista tulee vähemmistö. Nuoret eivät voi yksin olla vastuussa uusien toimintatapojen, teknologioiden ja kestävyyden omaksumisesta toimintaansa. Toisaalta ihmisen toimintakyky voi tulevaisuudessa olla ikää määrittävämpi tekijä."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Kaupungistuminen jatkuu",
      "Mistä on kyse?": "Muutto maalta kaupunkeihin jatkuu globaalisti. Vuonna 2050 lähes 70 prosenttia maailman ihmisistä asuu kaupungeissa. Se, millaisia Aasiaan ja Afrikkaan tällä hetkellä syntyvät megakaupungit ovat, määrittää myös globaalia tulevaisuutta. Ovatko nämä kaupungit jättimäisiä miljoonien ihmisten slummeja vai infrastruktuuriltaan, hallinnoltaan ja toiminnaltaan kestäviä on tärkeä kysymys."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Radikaali avoimuus ja verkkovalvonta lisääntyy",
      "Mistä on kyse?": "Radikaali avoimuus lisääntyy edelleen internetin myötä. Hallitusten, yritysten ja yksilöiden tekemiset ovat yhä avoimemmin kaikkien saatavilla. Parhaassa tapauksessa tämä johtaa parempiin, kestävämpiin toimintatapoihin. Verkkovalvonnan ja yksilön oikeuksien määrittäminen tulee olemaan yksi lähitulevaisuuden suurista poliittista kysymyksistä."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Pakolaisuus ja muuttoliikkeet kasvavat",
      "Mistä on kyse?": "Pakolaisuus lisääntyy ja ihmisten massaliikkuminen yleistyy konfliktien ja ilmastonmuutoksen johdosta. Konflikti- ja kuivuusalueilta lähteneiden ihmisten olot ovat yhä vaikeammat ja kansainvälinen turvapaikkajärjestelmä natisee liitoksissaan."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Globalisaatio vs. nationalismi",
      "Mistä on kyse?": "Globalisaatio voimistuu ja maailma on yhä keskinäisriippuvaisempi, kun ihmisestä tulee koko ajan suurempi laji sille yhä pienemmäksi käyvällä maapallolla. Tämän kehityksen vastatrendiksi on noussut kasvava nationalismi ja sisäänpäin kääntyminen. Globaaleille ratkaisuille on yhä kasvavampi tarve. Samalla on pohdittava miten ihmiset voivat aidosti vaikuttaa demokratian kautta omaan elinympäristöönsä."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Paikallisuus vahvistuu",
      "Mistä on kyse?": "Paikallisuus vahvistuu uusien teknologioiden myötä. Internetin sovellutukset mahdollistavat myös fyysisen yhteisöllisyyden voimistamista. Esimerkiksi 3D-printtaus ja ruoka- ja viljelyteknologian kehittyminen voivat tulevaisuudessa luoda maaseudulle täysin uudenlaista elinvoimaa."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Terveys ja hyvinvointi korostuvat",
      "Mistä on kyse?": "Ihmisillä on käytössään yhä parempia tapoja hoitaa ja edistää omaa terveyttään sovellutusten, datan ja geeniteknologian kehittymisen myötä. Samalla terveys ja hyvinvointi voivat olla yhä voimakkaammin väestön eri osia erottava ja jakava tekijä. Hyvinvoinnin piiriin kuuluvat myös kokemus osallisuudesta, merkityksellisyydestä sekä omien mahdollisuuksien ymmärtämisestä."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Ymmärrys maapallon kantokyvystä kasvaa",
      "Mistä on kyse?": "Maapallo on ensimmäistä kertaa ihmisen historiassa muuttumassa pieneksi planeetaksi suurelle ihmislajille sekä ekologisesti että tilallisesti. Ajatus ja ymmärrys yhdestä yhteisestä maapallosta voimistuvat."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Sosiaalisen pääoman korostuminen",
      "Mistä on kyse?": "Sosiaalinen pääoma korostuu hyvinvoinnin ja myös työelämän näkökulmasta. Sosiaalinen pääoma tarkoittaa sosiaalisia verkostoja ja niissä syntyvää luottamusta ja vastavuoroisuutta. Sosiaalisen pääoman muodostavat osallistuminen ryhmien toimintaan, vapaaehtoistyö, verkostot, niistä saatu tuki, luottamus ja osallistuminen kansalaistoimintaan. Verkostoja ovat myös toisten auttaminen ja kanssakäynti ystävien ja tuttujen kanssa."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Uudenlaiset perhe- ja asumismuodot",
      "Mistä on kyse?": "Uudenlaiset perhe- ja asumismuodot yleistyvät voimakkaammin. Perheet valitsevat täysin uudenlaisia tapoja järjestää elämänsä ja esimerkiksi yhteisöllinen rakentaminen on kasvava trendi. Sateenkaariperheiden, ystävien perustamien perheiden tai esimerkiksi ylisukupolvisten asumismuotojen yleisyys kasvaa."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Tyttöjen ja naisten aseman vahvistuminen",
      "Mistä on kyse?": "Nouseva tyttöjen ja naisten aseman paraneminen on edelleen voimistuva trendi globaalisti. Puhutaan jopa naistaloudesta, jossa yhä enemmän naisille suunnattu kulutus ja trendit voimistuvat. Samalla sosiaalisen median myötä tasa-arvoisimmissa yhteiskunnissa on purskahtanut pintaan uudenlaista vihapuhetta sekä naisten ja tyttöjen asemaan liittyvää vihamielisyyttä."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Luovuus synnyttää työtä ja hyvinvointia",
      "Mistä on kyse?": "Työn digitalisoituessa yhä useampi työpaikka syntyy luovalle alalle, jota koneet eivät voi korvata. Taide, elämykset, aistit ja tunteet ovat alueita, joiden tiimoilta yhä useammat ihmiset etsivät merkityksellisyyttä."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Maailmankansalaisuus yleistyy",
      "Mistä on kyse?": "Osa ihmisistä kokee kuuluvansa enemmän osaksi globaalia yhteisöä kuin mitään tiettyä valtiota. Maailmankansalaiset liikkuvat sujuvasti työn ja mahdollisuuksien perässä maasta toiseen. Usein heitä vetävät puoleensa maailman metropolit, joissa luodaan globaalia rajat ylittävää kaupunkikulttuuria."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Teknologia jakaa väestöä",
      "Mistä on kyse?": "Teknologian nopean kehittymisen ja ihmisten elinikien pitenemisen myötä yhteiskunnassa on yhä enemmän toisistaan erillään olevia teknologisia todellisuuksia. Eri ikäryhmät käyttävät teknologiaa hyvin toisistaan poikkeavilla tavoilla. Yhtä ratkaisua kaikille ei enää ole."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Riittävä on tarpeeksi",
      "Mistä on kyse?": "Materiaalisen hyvinvoinnin lakipisteen saavuttaminen hyvinvoivissa väestöryhmissä synnyttää ”nyt riittää” -ajatteluksi kutsutun trendin. Hyvinvointi ei lisäänny enää hankkimalla materiaa vaan nimenomaan rajaamalla sitä. Hyvä elämä arvona korostuu."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Kokeilukulttuuri voimistuu",
      "Mistä on kyse?": "Yhä useampia tuotteita, palveluja ja toimintatapoja kehitetään ketterästi ja kokeillen. Suuntaa voi muuttaa nopeasti tarvittaessa ja keskeneräisyys ei enää ole pelkästään pahe."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Merkityksellisyys liiketoiminnassa ja johtamisessa korostuu",
      "Mistä on kyse?": "Ihmiset haluavat sekä kuluttajina että työntekijöinä sitoutua johonkin suurempaan tarkoitukseen kuin pelkästään voitontavoitteluun."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Eriarvoisuus lisääntyy",
      "Mistä on kyse?": "Useat maat ovat vauraampia kuin koskaan, mutta länsimaissa kamppaillaan kasvavien tulo- ja hyvinvointierojen kanssa. Työn murros ja globalisaatio ovat jakaneet ihmisiä voittajiin ja häviäjiin voimakkaammin. Mikäli erot kasvavat sietämättömiksi, yhteiskuntarauha voi heikentyä. Esimerkiksi perustulo on siksi tällä hetkellä monia tahoja kiinnostava ajatus."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Terveydestä ja eliniän pidentämisestä tulee merkittävää liiketoimintaa",
      "Mistä on kyse?": "Ihmisen elinikää pyritään pidentämään geeniterapian, uudenlaisten lääkkeiden, ravinnon ja muun terveysteknologian avulla. Yhä useampi elää yhä pidempään ja he, joilla on varaa, kuluttavat terveyteen. Eriarvoisuus näkyy terveydessä ja eliniässä."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Hyperkonnektiivisuus syvenee",
      "Mistä on kyse?": "Verkkopohjaisten palveluiden käyttö lisääntyy ja laajenee ja hyperkonnektiivisuus eli kaiken jatkuva yhteys kaikkeen syvenee entisestään. Kaikki toiminnot liitetään tavalla tai toisella verkkoon ja niin tavarat, palvelut kuin ihmisetkin ovat toisiinsa yhteydessä ensin asioiden internetin ja myöhemmin kaikkialla läsnä olevan verkon kautta. On kiinnostavaa nähdä, syntyykö kehitykselle voimakasta vastatrendiä, jossa ihmiset sanoutuvat irti verkosta tai olisiko irrottautuminen edes mahdollista."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Vertais- ja jakamistalous yleistyvät",
      "Mistä on kyse?": "Yhteistuotanto, yhteiskulutus sekä vertais- ja jakamistalous yleistyvät toimintamalleina. Teknologia mahdollistaa yhä erilaisempien asioiden tuottamisen, kuluttamisen ja jakamisen helposti. Olipa kyse ruuasta, kyydeistä, työkaluista, asunnoista, harrastuksista tai urheiluvälineistä, yhä useammalla alalla nähdään murroksia ja uusia toimintatapoja."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Fiksut tavarat ja palvelut yleistyvät",
      "Mistä on kyse?": "Ekologisuus yhdistettynä teknologiaan synnyttää yhä fiksumpia ja laadultaan ja kiinnostavuudeltaan kilpailukykyisiä tavaroita ja palveluja suoraan kuluttajille. Käyttämisen vaivattomuus ja käyttäjän näkökulma korostuvat."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Kestävyyskriisi kärjistyy entisestään",
      "Mistä on kyse?": "Kestävyyskriisi on akuutti ja se liittyy sekä luonnonresurssien niukkenemiseen että ilmastonmuutokseen. Aikamme suurin haaste on löytää ratkaisu luonnonresurssien käytön ja päästöjen irtikytkennälle talouskasvusta ja koetusta hyvinvoinnista. Monta mahdollisuutta tähän löytyy jo teknologiasta. Kaikkein haastavinta on muuttaa ihmisten käyttäytymistä ja mielen malleja."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Datan arvo kasvaa",
      "Mistä on kyse?": "Pääsy dataan sekä kyky hyödyntää ja yhdistellä sitä luovasti ovat valttikortteja uusien liiketoimintamallien ja tehokkaan hallinnon kehittämisessä. Dataan liittyvät oikeudelliset, inhimilliset ja eettiset kysymykset tulevat olemaan lähitulevaisuuden kuumalla poliittisella listalla."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Työn rakenteet muuttuvat",
      "Mistä on kyse?": "Alustatalous ja uudet organisaatiomallit haastavat perinteistä työnantaja-työntekijä suhdetta. Työtä voidaan organisoida ja sen hyötyjä voidaan jakaa monin tavoin. Perinteinen jaottelu työttömiin, palkansaajiin ja yrittäjiin ei välttämättä tulevaisuudessa päde, kun eläkeläisfreelancereiden, projektinomadien ja erilaisissa välitiloissa olevien määrä kasvaa."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Tekoälyn käyttö laajenee",
      "Mistä on kyse?": "Tekoälyä eli oppivia algoritmeja käytetään yhä useammissa tehtävissä. Tekoäly auttaa ihmisiä tulkitsemaan suuria tietomääriä ja toimimaan yhdessä, mahdollistaen uudenlaisen joukkoälykkyyden hyödyntämisen. Parhaassa tapauksessa tekoälyn avulla voidaan ratkoa ihmiskunnan pahimpia haasteita. Samalla tekoälyn kehitykseen liittyy runsaasti eettisiä kysymyksiä liittyen esimerkiksi algoritmien läpinäkyvyyteen, päätösten vastuullisuuteen ja käytetyn tiedon omistajuuteen ja vinoumiin."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Toimeentulon epävarmuus lisääntyy",
      "Mistä on kyse?": "Teknologian muuttaessa voimakkaasti monia tuntemiamme aloja ja synnyttäen uusia, on epäselvää, miten työ ja toimeentulo syntyvät ja jakautuvat tulevaisuudessa. On mahdollista, että vain harvoilla on työtä ja vielä harvemmat hyötyvät sen tuloksista tai että teknologia ja digitalisoituminen synnyttävätkin mittavasti uutta palkkatyötä, jota on runsaasti tarjolla. Tulevaisuuden vauraudenjaon ja toimeentulon pohtimisen tulisi olla politiikan tulevaisuuspohdintojen ytimessä."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Elinikäinen oppiminen muuttuu hyveestä välttämättömyydeksi",
      "Mistä on kyse?": "Elinikäisestä uuden oppimisesta pitäisi tulla uusi elämän perusasetus, kun tulevaisuudessa eliniät pitenevät entisestään. Jos tulevaisuudessa yhä useampi elää lähes 100-vuotiaaksi, ei pelkästään elämän alkuvaiheessa hankittu koulutus välttämättä riitä kantamaan koko työelämän läpi. Mikrotutkinnot tai opintotilit voisivat auttaa tässä."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Äärimmäiset sääilmiöt yleistyvät",
      "Mistä on kyse?": "Ilmastonmuutos lisää äärimmäisiä sääilmiöitä. Tulvat ja kuivuudet lisääntyvät, samoin kuin entistä voimakkaammat myrskyt. Sääolojen vaihtelevuus aiheuttaa paineita erityisesti maataloudelle ja infrastruktuurille."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Edustuksellisen demokratian puhti on hukassa",
      "Mistä on kyse?": "Äänestysprosentit ja puolueiden jäsenmäärät ovat tasaisesti laskeneet useita vuosikymmeniä, myös demokratian leviäminen maailmassa on hidastunut ja jopa pysähtynyt. Toimiakseen demokratia kaipaa vahvistamista, uusia toimintatapoja ja osallisuuden toteutumista. On mahdollista että tulevaisuudessa näemme vallan keskittymistä yhä harvempiin käsiin sekä levottomuuden ja jännitteiden lisääntymistä. Toisaalta on mahdollista että kriisin merkit laukaisevat demokratian kehittämisen ja osallisuuden kultakauden."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Luottamuksen puute ja eriarvoistuminen haastavat demokratiaa",
      "Mistä on kyse?": "Demokratian tilan tarkastelu on aina koko yhteiskunnan hyvinvoinnin tarkastelua, johon vaikuttavat esimerkiksi yhteiskunnassa vallitseva luottamus, tasa-arvo, instituutioiden toimivuus, talouden tila ja työllisyys. Viime vuosina OECD-maissa yhteiskunnallinen eriarvoistuminen on ollut kasvava trendi, vaikka pohjoismaissa kehitys on ollut tasaisempaa. Globaaleissa luottamusbarometreissa on mitattu hälyttäviä lukuja kansalaisten luottamuksen rapautumisesta instituutioihin, bisnekseen ja hallituksiin."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Globaali päätöksenteko ja lähidemokratia kaipaavat vahvistusta",
      "Mistä on kyse?": "Maailmassa on useita viheliäisiä ongelmia, joita ei voida ratkaista kansallisvaltioiden rajojen sisällä. Globalisaation aiheuttamat hyödyt ja haitat, luonnonresurssien jakaminen sekä ilman, veden ja viljelymaiden puhtaus ovat esimerkkejä aiheista, jotka koskettavat kaikkia maapallon asukkaita. Samaan aikaan globaali keskinäisriippuvainen maailma tarvitsee vastapainokseen hyvin toteutuvaa lähidemokratiaa. Molempien ulottuvuuksien kehittäminen tulee tärkeäksi tulevaisuudessa."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Teknologian ymmärtämisestä tulee kansalaistaito",
      "Mistä on kyse?": "Kun yhä useampi asia tapahtuu verkossa digitaalisilla alustoilla, tulee tärkeäksi uudenlaisten teknologiataitojen haltuunotto. Tähän voivat kuulua esimerkiksi henkilökohtaisen datan käyttöön, oikeuksiin ja hyödyntämiseen liittyvät asiat, ymmärrys algoritmien vaikutuksista mediankäyttöömme tai vaikkapa verkkorikollisuuteen varautumiseen liittyvät asiat."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Päätöksenteosta tulee ongelmanratkaisua",
      "Mistä on kyse?": "Informaatiota pullistelevassa maailmassa asioihin on entistä vaikeampaa löytää suoraviivaisia vastauksia. Tulevaisuudessa päätöksentekijöiden, tiedon tuottajien ja ratkaisujen muotoilijoiden tulisi kokoontua yhteen oppimaan toisiltaan. Sen sijaan, että tehtäisiin kertapäätös asioiden oikeasta tilasta, tulevaisuudessa tulisi sitoutua yhteiselle oppimis- ja kehittämismatkalle."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Talouden reunaehdot tiukentuvat",
      "Mistä on kyse?": "Pitkä hitaan kasvun aika on taittumassa, mutta tulevaisuuden talouskasvuun liittyy monia epävarmuuksia. Ikääntyvä väestö ja maapallon ekologisen kantokyvyn rajat asettavat talouskasvulle paljon tiukemmat reunaehdot aiempaan verrattuna."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Kiertotalouden merkitys kasvaa",
      "Mistä on kyse?": "Kiertotalous on talousmalli, jossa tuotanto ja käyttö suunnitellaan siten, että jätettä ei synny, vaan materiaalit ja niiden arvo säilyvät kierrossa. Kiertotalous ei ole vain kierrätystä, vaan myös talouden uusia toimintamalleja kuten jakamista, liisaamista, korjaamista ja uudelleenkäyttöä, jonka mahdollistamisessa uusi teknologia on avainasemassa."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Talouden onnistumisen uudet mittarit",
      "Mistä on kyse?": "Tulevaisuudessa taloutta tarkastellaan mahdollisesti sen onnistumisesta käsin, ei sen koosta ja kasvuvauhdista käsin. Mikäli tulevaisuudessa sekä hyvinvointi että maapallon kantokyky hyväksytään yhä selkeämmin menestyvän yhteiskunnan merkeiksi, vaatii talouden tarkastelu uudenlaista mittaristoa suhteessa näihin tavoitteisiin. Tämä mittaristo koostuisi monipuolisesta tiedosta liittyen esimerkiksi hyvinvoinnin edellytyksiin, demokratiaan, terveyteen, ilmastonmuutokseen, veden ja resurssien riittävyyteen, eläinlajien säilymiseen ja niin edelleen."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Digitalisaatio",
      "Mistä on kyse?": "Digitalisaatio on tämänhetkistä murrosta voimakkaimmin määrittelevä teknologian kehitysmuoto. Digitalisaatiossa on kyse digitaalisen teknologian käytöstä asioiden hoitamisessa. Tämä mahdollistaa uusia verkostomaisia toimintatapoja sekä valtavien datamäärien keruun ja nopean analysoinnin, joka ei aiemmin ollut mahdollista. Kun teollinen vallankumous loi talouteen muskelit, luo digitalisaatio ikään kuin hermojärjestelmän ja muuttaa sitä kautta tapaamme toimia."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Virtuaali- ja lisätty todellisuus yleistyy",
      "Mistä on kyse?": "Virtuaalitodellisuudessa uppoudutaan täysin simuloituun maailmaan, kun taas lisätyssä todellisuudessa täydennetään nähtyä todellista ympäristöä. Nämä muokkaavat kokemusta eletystä ympäristöstä ja mahdollistavat uudenlaisia taitoja. Esimerkiksi erilainen viihde, matkustaminen ja kulttuurikokemukset voivat tulla mahdollisiksi aivan uudella tavalla ilman siirtymistä paikasta toiseen."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Robotisaatio",
      "Mistä on kyse?": "Robotisaatio mahdollistaa palvelut, jotka ovat joko kokonaan tai osaksi automatisoituja, sekä kokonaan automatisoidun tuotannon. Robotisaation ja tekoälyn yhteisvaikutus on se, että robotit suoriutuvat yhä paremmin erilaisista tehtävistä. Esimerkiksi teknologiafirmat kehittävät henkilökohtaisia assistenttirobotteja. Myös itse ajavat autot, saumaton älykäs liikenne ja miehittämättömät lennokit (drones) perustuvat robotisaatioon."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Nopea analytiikka yleistyy",
      "Mistä on kyse?": "Modernit laboratoriotekniikat, kuten verinäytteet, bakteeri- ja virustestaaminen sekä esimerkiksi rikostutkintaan liittyvä tekniikka voidaan tehdä koko ajan halvemmalla, jolloin niitä voidaan myydä myös kuluttajamarkkinoille. Pian on mahdollista ostaa erilaisia analytiikkaa tarjoavia tuotteita, jotka integroituna kannettaviin laitteisiin kertovat omistajalleen hänen terveydentilastaan, ympäröivän ilman laadusta, hedelmän tuoreusasteesta tai minkä tahansa materiaalin koostumuksesta."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Organismien ohjelmointi arkipäiväistyy",
      "Mistä on kyse?": "Geenimuuntelu ja synteettinen biologia mahdollistavat uudenlaisten organismien luomisen ja olemassa olevien muuntelemisen haluttuun tarkoitukseen. Muokatun hiivan avulla voidaan tuottaa silkkiä ja sinilevällä polttoainetta. Vastaavia sovelluksia voidaan hyödyntää esimerkiksi ruuantuotannossa, kemiallisissa prosesseissa, tekstiileissä, lääketeollisuudessa ja rakentamisessa. Personoitu lääketiede ja ravitsemus ja monien tautien voittaminen voivat tarkoittaa merkittävästi pidempiä elinikiä."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Uusiutuva energia halpenee",
      "Mistä on kyse?": "Aurinko- ja tuulivoiman hinta on pudonnut nopeasti. Samoin niiden varastointiin liittyvä akkuteknologia on kehittynyt vauhdilla. Uusiutuva energia on paikoin jo halvempaa kuin fossiilisilla polttoaineilla tuotettu. Samalla energiantuotanto hajautuu, kun yhä useampi kansalainen tuottaa itse oman energiansa ja myy ylimenevän osan."
    },
    {
      "Gen": false,
      "Lähde": "Megatrendikortit 2017 © Sitra",
      "Ilmiö": "Lohkoketjut mahdollistavat hajautetun toiminnan",
      "Mistä on kyse?": "Blockchain eli lohkoketjuteknologia mahdollistaa hajautetun tietokannan tuottamisen ja ylläpitämisen. Käytännössä tämä tarkoittaa, että kolmatta osapuolta ei enää tarvita varmistamaan maksutapahtumia, tiedon paikkansapitävyyttä tai yleisesti vuorovaikutuksen luotettavuutta. Tunnetuin esimerkki lohkoketjuteknologian hyödyntämisestä on virtuaalivaluutta bitcoin, mutta lohkoketjun avulla voidaan toteuttaa myös esimerkiksi itseään valvovia älysopimuksia tai vaikkapa täysin hajautettu kyytipalvelu."
    }
  ]