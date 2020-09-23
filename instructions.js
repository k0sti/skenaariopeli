const stepData = [
  {
    title: "Tervetuloa Skenaariopeliin!",
    cuePoint: true,
    body: `
Skenaariopelissä ryhmällenne on annettu kaikki valta luotsata itsenne seuraavien vuosien tai vuosikymmenten halki.

Seuraavan noin 90 minuutin aikana luodaan 2–5 hengen ryhmässä yksi mahdollinen tulevaisuusskenaario ryhmäänne kiinnostavasta aiheesta. Lopuksi joku ryhmästänne kertoo siitä 2 minuutin kiteytetyn tarinan, joka kannattaa tallentaa muistoksi.

Suosittelemme, että ryhmä valitsee aluksi keskuudestaan pelinjohtajan, joka huolehtii pelin etenemisestä.

Painakaa <b>Eteenpäin <i class="fas fa-play"></i></b> -nappia kun olette valmiita aloittamaan!

<h2>Miron käyttö</h2>
Pelissä käytetään Miron virtuaalisia tarralappuja. Odotellessa voit harjoitella <b><i class="far fa-sticky-note"></i> tarralappujen</b> vetämistä työkalupakista taululle.

<iframe width="200" height="150" src="https://www.youtube.com/embed/7L1-0DOGHDY" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

`,
  },

  {
    title: "1/6 Me ja skenaarion luonne",
    cuePoint: true,
    body: `
Kirjoittakaa aluksi <b>lapulle <i class="far fa-sticky-note"></i></b>, kenen näkökulmasta tulevaisuutta tarkastelette.

Asettakaa lappu taululle kohtaan "Me".

<i>esim. “Yle".</i>
`,
  },

  {
    title: "1/6 Me ja skenaarion luonne",
    body: `
Kirjoittakaa kortille <i class="far fa-sticky-note"></i> skenaarionne tarkasteluvuosi.

<i>esim. "2030" tai "2050"</i>
`,
  },

  {
    title: "1/6 Me ja skenaarion luonne",
    body: `
Kirjoittakaa kortille <i class="far fa-sticky-note"></i>, minkä luonteisen skenaarion laaditte.

<i>esim. toivottava/epätoivottava, todennäköinen/epätodennäköinen</i>
`,
  },

  {
    title: "2/6 Maailma vuonna {scenario_year}",
    cuePoint: true,
    body: `

<b>Tutustu</b> hetki pöydällä oleviin, tulevaisuutta muokkaaviin ilmiöihin.

<b><i class="fas fa-mouse-pointer"></i> Osoita</b> sitten ilmiötä, joka on ollut vaikuttavin vuoden {scenario_year} maailmassa.

<b>Siivotkaa</b> pöydältä ne ilmiöt, jotka eivät tulleet valituksi.

<b>Eteenpäin <i class="fas fa-play"></i></b> -nappi jakaa valittavaksi uusia ilmiöitä, kunnes pöydällä on 5 valittua ilmiötä.
`,
  },

  {
    title: "3/6 {scenario_actor} vuonna {scenario_year}",
    cuePoint: true,
    body: `
<b><i class="far fa-sticky-note"></i> Kirjoita</b> omalle kortille yksi olennainen ominaisuus, jolla {scenario_actor} on sopeutunut vuoden {scenario_year} maailmaan.
<i>Aloita vaikkapa "{scenario_actor} on..."</i>

<b>Esitelkää</b> vuorollanne omat ehdotuksenne muille.
`,
  },

  {
    title: "3/6 {scenario_actor} vuonna {scenario_year}",
    body: `
<b><i class="far fa-sticky-note"></i> Kirjoita</b> uudelle kortille vielä yksi lisäominaisuus. Voit yhdistellä tai kehitellä jotain ehdotettua ominaisuutta!

<b>Esitelkää</b> vuorollanne myös nämä ehdotukset.
`,
  },

  {
    title: "3/6 {scenario_actor} vuonna {scenario_year}",
    body: `
<b><i class="fas fa-mouse-pointer"></i> Osoita</b> ominaisuutta, joka on mielestäsi olennaisin ja skenaarion luonteen mukainen.

<b>Keskustelkaa</b> valinnoista ja jättäkää pöydälle 3 ominaisuutta. Muokatkaa ja yhdistäkää ominaisuuksia tarvittaessa.
`,
  },

  {
    title: "4/6 Miten tähän päädyttiin?",
    cuePoint: true,
    body: `
Eletään vuotta {scenario_year}. Seuraavaksi muistellaan, mitkä aiemmat tapahtumat ovat johtaneet siihen, millainen {scenario_actor} on nyt.

<b><i class="far fa-sticky-note"></i> Kirjoita</b> kortille jokin kiinnostava kehityskulku vuoden {backcast_year_4} paikkeilta, joka vaikutti jonkin ominaisuuden kehittymiseen.

<b>Esitelkää</b> vuorollanne tapahtumat muille.

<b><i class="fas fa-mouse-pointer"></i> Osoita</b> sitten tapahtumaa, joka parhaiten selittää tulevan kehityksen.

<b>Asetelkaa</b> nämä tapahtumat ne aikajanalle ja siirtäkää muut sivuun.
`,
  },

  {
    title: "4/6 Miten tähän päädyttiin?",
    cuePoint: false,
    body: `
<b><i class="far fa-sticky-note"></i> Kirjoita</b> kortille jokin kiinnostava kehityskulku vuoden {backcast_year_3} paikkeilta, joka vaikutti jonkin ominaisuuden kehittymiseen.

<b>Esitelkää</b> vuorollanne tapahtumat muille.

<b><i class="fas fa-mouse-pointer"></i> Osoita</b> sitten tapahtumaa, joka parhaiten selittää tulevan kehityksen.

<b>Asetelkaa</b> nämä tapahtumat ne aikajanalle ja siirtäkää muut sivuun.
`,
  },

  {
    title: "4/6 Miten tähän päädyttiin?",
    cuePoint: false,
    body: `
<b><i class="far fa-sticky-note"></i> Kirjoita</b> kortille jokin kiinnostava kehityskulku vuoden {backcast_year_2} paikkeilta, joka vaikutti jonkin ominaisuuden kehittymiseen.

<b>Esitelkää</b> vuorollanne tapahtumat muille.

<b><i class="fas fa-mouse-pointer"></i> Osoita</b> sitten tapahtumaa, joka parhaiten selittää tulevan kehityksen.

<b>Asetelkaa</b> nämä tapahtumat ne aikajanalle ja siirtäkää muut sivuun.
`,
  },

  {
    title: "4/6 Miten tähän päädyttiin?",
    cuePoint: false,
    body: `
<b><i class="far fa-sticky-note"></i> Kirjoita</b> kortille jokin kiinnostava kehityskulku vuoden {backcast_year_1} paikkeilta, joka vaikutti jonkin ominaisuuden kehittymiseen.

<b>Esitelkää</b> vuorollanne tapahtumat muille.

<b><i class="fas fa-mouse-pointer"></i> Osoita</b> sitten tapahtumaa, joka parhaiten selittää tulevan kehityksen.

<b>Asetelkaa</b> nämä tapahtumat ne aikajanalle ja siirtäkää muut sivuun.
`,
  },

  {
    title: "5/6 Dokumentoi",
    cuePoint: true,
    body: `
Valmistelkaa ja kertokaa 2 minuutin tarina tulevaisuuden maailmasta, itsestänne siellä sekä kohokohdat tapahtumista, jotka siihen johtivat.

<i>Vinkki: Tarinan dokumentoimiseen voi käyttää vaikkapa videopuhelun tallennustoimintoa [Ohjeita].</i>
`,
  },

  {
    title: "6/6 Jaa ja keskustele",
    cuePoint: true,
    body: `
Käyttäkää pieni hetki keskusteluun pelin tuloksista.

<b>Kerro</b> vuorollasi muille, mikä yllätti, mikä energisoi, mikä ehkä säikäytti. Minkä ajatuksen kanssa haluaisit edetä pelin jälkeen, miten ja kenen kanssa.

Kiitoksia pelistä!
`,
  },
];
