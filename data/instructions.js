const stepData = [
  {
    title: "Tervetuloa Skenaariopeliin!",
    cuePoint: true,
    id: "Frame0",
    focus: "Frame0",
    body: `
Seuraavan noin 90 minuutin aikana luodaan 2–5 hengen ryhmässä yksi mahdollinen tulevaisuusskenaario ryhmäänne kiinnostavasta aiheesta. Lopuksi joku ryhmästänne kertoo siitä 2 minuutin kiteytetyn tarinan, joka kannattaa tallentaa muistoksi.

<h2>Pelin aloitus ja kulku</h2>
Pelissä on 6 vaihetta, joissa on muutamia alivaiheita. Tämä ohjepaneeli opastaa pelin läpi.

Suosittelemme, että ryhmä valitsee aluksi keskuudestaan pelinjohtajan, joka huolehtii pelin etenemisestä.

Kun olette valmiit, aloittakaa peli painamalla <b>Eteenpäin <i class="fas fa-play"></i></b> -nappia. Samasta napista myös siirrytään eteenpäin pelin vaiheissa.

<h2>Pikaohje Miron käyttöön</h2>
Pelissä käytetään Miron virtuaalisia tarralappuja. Odotellessa voit harjoitella <b><i class="far fa-sticky-note"></i> tarralappujen</b> vetämistä työkalupakista "pelaajien nimet" -taululle.

<iframe width="100%" height="auto" src="https://www.youtube.com/embed/7L1-0DOGHDY" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

`,
  },

  {
    title: "1/6 Me ja skenaarion luonne",
    cuePoint: true,
    id: "Frame1",
    focus: "Frame1",
    body: `
Skenaariopelissä ryhmällenne on annettu kaikki valta luotsata itsenne seuraavien vuosien tai vuosikymmenten halki.

Kirjoittakaa aluksi <b>lapulle <i class="far fa-sticky-note"></i></b>, kenen näkökulmasta tulevaisuutta tarkastelette.

Asettakaa lappu taululle kohtaan "Me".

<i>esim. “Yle".</i>
`,
  },

  {
    title: "1/6 Me ja skenaarion luonne",
    body: `
Kirjoittakaa toiselle kortille <i class="far fa-sticky-note"></i> skenaarionne tarkasteluvuosi.

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
    id: "Frame2",
    focus: "Frame2",
    body: `

<b>Jakakaa</b> taululle 3 satunnaista muutosvoimaa napauttamalla ilmiökorttipakkaa.

<b>Tutustukaa</b> hetki niihin ja päätä vaikuttavin muutosvoima vuoden {scenario_year} maailmassa.

<b><i class="fas fa-mouse-pointer"></i> Osoittakaa</b> sitten yhtäaikaa valitsemianne ilmiötä. Voit myös olla valitsematta mitään.

<b>Siivotkaa</b> pöydältä ne ilmiöt, jotka eivät tulleet valituksi.

<b>Jakakaa ja valitkaa</b> ilmiöitä, kunnes olette päätyneet 5 muutosvoimaan ja painakaa <b>Eteenpäin <i class="fas fa-play"></i></b>.
`,
  },

  {
    title: "3/6 {scenario_actor} vuonna {scenario_year}",
    cuePoint: true,
    focus: "Frame3",
    body: `
<b><i class="far fa-sticky-note"></i> Kirjoita</b> omalle kortille lyhyt kuvaus siitä, miten ryhmänne {scenario_actor} on sopeutunut vuoden {scenario_year} maailmaan.
<i>Voit jatkaa virkettä "Vuonna {scenario_year} {scenario_actor}..."</i>

<b>Esitelkää</b> vuorollanne omat kuvauksenne muille.
`,
  },

  {
    title: "3/6 {scenario_actor} vuonna {scenario_year}",
    body: `
<b><i class="far fa-sticky-note"></i> Kirjoita</b> uudelle kortille toinen lyhyt kuvaus ryhmästänne vuonna {scenario_year}. Voit myös kehitellä jotain jo ehdotettua kuvausta eteenpäin!

<b>Esitelkää</b> vuorollanne myös nämä kuvaukset.
`,
  },

  {
    title: "3/6 {scenario_actor} vuonna {scenario_year}",
    body: `
<b><i class="fas fa-mouse-pointer"></i> Osoita</b> kuvausta, joka on mielestäsi olennaisin ja skenaarion luonteen mukainen.

<b>Keskustelkaa</b> valinnoista ja jättäkää pöydälle 3 kuvausta. Muokatkaa ja yhdistäkää tarvittaessa.
`,
  },

  {
    title: "4/6 Miten tähän päädyttiin?",
    cuePoint: true,
    id: "Frame4a",
    focus: "Frame4",
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
    id: "Frame4b",
    focus: "Frame4",
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
    id: "Frame4c",
    focus: "Frame4",
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
    id: "Frame4d",
    focus: "Frame4",
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
