var ilmiöt = [];

const SPREADSHEET_URL =
  "1qswMijuMmv6wzbPzx8B8IBX3e1-otjM1Hk06KzxhQOE";

(async() => {
  /*await*/ loadSheetData();
  //ilmiöt.forEach(row => {
  //  console.log(`${row["Gen"]} ${row["Lähde"]}, ${row["Ilmiö"]}, ${row["Mistä on kyse?"]}`);
  //});
})();


async function loadSheetData() {
  const tabletop = await Tabletop.init({
    key: SPREADSHEET_URL,
    simpleSheet: false
  });

  const items = tabletop["Kortit"].elements;

  ilmiöt = items.slice().filter(row => row["Gen"]);

  console.log(`${ilmiöt.length} rows loaded`);
}
