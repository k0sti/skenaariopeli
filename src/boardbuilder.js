var boardbuilder = function() {

  const SHARED_NAMED_WIDGETS = "NamedWidgets";

  var NamedWidgets = {};
  var WidgetsModified = false;

  async function build() {
    WidgetsModified = false;

    let j = await mirotools.getSharedValue(SHARED_NAMED_WIDGETS);
    console.log(j);
    if (j) NamedWidgets = await JSON.parse(j);
    console.log(NamedWidgets);

    if (!await verifyWidget("Frame0")) {
      addWidget("Frame0", await createFrame(0,0, 1350,1080, "Pelaajien nimet"));
    }

    if (!await verifyWidget("Frame1")) {
      addWidget("Frame1", await createFrame(1400,0, 1350,1080, "Me ja skenaarion luonne"));
    }

    if (!await verifyWidget("Frame2")) {
      addWidget("Frame2", await createFrame(2800,0, 1350,1080, "Tulevaisuuden maailma"));
    }

    if (!await verifyWidget("Frame3")) {
      addWidget("Frame3", await createFrame(4200,0, 1350,1080, "Me vuonna 20xx"));
    }

    if (!await verifyWidget("Frame4")) {
      addWidget("Frame4", await createFrame(5925,0, 2000,1080, "Miten tähän päädyttiin?"));
    }

    if (WidgetsModified) {
      await mirotools.setSharedValue(SHARED_NAMED_WIDGETS, JSON.stringify(NamedWidgets));
    }

    skenaariopeli.setNamedWidgets(NamedWidgets);
  }

  async function verifyWidget(widgetName) {
    if (NamedWidgets[widgetName]) {
      let widget = (await miro.board.widgets.get({ id: NamedWidgets[widgetName] }))[0];
      if (widget) {
        console.log(`Found ${widgetName}`)
        return true;
      }
    }
    console.log(`Not found ${widgetName}`)
    return false;
  }

  function addWidget(widgetName, w) {
    NamedWidgets[widgetName] = w;
    WidgetsModified = true;
  }

  async function createFrame(x, y, w, h, title) {
    let createdWidgets = await miro.board.widgets.create([{
      "type": "FRAME",
      "x": x,
      "y": y,
      "width": w,
      "height": h,
      "style": {
        "backgroundColor": "#ffffff"
      },
      "title": title
    }]);
    return createdWidgets[0].id;
  }

  /*
  {
    "type": "FRAME",
    "x": -1436.1589796508217,
    "y": -390.82251718539095,
    "width": 658.4492636918368,
    "height": 537.298865748549,
    "style": {
      "backgroundColor": "#ffffff"
    },
    "title": "Pelaajien nimet"
  }
  */
  return {
    build
  }
}();
