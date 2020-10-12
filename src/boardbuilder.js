var boardbuilder = function() {

  const SHARED_NAMED_WIDGETS = "NamedWidgets";

  var nw;
  var WidgetsModified = false;

  async function build() {
    WidgetsModified = false;

    let j = await mirotools.getSharedValue(SHARED_NAMED_WIDGETS);
    console.log(j);
    if (j) nw = await JSON.parse(j);
    console.log(nw);

    if (await verifyWidget("Frame0")) {
      addWidget("Frame0", await createFrame());
    }

    if (WidgetsModified) {
      await mirotools.setSharedValue(SHARED_NAMED_WIDGETS, JSON.stringify(nw));
    }

    skenaariopeli.setNamedWidgets(nw);
  }

  async function verifyWidget(widgetName) {
    if (nv.widgetName) {
      console.log(`Found ${widgetName}`)
      return true;
    }
    console.log(`Not found ${widgetName}`)
    return false;
  }

  function addWidget(widgetName, w) {
    nv[widgetName] = w;
    WidgetsModified = true;
  }

  async function createFrame() {
    let createdWidgets = await miro.board.widgets.create([{
      "type": "FRAME",
      "x": -1436,
      "y": -390,
      "width": 660,
      "height": 540,
      "style": {
        "backgroundColor": "#ffffff"
      },
      "title": "Pelaajien nimet"
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
