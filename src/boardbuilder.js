var boardbuilder = function() {

  const SHARED_NAMED_WIDGETS = "NamedWidgets";

  var NamedWidgets;
  var WidgetsModified = false;

  async function build() {
    WidgetsModified = false;

    let j = await mirotools.getSharedValue(SHARED_NAMED_WIDGETS);
    console.log(j);
    if (j) NamedWidgets = await JSON.parse(j);
    console.log(NamedWidgets);

    if (!await verifyWidget("Frame0")) {
      addWidget("Frame0", await createFrame());
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
