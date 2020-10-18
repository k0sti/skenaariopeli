var boardbuilder = function() {

  const SHARED_NAMED_WIDGETS = "NamedWidgets";

  const FRAME_WIDTH = 1350;
  const FRAME_HEIGHT = 1080;
  const FRAME_MARGIN = 50;
  const FRAME_4_WIDTH = 2000;

  var NamedWidgets = {};
  var WidgetsModified = false;

  async function build() {
    WidgetsModified = false;

    let j = await mirotools.getSharedValue(SHARED_NAMED_WIDGETS);
    console.log(j);
    if (j) NamedWidgets = await JSON.parse(j);
    console.log(NamedWidgets);

    if (!await verifyWidget("Frame0")) {
      addWidget("Frame0", await createFrame(0,0, FRAME_WIDTH,FRAME_HEIGHT, "Pelaajien nimet"));
    }

    if (!await verifyWidget("Frame1")) {
      addWidget("Frame1", await createFrame( (FRAME_WIDTH+FRAME_MARGIN)*1,0, FRAME_WIDTH,FRAME_HEIGHT, "Me ja skenaarion luonne"));
    }

    if (!await verifyWidget("Frame2")) {
      addWidget("Frame2", await createFrame( (FRAME_WIDTH+FRAME_MARGIN)*2,0, FRAME_WIDTH,FRAME_HEIGHT, "Tulevaisuuden maailma"));
    }

    if (!await verifyWidget("Frame3")) {
      addWidget("Frame3", await createFrame( (FRAME_WIDTH+FRAME_MARGIN)*3,0, FRAME_WIDTH,FRAME_HEIGHT, "Me vuonna 20xx"));
    }

    if (!await verifyWidget("Frame4")) {
      addWidget("Frame4", await createFrame( (FRAME_WIDTH+FRAME_MARGIN)*3+(FRAME_MARGIN+FRAME_WIDTH/2+FRAME_4_WIDTH/2),0, FRAME_4_WIDTH,FRAME_HEIGHT, "Miten tähän päädyttiin?"));
    }

    if (!await verifyWidget("DealButton")) {
      addWidget("DealButton", await createSticker((FRAME_WIDTH+FRAME_MARGIN)*2,200, "Jaa Ilmiökortti", "#ff9d48"));
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

  async function createSticker(x, y, text, color="#f5d128") {
    let createdWidgets = await miro.board.widgets.create([{
      "type": "STICKER",
      "style": {
        "stickerBackgroundColor": color,
        "stickerType": 0
      },
      "x": x,
      "y": y,
      "scale": 1,
      "text": text,
    }]);
    return createdWidgets[0].id;
  }

  return {
    build
  }
}();
