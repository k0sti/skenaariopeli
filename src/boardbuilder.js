var boardbuilder = function() {

  async function build() {
    let nw = skenaariopeli.namedWidgets;
    if (await verifyWidget(nw.Frame0)) {
      
    }
  }

  async function verifyWidget(widgetName) {
    if (widgetName) {
      console.log(`Found ${widgetName}`)
      return true;
    }
    console.log(`Not found ${widgetName}`)
    return false;
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
