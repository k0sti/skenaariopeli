var skenaariopeli = function() {
  const SHARED_STEP = "Step";
  const DEAL_CARD_WIDGET_ID = "3074457350081245516";

  var StepNumber = 0;
  var Deck = [];
  var poll;
  var namedWidgets = {
    "Frame1": "3074457349955055983",
  };

  var replacements = {
    "{scenario_actor}": "Yle",
    "{scenario_year}": "2030",
    "{backcast_year_4}": "2029",
    "{backcast_year_3}": "2027",
    "{backcast_year_2}": "2023",
    "{backcast_year_1}": "2021",
  };

  async function initialize() {
    console.log("skenaariopeli.initialize");
    StepNumber = parseInt(await mirotools.getSharedValue(SHARED_STEP));
    onEnterState(StepNumber);

    poll = setInterval(pollCallback, 2000);
    await miro.addListener("SELECTION_UPDATED", (e) => onMiroSelectionChange(e))
  }

  function deInitialize() {
    clearInterval(poll)
  }

  function shuffleIlmiöt() {
    Deck = ilmiöt.filter(ilmiö => ilmiö.Gen);
    Deck.sort(function (a, b) { return 0.5 - Math.random() });
  }

  function popIlmiö() {
    if (Deck.length == 0) {
      shuffleIlmiöt();
    }
    return Deck.shift();
  }

  async function onMiroSelectionChange(e) {
    let widgets = e.data;
    if (widgets.length === 1) {
      let widget = widgets[0];
      if (widget.id === DEAL_CARD_WIDGET_ID) {
        console.log("DEAL CARD!");
        let deckWidget = (await miro.board.widgets.get({ id: DEAL_CARD_WIDGET_ID }))[0];
        let ilmiöCard = popIlmiö();
        await miro.board.widgets.create([{
          type: "sticker",
          text: ilmiöCard.Ilmiö,
          x: deckWidget.x + Math.random() * 100 - 50,
          y: deckWidget.y + Math.random() * 20 + 100,
          scale: 0.5},
        ]);
        // Clear selection
        miro.board.selection.selectWidgets([]);
      }
    }
  }

  async function stepForward(skipToCue) {
    await onExitState(StepNumber);
    let stop = false;
    while (StepNumber < stepData.length - 1 && !stop) {
      StepNumber++;
      if (!skipToCue || stepData[StepNumber].cuePoint) stop = true;
    }
    await onEnterState(StepNumber);
    if (mirotools.isMiroEnabled()) mirotools.setSharedValue(SHARED_STEP, StepNumber);
  }

  async function stepBackward(skipToCue) {
    await onExitState(StepNumber);
    let stop = false;
    while (StepNumber > 0 && !stop) {
      StepNumber--;
      if (!skipToCue || stepData[StepNumber].cuePoint) stop = true;
    }
    await onEnterState(StepNumber);
    if (mirotools.isMiroEnabled()) mirotools.setSharedValue(SHARED_STEP, StepNumber);
  }

  function formatPlainText(text) {
    var formattedText = text;
    // use string replacements
    formattedText = Object.keys(replacements).reduce(
      (prev, key) => prev.replace(new RegExp(key, "g"), replacements[key]),
      formattedText
    );
    // add html paragraph breaks
    formattedText = formattedText.replace(
      /^(?!<p>)(.*)(?!<\/p>)$/gm,
      "<p>$1</p>"
    );
    return formattedText;
  }

  async function pollCallback() {
    let sharedState = parseInt(await mirotools.getSharedValue(SHARED_STEP));
    if (StepNumber != sharedState) {
      StepNumber = sharedState;
      changeState(StepNumber);
    }
  }

  async function onEnterState(stepNumber) {
    var stateData = stepData[stepNumber];

    document.getElementById("step_head").innerHTML = formatPlainText(
      stateData.title
    );
    document.getElementById("step_text").innerHTML = formatPlainText(
      stateData.body
    );

    // Miro specifics below
    if (!mirotools.isMiroEnabled()) return;

    if (stateData.focus) {
      let widget = (await miro.board.widgets.get({ id: namedWidgets[stateData.focus] }))[0];
      miro.board.viewport.zoomToObject(widget.id)
    }

    switch(stateData.id) {
      case "Frame2": {
        let actorResponse = await mirotools.getContainedStickerText(
          "SCENARIO_ACTOR_CONTAINER"
        );
        if (actorResponse.success) {
          replacements["{scenario_actor}"] = actorResponse.value;
        }
        let yearResponse = await mirotools.getContainedStickerText(
          "SCENARIO_YEAR_CONTAINER"
        );
        if (yearResponse.success) {
          replacements["{scenario_year}"] = yearResponse.value;
        }
      }
    }

  }

  async function onExitState(stepNumber) {
    var stateData = stepData[stepNumber];

    if (!mirotools.isMiroEnabled()) return;
    // Miro specifics below

    switch(stateData.id) {
    }
  }

  return {
    initialize,
    deInitialize,
    onEnterState,
    stepForward,
    stepBackward,
  }
}();