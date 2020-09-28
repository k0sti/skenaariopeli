var skenaariopeli = function() {
  const SHARED_STEP = "Step";
  const DEAL_CARD_WIDGET_ID = "3074457350081245516";

  var StepNumber = 0;
  var Deck = [];
  var poll;
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
    changeState(StepNumber);

    poll = setInterval(pollCallback, 2000);
    await miro.addListener("SELECTION_UPDATED", (e) => onMiroSelectionChange(e))
  }

  function deInitialize() {
    clearInterval(poll)
  }

  function shuffleIlmiöt() {
    Deck = ilmiöt.filter(ilmiö => ilmiö.Gen);
    Deck.sort(function (a, b) { return 0.5 - Math.random() });
    console.log(Deck[0].Ilmiö)
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
    let stop = false;
    while (StepNumber < stepData.length - 1 && !stop) {
      if (mirotools.isMiroEnabled()) {
        await onExitState(StepNumber);
      }
      StepNumber++;
      if (!skipToCue || stepData[StepNumber].cuePoint) stop = true;
    }
    changeState(StepNumber);
    if (mirotools.isMiroEnabled()) mirotools.setSharedValue(SHARED_STEP, StepNumber);
  }

  async function stepBackward(skipToCue) {
    let stop = false;
    while (StepNumber > 0 && !stop) {
      if (mirotools.isMiroEnabled()) {
        await onExitState(StepNumber);
      }
      StepNumber--;
      if (!skipToCue || stepData[StepNumber].cuePoint) stop = true;
    }
    changeState(StepNumber);
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

  function changeState(stateId) {
    var stateData = stepData[stateId];

    document.getElementById("step_head").innerHTML = formatPlainText(
      stateData.title
    );
    document.getElementById("step_text").innerHTML = formatPlainText(
      stateData.body
    );
  }

  async function pollCallback() {
    let sharedState = parseInt(await mirotools.getSharedValue(SHARED_STEP));
    if (StepNumber != sharedState) {
      StepNumber = sharedState;
      changeState(StepNumber);
    }
  }

  async function onExitState(state) {
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
    console.log("Actor: " + actorResponse.value);
    console.log("Year: " + yearResponse.value);
  }

  return {
    initialize,
    deInitialize,
    changeState,
    stepForward,
    stepBackward,
  }
}();