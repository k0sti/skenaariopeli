var skenaariopeli = function() {
  const SHARED_STEP = "Step";
  const SHARED_SEED = "Seed";
  const SHARED_NAMED_WIDGETS = "NamedWidgets";

  var StepNumber = 0;
  var Seed = 0;
  var Deck = [];
  var poll;
  var namedWidgets = {};
/*
    "DealButton": "3074457350081245516",
    "Frame1Area1": "3074457349955055929",
    "Frame1Area2": "3074457349955055930",
    "Frame1Area3": "3074457350201308677",
    "Frame0": "3074457349957558594",
    "Frame1": "3074457349955055983",
    "Frame2": "3074457349955055980",
    "Frame3": "3074457349955055981",
    "Frame4": "3074457349955055982",
  };
*/
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

    let j = await mirotools.getSharedValue(SHARED_NAMED_WIDGETS);
    if (j) namedWidgets = JSON.parse(j);
    boardbuilder.build();

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
      if (widget.id === namedWidgets.DealButton) {
        console.log("DEAL CARD!");
        let deckWidget = (await miro.board.widgets.get({ id: namedWidgets.DealButton }))[0];
        let ilmiöCard = popIlmiö();
        await miro.board.widgets.create([{
          type: "sticker",
          text: ilmiöCard.Ilmiö,
          x: deckWidget.x + Math.random() * 20 - 10 + ((Seed % 3) - 1) * 200,
          y: deckWidget.y + Math.random() * 20 + 120,
          scale: 0.5,
          style: {
            stickerType: 1,
          }
        }]);
        // Clear selection
        miro.board.selection.selectWidgets([]);
        Seed++;
        mirotools.setSharedValue(SHARED_SEED, Seed);
      }
    }
  }

  async function stepForward(skipToCue) {
    let destinationStep = StepNumber;
    let stop = false;
    while (destinationStep < stepData.length - 1 && !stop) {
      destinationStep++;
      if (!skipToCue || stepData[destinationStep].cuePoint) stop = true;
    }
    if (mirotools.isMiroEnabled()) mirotools.setSharedValue(SHARED_STEP, destinationStep);
    seekStep(destinationStep);
  }

  async function stepBackward(skipToCue) {
    let destinationStep = StepNumber;
    let stop = false;
    while (destinationStep > 0 && !stop) {
      destinationStep--;
      if (!skipToCue || stepData[destinationStep].cuePoint) stop = true;
    }
    if (mirotools.isMiroEnabled()) mirotools.setSharedValue(SHARED_STEP, destinationStep);
    seekStep(destinationStep);
  }

  async function seekStep(destinationStep) {
    if (StepNumber === destinationStep) return;
    let delta = Math.sign(destinationStep - StepNumber);
    do {
      await onExitState(StepNumber);
      StepNumber += delta;
      await onEnterState(StepNumber);
    } while (StepNumber !== destinationStep);
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
    let destinationStep = parseInt(await mirotools.getSharedValue(SHARED_STEP));
    if (StepNumber != destinationStep) {
      seekStep(destinationStep);
    }
    Seed = parseInt(await mirotools.getSharedValue(SHARED_SEED));
  }

  async function onEnterState(stepNumber) {
    var stateData = stepData[stepNumber];

    if (mirotools.isMiroEnabled()) {
      // Handle Miro board focus
      if (stateData.focus) {
        let widget = (await miro.board.widgets.get({ id: namedWidgets[stateData.focus] }))[0];
        miro.board.viewport.zoomToObject(widget.id)
      }

      if (stateData.id) {
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
    }

    // Change sidebar content
    document.getElementById("step_head").innerHTML = formatPlainText(
      stateData.title
    );
    document.getElementById("step_text").innerHTML = formatPlainText(
      stateData.body
    );

  }

  async function onExitState(stepNumber) {
    var stateData = stepData[stepNumber];

    if (mirotools.isMiroEnabled()) {
      if (stateData.id) {
        switch(stateData.id) {
        }
      }
    }
  }

  return {
    initialize,
    deInitialize,
    onEnterState,
    stepForward,
    stepBackward,
    namedWidgets,
  }
}();