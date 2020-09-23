parent.mirotools = function() {
  let MiroEnabled = () => miro && miro.board ? true : false;

  // Get a Miro Sticker to store sync data in
  async function getMiroStickerByKey(key) {
    var searchString = `${key}: `;
    var elements = await miro.board.widgets.get({
      type: "sticker",
    });
    var element = elements.find((candidate) =>
      candidate.plainText.startsWith(searchString)
    );
    // miro.board.widgets.update([{ id: element.id, clientVisible: false}])
    return element;
  }

  // Fetch value for key from a Miro Sticker
  async function getSharedValue(key) {
    let element = await getMiroStickerByKey(key);
    if (element) {
      return await element.plainText.substring(key.length + 2); // Skip key name and ": "
    } else {
      return undefined;
    }
  }

  // Store value for key from a Sticker
  async function setSharedValue(key, value) {
    let element = await getMiroStickerByKey(key);
    let text = `${key}: ${value}`;
    if (element) {
      await miro.board.widgets.update([{ id: element.id, text: text }]);
    } else {
      await miro.board.widgets.create([
        { type: "sticker", text: text /* clientVisible: false, */ },
      ]);
    }
  }

  async function getMiroElementByContent(key) {
    return (await miro.board.widgets.get({ plainText: key }))[0];
  }

  async function getIntersectedStickers(container) {
    let stickers = await miro.board.widgets.get({
      type: "sticker",
    });
    let elements = stickers.filter((sticker) => {
      if (sticker.bounds.right < container.bounds.left) return false;
      if (sticker.bounds.left > container.bounds.right) return false;
      if (sticker.bounds.bottom < container.bounds.top) return false;
      if (sticker.bounds.top > container.bounds.bottom) return false;
      return true;
    });
    return elements;
  }

  // Expect just one sticker
  async function getContainedStickerText(containerContent) {
    let container = await getMiroElementByContent(containerContent);
    if (!container) {
      let response = {
        success: false,
        errorMessage: `Aluetta nimeltä ${containerContent} ei löytynyt.`,
      };
      console.warn(response.errorMessage);
      return response;
    }

    let containedStickers = await getIntersectedStickers(container);
    if (containedStickers.length < 1) {
      let response = {
        success: false,
        errorMessage: `Yhtään tarralappua ei löytynyt alueella ${container.plainText}`,
      };
      console.warn(response.errorMessage);
      return response;
    }
    if (containedStickers.length > 1) {
      let response = {
        success: false,
        errorMessage: `Useita tarralappuja löydettiin alueella ${container.plainText}`,
      };
      console.warn(response.errorMessage);
      return response;
    }
    let response = {
      success: true,
      value: containedStickers[0].plainText,
    };
    return response;
  }

  // Return the module's public interface accessible via modulename.property
  return {
    MiroEnabled,
    getMiroStickerByKey,
    setSharedValue,
    getMiroElementByContent,
    getIntersectedStickers,
    getContainedStickerText
  }
}();
