console.log("-- Init Skenaariopeli applogic.js - version 4");

miro.onReady(async function() {
  const authorized = await miro.isAuthorized();
  if (authorized) {
    console.log("Authorized")
    initialize();
  } else {
    console.log("Not authorized")
    miro.board.ui.openModal('skenaariopeli/not-authorized.html')
      .then(res => {
        if (res === 'success') {
          initialize();
        }
      })
  }
})

function initialize() {
  miro.initialize({
    extensionPoints: {
      bottomBar: {
        title: 'Skenaariopeli',
        svgIcon: '<circle cx="12" cy="12" r="9" fill="none" fill-rule="evenodd" stroke="currentColor" stroke-width="2"/>',
        onClick: () => {
          miro.board.ui.openLeftSidebar('skenaariopeli/sidebar.html');
        }
      }
    }
  });
  miro.board.ui.openLeftSidebar('skenaariopeli/sidebar.html');
}

function updateViewport() {
  console.log("Debug");
}
