console.log("-- Init Skenaariopeli applogic.js - version 3");

miro.onReady(function() {
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
})
