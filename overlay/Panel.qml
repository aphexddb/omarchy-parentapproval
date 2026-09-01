import QtQuick
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import qs.Commons
import qs.Ui

Item {
  id: root

  property var shell: null
  property var manifest: null
  property bool opened: false
  property string user: ""
  property string cmd: ""
  property string match: ""
  property var qrRows: []
  property int qrSize: 0
  property string error: ""

  readonly property color onScrim: "white"
  readonly property color onScrimDim: Qt.rgba(1, 1, 1, 0.55)
  readonly property string fontFamily: Style.font.family

  function applyPayload(payloadJson) {
    var payload = {}
    try { payload = JSON.parse(payloadJson || "{}") || {} } catch (e) { return }
    if (payload.user) root.user = String(payload.user)
    if (payload.cmd) root.cmd = String(payload.cmd)
    if (payload.match) root.match = String(payload.match)
    if (payload.matrix && payload.matrix.length) {
      root.qrRows = payload.matrix
      root.qrSize = payload.matrix.length
    }
  }

  function open(payloadJson) {
    applyPayload(payloadJson)
    root.opened = true
    refresh()
    poll.running = true
    Qt.callLater(function() {
      if (root.opened) keyCatcher.forceActiveFocus()
    })
  }

  function close() {
    root.opened = false
    poll.running = false
    root.qrSize = 0
    root.qrRows = []
    root.match = ""
    root.user = ""
    root.cmd = ""
    root.error = ""
  }

  function dismiss() {
    if (root.shell && typeof root.shell.hide === "function")
      root.shell.hide((root.manifest && root.manifest.id) || "parent.approve")
    else close()
  }

  function refresh() {
    if (!pendingProc.running) pendingProc.running = true
  }

  Timer {
    id: poll
    interval: 400
    repeat: true
    running: false
    onTriggered: root.refresh()
  }

  Process {
    id: pendingProc
    command: ["/usr/bin/parentapproval", "pending", "--json"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        var text = String(this.text || "").trim()
        if (!text) return
        try {
          var data = JSON.parse(text)
          if (!data.rid) {
            if (root.opened) root.dismiss()
            return
          }
          root.user = data.user || ""
          root.cmd = data.cmd || ""
          root.match = data.match || ""
          root.qrRows = data.matrix || []
          root.qrSize = root.qrRows.length
          root.error = ""
        } catch (e) {
          root.error = "Could not read the pending request"
        }
      }
    }
  }

  PanelWindow {
    id: panel
    visible: root.opened
    anchors { top: true; bottom: true; left: true; right: true }
    color: "transparent"
    WlrLayershell.namespace: "omarchy-parent-approve"
    WlrLayershell.layer: WlrLayer.Overlay
    WlrLayershell.keyboardFocus: WlrKeyboardFocus.Exclusive
    exclusionMode: ExclusionMode.Ignore

    Item {
      id: keyCatcher
      anchors.fill: parent
      focus: true
      Keys.onPressed: function(event) {
        if (event.key === Qt.Key_Escape) root.dismiss()
      }
    }

    Rectangle {
      anchors.fill: parent
      color: Qt.rgba(0, 0, 0, 0.78)
      MouseArea { anchors.fill: parent; onClicked: root.dismiss() }
    }

    ColumnLayout {
      anchors.centerIn: parent
      spacing: Style.space(16)
      width: Style.space(320)

      Text {
        text: (root.user || "Kid").toUpperCase() + " WANTS TO RUN"
        color: root.onScrimDim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        font.bold: true
        font.letterSpacing: 2
        Layout.alignment: Qt.AlignHCenter
      }

      Text {
        text: root.cmd
        color: root.onScrim
        font.family: root.fontFamily
        font.pixelSize: Style.font.body
        wrapMode: Text.Wrap
        horizontalAlignment: Text.AlignHCenter
        Layout.fillWidth: true
      }

      Rectangle {
        id: qrCanvas
        visible: root.qrSize > 0
        readonly property int moduleSize: root.qrSize > 0 ? Math.max(3, Math.floor(Style.space(240) / root.qrSize)) : 0
        width: root.qrSize * moduleSize
        height: width
        color: "white"
        radius: Style.cornerRadius
        Layout.alignment: Qt.AlignHCenter

        Grid {
          anchors.fill: parent
          columns: root.qrSize
          Repeater {
            model: root.qrSize * root.qrSize
            Rectangle {
              required property int index
              readonly property int matrixRow: Math.floor(index / root.qrSize)
              readonly property int matrixColumn: index % root.qrSize
              width: qrCanvas.moduleSize
              height: width
              color: (root.qrRows[matrixRow] || "").charAt(matrixColumn) === "1" ? "#111111" : "transparent"
            }
          }
        }
      }

      Text {
        text: "MATCH  " + (root.match || "•••")
        color: "#f5c542"
        font.family: root.fontFamily
        font.pixelSize: Style.font.title
        font.bold: true
        Layout.alignment: Qt.AlignHCenter
      }

      Text {
        text: "Approve on a paired parent phone. This is not a password."
        color: root.onScrimDim
        font.family: root.fontFamily
        font.pixelSize: Style.font.bodySmall
        wrapMode: Text.Wrap
        horizontalAlignment: Text.AlignHCenter
        Layout.fillWidth: true
      }
    }
  }
}
