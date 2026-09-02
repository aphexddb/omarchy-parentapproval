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
  property string kind: "ask"
  property string user: ""
  property string cmd: ""
  property string match: ""
  property string sid: ""
  property string pairState: ""
  property string pairName: ""
  property bool pairBusy: false
  property var qrRows: []
  property int qrSize: 0
  property string error: ""
  property string verdict: ""
  property real stageOpacity: 1
  readonly property bool pairing: root.kind === "pair"

  readonly property color onScrim: "white"
  readonly property color onScrimDim: Qt.rgba(1, 1, 1, 0.55)
  readonly property string fontFamily: Style.font.family

  function applyPayload(payloadJson) {
    var payload = {}
    try { payload = JSON.parse(payloadJson || "{}") || {} } catch (e) { return }
    if (payload.kind) root.kind = String(payload.kind)
    if (payload.user) root.user = String(payload.user)
    if (payload.cmd) root.cmd = String(payload.cmd)
    if (payload.match) root.match = String(payload.match)
    if (payload.matrix && payload.matrix.length) {
      root.qrRows = payload.matrix
      root.qrSize = payload.matrix.length
    }
    if (payload.result === "allow" || payload.result === "deny")
      root.playVerdict(String(payload.result))
  }

  function open(payloadJson) {
    applyPayload(payloadJson)
    root.opened = true
    if (root.verdict === "") {
      refresh()
      poll.running = true
    }
    Qt.callLater(function() {
      if (root.opened) keyCatcher.forceActiveFocus()
    })
  }

  function close() {
    verdictAnim.stop()
    root.opened = false
    poll.running = false
    root.qrSize = 0
    root.qrRows = []
    root.match = ""
    root.user = ""
    root.cmd = ""
    root.kind = "ask"
    root.sid = ""
    root.pairState = ""
    root.pairName = ""
    root.pairBusy = false
    root.error = ""
    root.verdict = ""
    root.stageOpacity = 1
  }

  function dismiss() {
    if (root.shell && typeof root.shell.hide === "function")
      root.shell.hide((root.manifest && root.manifest.id) || "parentapproval")
    else close()
  }

  function playVerdict(result) {
    if (root.verdict !== "") return
    if (result !== "allow" && result !== "deny") {
      root.dismiss()
      return
    }
    root.verdict = result
    poll.running = false
    verdictAnim.restart()
  }

  function confirmPair() {
    if (root.pairBusy || root.pairState !== "pending_confirm") return
    root.pairBusy = true
    confirmProc.command = root.sid
      ? ["/usr/bin/parentapproval", "pair-confirm", root.sid]
      : ["/usr/bin/parentapproval", "pair-confirm"]
    confirmProc.running = true
  }

  function abortPair() {
    if (root.pairBusy) return
    root.pairBusy = true
    abortProc.command = root.sid
      ? ["/usr/bin/parentapproval", "pair-abort", root.sid]
      : ["/usr/bin/parentapproval", "pair-abort"]
    abortProc.running = true
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

  SequentialAnimation {
    id: verdictAnim
    ParallelAnimation {
      NumberAnimation { target: verdictBadge; property: "opacity"; from: 0; to: 1; duration: 180; easing.type: Easing.OutCubic }
      NumberAnimation { target: verdictBadge; property: "scale"; from: 0.55; to: 1; duration: 280; easing.type: Easing.OutBack }
    }
    PauseAnimation { duration: 650 }
    NumberAnimation { target: root; property: "stageOpacity"; to: 0; duration: 420; easing.type: Easing.InQuad }
    ScriptAction { script: root.dismiss() }
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
          if (data.result === "allow" || data.result === "deny") {
            if (!root.pairing) root.playVerdict(data.result)
            return
          }
          if (data.kind === "pair" || data.sid) {
            root.kind = "pair"
            root.sid = data.sid || ""
            root.pairState = data.state || "waiting"
            root.pairName = data.name || ""
            root.match = data.match || ""
            root.qrRows = data.matrix || []
            root.qrSize = root.qrRows.length
            root.error = ""
            return
          }
          if (!data.rid) {
            if (root.verdict !== "") return
            if (root.kind === "pair") {
              if (root.pairState === "pending_confirm") root.dismiss()
              return
            }
            return
          }
          root.kind = "ask"
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

  Process {
    id: confirmProc
    onExited: function(code) {
      root.pairBusy = false
      if (code === 0) root.dismiss()
      else root.error = "Could not confirm this phone"
    }
  }

  Process {
    id: abortProc
    onExited: function() {
      root.pairBusy = false
      root.dismiss()
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
        if (root.pairing && root.pairState === "pending_confirm" && !root.pairBusy) {
          if (event.key === Qt.Key_Y || event.key === Qt.Key_Return) {
            root.confirmPair()
            event.accepted = true
            return
          }
          if (event.key === Qt.Key_N || event.key === Qt.Key_Escape) {
            root.abortPair()
            event.accepted = true
            return
          }
        }
        if (event.key === Qt.Key_Escape) root.dismiss()
      }
    }

    Item {
      id: stage
      anchors.fill: parent
      opacity: root.stageOpacity

      Rectangle {
        anchors.fill: parent
        color: Qt.rgba(0, 0, 0, 0.78)
        MouseArea { anchors.fill: parent; onClicked: if (!root.pairing && root.verdict === "") root.dismiss() }
      }

      ColumnLayout {
        anchors.centerIn: parent
        spacing: Style.space(16)
        width: Style.space(320)

        Text {
          text: root.pairing
            ? (root.pairState === "pending_confirm" ? "SAME CODE?" : "SCAN TO PAIR")
            : ((root.user || "Kid").toUpperCase() + " WANTS TO RUN")
          color: root.onScrimDim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          font.bold: true
          font.letterSpacing: 2
          Layout.alignment: Qt.AlignHCenter
        }

        Text {
          text: root.pairing
            ? (root.pairState === "pending_confirm"
                ? ((root.pairName || "Phone") + " wants to parent this machine.")
                : "Parent phone only — not the kid's.")
            : root.cmd
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

          Item {
            id: verdictBadge
            anchors.centerIn: parent
            width: parent.width * 0.44
            height: width
            visible: root.verdict !== ""
            opacity: 0
            scale: 0.55

            Rectangle {
              anchors.fill: parent
              radius: width / 2
              color: root.verdict === "allow" ? "#3dd68c" : "#e24b4b"
            }

            Text {
              anchors.centerIn: parent
              text: root.verdict === "allow" ? "✓" : "✕"
              color: root.verdict === "allow" ? "#062016" : "white"
              font.family: root.fontFamily
              font.pixelSize: verdictBadge.width * 0.58
              font.bold: true
            }
          }
        }

        Text {
          text: (root.pairing ? "CODE  " : "MATCH  ") + (root.match || "•••")
          color: "#f5c542"
          font.family: root.fontFamily
          font.pixelSize: Style.font.title
          font.bold: true
          Layout.alignment: Qt.AlignHCenter
        }

        Text {
          text: root.pairing
            ? (root.pairState === "pending_confirm"
                ? "If the phone shows this code, confirm. This is not a password."
                : "The phone must show the same code. This is not a password.")
            : "Approve on a paired parent phone. This is not a password."
          color: root.onScrimDim
          font.family: root.fontFamily
          font.pixelSize: Style.font.bodySmall
          wrapMode: Text.Wrap
          horizontalAlignment: Text.AlignHCenter
          Layout.fillWidth: true
        }

        RowLayout {
          visible: root.pairing && root.pairState === "pending_confirm"
          Layout.alignment: Qt.AlignHCenter
          Layout.fillWidth: true
          spacing: Style.space(12)

          Rectangle {
            Layout.fillWidth: true
            height: Style.space(48)
            radius: Style.cornerRadius
            color: "transparent"
            border.color: root.onScrimDim
            border.width: 1
            opacity: root.pairBusy ? 0.45 : 1
            MouseArea {
              anchors.fill: parent
              enabled: !root.pairBusy
              onClicked: root.abortPair()
            }
            Text {
              anchors.centerIn: parent
              text: "Abort"
              color: root.onScrim
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
              font.bold: true
            }
          }

          Rectangle {
            Layout.fillWidth: true
            height: Style.space(48)
            radius: Style.cornerRadius
            color: "#3dd68c"
            opacity: root.pairBusy ? 0.45 : 1
            MouseArea {
              anchors.fill: parent
              enabled: !root.pairBusy
              onClicked: root.confirmPair()
            }
            Text {
              anchors.centerIn: parent
              text: "Confirm"
              color: "#062016"
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
              font.bold: true
            }
          }
        }
      }
    }
  }
}
