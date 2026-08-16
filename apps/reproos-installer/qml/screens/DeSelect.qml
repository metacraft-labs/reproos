import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import "../components"

InstallerPage {
    eyebrow: qsTr("Graphical session")
    title: qsTr("Desktop profile")
    description: qsTr("This image includes one desktop whose complete runtime closure is built from source and validated in the boot test.")

    ChoiceCard {
        Layout.fillWidth: true
        Layout.maximumWidth: 760
        Layout.preferredHeight: 112
        title: "Sway"
        description: qsTr("A focused Wayland desktop with keyboard-driven tiling, predictable resource use, and an i3-compatible configuration.")
        meta: qsTr("INCLUDED")
        selected: true
        onChosen: installerState.desktopKind = "sway"
    }

    RowLayout {
        Layout.fillWidth: true
        Layout.maximumWidth: 760
        spacing: 28
        Label {
            text: qsTr("Wayland native")
            color: Theme.accent
            font.pixelSize: 12
            font.weight: Font.DemiBold
        }
        Label { text: qsTr("Source-built wlroots"); color: Theme.muted; font.pixelSize: 12 }
        Label { text: qsTr("SDDM login"); color: Theme.muted; font.pixelSize: 12 }
    }

    Rectangle {
        Layout.fillWidth: true
        Layout.maximumWidth: 760
        Layout.preferredHeight: 66
        Layout.topMargin: 8
        radius: 6
        color: Theme.surface
        border.width: 1
        border.color: Theme.border
        Label {
            anchors.fill: parent
            anchors.margins: 14
            text: qsTr("Additional desktop profiles will appear here only after their complete source package closure and installed-session health checks are available.")
            color: Theme.muted
            font.pixelSize: 12
            lineHeight: 1.2
            wrapMode: Text.WordWrap
            verticalAlignment: Text.AlignVCenter
        }
    }

    Item { Layout.fillHeight: true }

    Component.onCompleted: installerState.desktopKind = "sway"
}
