import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import "../components"

InstallerPage {
    eyebrow: qsTr("Graphical session")
    title: qsTr("Desktop profile")
    description: qsTr("This image includes one desktop whose complete runtime closure is built from source and validated in the boot test.")

    IncludedSummary {
        Layout.fillWidth: true
        Layout.maximumWidth: 760
        title: "Sway"
        description: qsTr("A focused Wayland desktop with keyboard-driven tiling, predictable resource use, and an i3-compatible configuration.")
        Label {
            text: qsTr("Wayland native")
            color: Theme.muted
            font.pixelSize: 12
        }
        Label { text: qsTr("Source-built wlroots"); color: Theme.muted; font.pixelSize: 12 }
        Label { text: qsTr("SDDM login"); color: Theme.muted; font.pixelSize: 12 }
    }

    Label {
        Layout.fillWidth: true
        Layout.maximumWidth: 760
        Layout.topMargin: 8
        text: qsTr("Additional desktops stay hidden until their source package closure and installed-session health checks are complete.")
        color: Theme.muted
        font.pixelSize: 12
        lineHeight: 1.2
        wrapMode: Text.WordWrap
    }

    Item { Layout.fillHeight: true }

    Component.onCompleted: installerState.desktopKind = "sway"
}
