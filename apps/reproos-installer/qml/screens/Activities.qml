import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import "../components"

InstallerPage {
    eyebrow: qsTr("Installed package set")
    title: qsTr("System profile")
    description: qsTr("Profiles add coherent package and service modules. This source image currently validates the base desktop profile end to end.")

    IncludedSummary {
        Layout.fillWidth: true
        Layout.maximumWidth: 760
        title: qsTr("Base desktop")
        description: qsTr("Sway, terminal utilities, networking foundations, system administration tools, and the editable ReproOS configuration surface.")
    }

    ColumnLayout {
        Layout.fillWidth: true
        Layout.maximumWidth: 760
        Layout.topMargin: 8
        spacing: 4
        Label {
            text: qsTr("More profiles")
            color: Theme.text
            font.pixelSize: 13
            font.weight: Font.DemiBold
        }
        Label {
            Layout.fillWidth: true
            text: qsTr("Development, creative, gaming, and office profiles stay hidden until they provision complete source-built package sets.")
            color: Theme.muted
            font.pixelSize: 12
            lineHeight: 1.2
            wrapMode: Text.WordWrap
        }
    }

    Item { Layout.fillHeight: true }

    Component.onCompleted: installerState.activeActivities = []
}
