import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import "../components"

InstallerPage {
    eyebrow: qsTr("Installed package set")
    title: qsTr("System profile")
    description: qsTr("Profiles add coherent package and service modules. This source image currently validates the base desktop profile end to end.")

    ChoiceCard {
        Layout.fillWidth: true
        Layout.maximumWidth: 760
        Layout.preferredHeight: 112
        title: qsTr("Base desktop")
        description: qsTr("Sway, terminal utilities, networking foundations, system administration tools, and the editable ReproOS configuration surface.")
        meta: qsTr("INCLUDED")
        selected: true
    }

    Rectangle {
        Layout.fillWidth: true
        Layout.maximumWidth: 760
        Layout.preferredHeight: 86
        Layout.topMargin: 8
        radius: 6
        color: Theme.surface
        border.width: 1
        border.color: Theme.border

        ColumnLayout {
            anchors.fill: parent
            anchors.margins: 14
            spacing: 4
            Label {
                text: qsTr("Activity catalog")
                color: Theme.text
                font.pixelSize: 13
                font.weight: Font.DemiBold
            }
            Label {
                Layout.fillWidth: true
                text: qsTr("Development, creative, gaming, and office profiles remain hidden until their modules provision real source-built packages in the installed image.")
                color: Theme.muted
                font.pixelSize: 12
                lineHeight: 1.2
                wrapMode: Text.WordWrap
            }
        }
    }

    Item { Layout.fillHeight: true }

    Component.onCompleted: installerState.activeActivities = []
}
