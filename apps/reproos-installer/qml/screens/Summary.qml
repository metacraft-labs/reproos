import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import "../components"

InstallerPage {
    eyebrow: qsTr("Final confirmation")
    title: qsTr("Review the installation")
    description: qsTr("Confirm the destination and account before entering the destructive install stage.")

    RowLayout {
        Layout.fillWidth: true
        spacing: 10

        Repeater {
            model: [
                { label: qsTr("TARGET"), value: installerState.targetDevice.length > 0 ? installerState.targetDevice : qsTr("Not selected") },
                { label: qsTr("ACCOUNT"), value: installerState.username },
                { label: qsTr("DESKTOP"), value: "Sway" }
            ]
            delegate: Rectangle {
                required property var modelData
                Layout.fillWidth: true
                Layout.preferredHeight: 62
                radius: 6
                color: Theme.surface
                border.width: 1
                border.color: modelData.label === qsTr("TARGET")
                    ? Theme.warning : Theme.border
                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 10
                    spacing: 2
                    Label {
                        text: modelData.label
                        color: Theme.subtle
                        font.pixelSize: 9
                        font.weight: Font.DemiBold
                    }
                    Label {
                        Layout.fillWidth: true
                        text: modelData.value
                        color: Theme.text
                        font.pixelSize: 13
                        font.weight: Font.DemiBold
                        elide: Text.ElideRight
                    }
                }
            }
        }
    }

    RowLayout {
        Layout.fillWidth: true
        Layout.topMargin: 2
        Label {
            Layout.fillWidth: true
            text: qsTr("Generated system.nim")
            color: Theme.text
            font.pixelSize: 13
            font.weight: Font.DemiBold
        }
        Label {
            text: qsTr("Editable after installation")
            color: Theme.accent
            font.pixelSize: 11
        }
    }

    Rectangle {
        Layout.fillWidth: true
        Layout.fillHeight: true
        radius: 6
        color: Theme.input
        border.width: 1
        border.color: Theme.border

        ScrollView {
            anchors.fill: parent
            anchors.margins: 10
            clip: true
            TextArea {
                id: previewArea
                readOnly: true
                selectByMouse: true
                color: Theme.text
                font.family: "monospace"
                font.pixelSize: 11
                background: null
                text: installerState.renderSystemNim()

                Connections {
                    target: installerState
                    function refresh() { previewArea.text = installerState.renderSystemNim(); }
                    function onHostnameChanged() { refresh(); }
                    function onLocaleChanged() { refresh(); }
                    function onTimezoneChanged() { refresh(); }
                    function onKeymapChanged() { refresh(); }
                    function onUsernameChanged() { refresh(); }
                    function onFullNameChanged() { refresh(); }
                    function onIsAdminChanged() { refresh(); }
                    function onDesktopKindChanged() { refresh(); }
                    function onActiveActivitiesChanged() { refresh(); }
                }
            }
        }
    }
}
