import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import "../components"

InstallerPage {
    id: installPage
    eyebrow: qsTr("Installation")
    title: installerState.installProgress >= 1.0
        ? qsTr("ReproOS is installed") : qsTr("Ready to write the system")
    description: installerState.installRunning
        ? qsTr("Keep the machine powered on while ReproOS writes and verifies the target disk.")
        : qsTr("Starting installation erases the selected disk. Progress and command output remain visible throughout the operation.")

    Connections {
        target: installerState
        function onInstallLogChanged() {
            logArea.text = installerState.installLog;
            logArea.cursorPosition = logArea.length;
        }
    }

    ColumnLayout {
        Layout.fillWidth: true
        spacing: 3
        Label {
            text: installerState.installStatus
            color: Theme.text
            font.pixelSize: 14
            font.weight: Font.DemiBold
        }
        Label {
            text: qsTr("Target: %1").arg(installerState.targetDevice)
            color: Theme.muted
            font.pixelSize: 11
        }
    }

    Rectangle {
        visible: installerState.installProgress <= 0
        Layout.fillWidth: true
        Layout.preferredHeight: 58
        color: Theme.dangerSoft
        radius: 6
        border.width: 1
        border.color: Theme.danger

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: 14
            anchors.rightMargin: 10
            spacing: 14
            Label {
                Layout.fillWidth: true
                text: qsTr("This is the final confirmation. Existing data cannot be recovered.")
                color: Theme.text
                font.pixelSize: 12
                wrapMode: Text.WordWrap
            }
            AppButton {
                danger: true
                text: qsTr("Erase disk and install")
                onClicked: installerState.install()
            }
        }
    }

    ProgressBar {
        visible: installerState.installProgress > 0
            || installerState.installRunning
        Layout.fillWidth: true
        value: installerState.installProgress
        indeterminate: installerState.installRunning
            && installerState.installProgress < 0.05
        palette.highlight: Theme.accent
    }

    RowLayout {
        Layout.fillWidth: true
        Label {
            Layout.fillWidth: true
            text: qsTr("Install output")
            color: Theme.text
            font.pixelSize: 12
            font.weight: Font.DemiBold
        }
        Label {
            text: qsTr("Live log")
            color: Theme.muted
            font.pixelSize: 10
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
                id: logArea
                readOnly: true
                selectByMouse: true
                color: Theme.accent
                font.family: "monospace"
                font.pixelSize: 11
                background: null
                text: installerState.installLog.length > 0
                    ? installerState.installLog
                    : qsTr("Install output will appear here after confirmation.")
                wrapMode: TextEdit.Wrap
            }
        }
    }
}
