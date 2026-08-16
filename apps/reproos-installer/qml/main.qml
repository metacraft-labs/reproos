import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import "components"

ApplicationWindow {
    id: window
    visible: true
    width: 1180
    height: 760
    minimumWidth: 900
    minimumHeight: 640
    title: qsTr("ReproOS Installer")
    color: Theme.canvas

    palette.window: Theme.canvas
    palette.windowText: Theme.text
    palette.button: Theme.surfaceRaised
    palette.buttonText: Theme.text
    palette.highlight: Theme.accent
    palette.highlightedText: Theme.accentText
    palette.text: Theme.text
    palette.base: Theme.input

    readonly property var screens: [
        { id: "welcome", file: "Welcome.qml", title: qsTr("Welcome") },
        { id: "locale", file: "Locale.qml", title: qsTr("Region") },
        { id: "keyboard", file: "Keyboard.qml", title: qsTr("Keyboard") },
        { id: "users", file: "Users.qml", title: qsTr("Account") },
        { id: "disk", file: "Disk.qml", title: qsTr("Storage") },
        { id: "deSelect", file: "DeSelect.qml", title: qsTr("Desktop") },
        { id: "activities", file: "Activities.qml", title: qsTr("Profile") },
        { id: "summary", file: "Summary.qml", title: qsTr("Review") },
        { id: "install", file: "Install.qml", title: qsTr("Install") },
        { id: "finished", file: "Finished.qml", title: qsTr("Complete") }
    ]

    property int currentScreenIndex: 0

    function gotoScreenIndex(idx) {
        if (idx < 0 || idx >= screens.length)
            return;
        currentScreenIndex = idx;
        stack.clear();
        stack.push(Qt.resolvedUrl("screens/" + screens[idx].file));
    }

    function nextScreen() {
        if (currentScreenIndex < screens.length - 1)
            gotoScreenIndex(currentScreenIndex + 1);
    }

    function prevScreen() {
        if (currentScreenIndex > 0)
            gotoScreenIndex(currentScreenIndex - 1);
    }

    function canContinue() {
        if (currentScreenIndex === 4) {
            return installerState.targetDevice.length > 0
                && installerState.wipeAcknowledged
                && installerState.diskoPreset === "simple";
        }
        if (currentScreenIndex === 8)
            return installerState.installProgress >= 1.0;
        return true;
    }

    Component.onCompleted: {
        var requestedIndex = 0;
        if (typeof startupScreenId !== "undefined" && startupScreenId.length > 0) {
            for (var i = 0; i < screens.length; ++i) {
                if (screens[i].id === startupScreenId) {
                    requestedIndex = i;
                    break;
                }
            }
        }
        gotoScreenIndex(requestedIndex);
    }

    RowLayout {
        anchors.fill: parent
        spacing: 0

        Rectangle {
            Layout.preferredWidth: window.width < 1040 ? 190 : 228
            Layout.fillHeight: true
            color: Theme.sidebar

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: 24
                spacing: 0

                RowLayout {
                    Layout.fillWidth: true
                    spacing: 12

                    Rectangle {
                        Layout.preferredWidth: 34
                        Layout.preferredHeight: 34
                        radius: 6
                        color: Theme.accent

                        Label {
                            anchors.centerIn: parent
                            text: "R"
                            color: Theme.accentText
                            font.pixelSize: 18
                            font.weight: Font.DemiBold
                        }
                    }

                    ColumnLayout {
                        spacing: 0
                        Label {
                            text: "ReproOS"
                            color: Theme.text
                            font.pixelSize: 20
                            font.weight: Font.DemiBold
                        }
                        Label {
                            text: qsTr("INSTALLER")
                            color: Theme.muted
                            font.pixelSize: 10
                            font.letterSpacing: 0
                        }
                    }
                }

                Label {
                    Layout.topMargin: 32
                    Layout.bottomMargin: 10
                    text: qsTr("SETUP PROGRESS")
                    color: Theme.subtle
                    font.pixelSize: 10
                    font.weight: Font.DemiBold
                    font.letterSpacing: 0
                }

                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 2

                    Repeater {
                        model: window.screens

                        delegate: Rectangle {
                            required property var modelData
                            required property int index
                            Layout.fillWidth: true
                            Layout.preferredHeight: 42
                            radius: 5
                            color: index === window.currentScreenIndex
                                ? Theme.surfaceRaised : "transparent"

                            RowLayout {
                                anchors.fill: parent
                                anchors.leftMargin: 10
                                anchors.rightMargin: 8
                                spacing: 10

                                Rectangle {
                                    Layout.preferredWidth: 22
                                    Layout.preferredHeight: 22
                                    radius: 11
                                    color: index < window.currentScreenIndex
                                        ? Theme.accent
                                        : index === window.currentScreenIndex
                                            ? Theme.accentSoft : "transparent"
                                    border.width: index >= window.currentScreenIndex ? 1 : 0
                                    border.color: index === window.currentScreenIndex
                                        ? Theme.accent : Theme.border

                                    Label {
                                        anchors.centerIn: parent
                                        text: index < window.currentScreenIndex ? "ok" : String(index + 1)
                                        color: index < window.currentScreenIndex
                                            ? Theme.accentText
                                            : index === window.currentScreenIndex
                                                ? Theme.accent : Theme.subtle
                                        font.pixelSize: index < window.currentScreenIndex ? 8 : 11
                                        font.weight: Font.DemiBold
                                    }
                                }

                                Label {
                                    Layout.fillWidth: true
                                    text: modelData.title
                                    color: index === window.currentScreenIndex
                                        ? Theme.text : Theme.muted
                                    font.pixelSize: 13
                                    font.weight: index === window.currentScreenIndex
                                        ? Font.DemiBold : Font.Normal
                                }
                            }
                        }
                    }
                }

                Item { Layout.fillHeight: true }

                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 2
                    Label {
                        text: qsTr("SOURCE BUILD")
                        color: Theme.accent
                        font.pixelSize: 10
                        font.weight: Font.DemiBold
                    }
                    Label {
                        Layout.fillWidth: true
                        text: qsTr("Editable configuration")
                        color: Theme.muted
                        font.pixelSize: 11
                        wrapMode: Text.WordWrap
                    }
                }
            }
        }

        ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 0

            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 68
                color: Theme.canvas

                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: window.width < 1040 ? 28 : 36
                    anchors.rightMargin: window.width < 1040 ? 28 : 36

                    Label {
                        Layout.fillWidth: true
                        text: window.screens[window.currentScreenIndex].title
                        color: Theme.text
                        font.pixelSize: 15
                        font.weight: Font.DemiBold
                    }
                    Label {
                        text: qsTr("%1 / %2")
                            .arg(window.currentScreenIndex + 1)
                            .arg(window.screens.length)
                        color: Theme.muted
                        font.pixelSize: 12
                    }
                }

                Rectangle {
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.bottom: parent.bottom
                    height: 1
                    color: Theme.border
                }
            }

            StackView {
                id: stack
                Layout.fillWidth: true
                Layout.fillHeight: true
                background: Rectangle { color: Theme.canvas }
            }

            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 76
                color: Theme.canvas

                Rectangle {
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.top: parent.top
                    height: 1
                    color: Theme.border
                }

                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: window.width < 1040 ? 28 : 36
                    anchors.rightMargin: window.width < 1040 ? 28 : 36
                    spacing: 12

                    AppButton {
                        text: qsTr("Back")
                        enabled: window.currentScreenIndex > 0
                            && window.currentScreenIndex < 9
                            && !installerState.installRunning
                        onClicked: window.prevScreen()
                    }

                    Item { Layout.fillWidth: true }

                    Label {
                        visible: window.currentScreenIndex === 4
                            && !window.canContinue()
                        text: qsTr("Select a disk and acknowledge the wipe")
                        color: Theme.warning
                        font.pixelSize: 11
                    }

                    AppButton {
                        primary: true
                        text: window.currentScreenIndex === 7
                            ? qsTr("Continue to install")
                            : window.currentScreenIndex === 8
                                ? qsTr("Continue")
                                : window.currentScreenIndex === 9
                                    ? qsTr("Reboot") : qsTr("Continue")
                        enabled: window.canContinue()
                        onClicked: {
                            if (window.currentScreenIndex === 9)
                                Qt.quit();
                            else
                                window.nextScreen();
                        }
                    }
                }
            }
        }
    }
}
