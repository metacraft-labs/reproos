import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import "../components"

InstallerPage {
    eyebrow: qsTr("Input")
    title: qsTr("Keyboard layout")
    description: qsTr("Select the layout used by the live session, the login screen, and the installed desktop.")

    RowLayout {
        Layout.fillWidth: true
        Layout.maximumWidth: 650
        spacing: 24
        Label {
            Layout.preferredWidth: 130
            text: qsTr("Layout")
            color: Theme.muted
            font.pixelSize: 12
        }
        AppComboBox {
            id: layoutCombo
            Layout.fillWidth: true
            model: [
                { display: qsTr("English (US)"), code: "us" },
                { display: qsTr("English (US, international)"), code: "us-intl" },
                { display: qsTr("English (UK)"), code: "gb" },
                { display: qsTr("German"), code: "de" },
                { display: qsTr("French"), code: "fr" },
                { display: qsTr("Spanish"), code: "es" },
                { display: qsTr("Italian"), code: "it" },
                { display: qsTr("Bulgarian (BDS)"), code: "bg" },
                { display: qsTr("Russian"), code: "ru" },
                { display: qsTr("Japanese"), code: "jp" },
                { display: qsTr("Dvorak"), code: "us-dvorak" },
                { display: qsTr("Colemak"), code: "us-colemak" }
            ]
            textRole: "display"
            Component.onCompleted: {
                for (var i = 0; i < model.length; ++i) {
                    if (model[i].code === installerState.keymap) {
                        currentIndex = i;
                        return;
                    }
                }
            }
            onCurrentIndexChanged: {
                if (currentIndex >= 0)
                    installerState.keymap = model[currentIndex].code;
            }
        }
    }

    ColumnLayout {
        Layout.fillWidth: true
        Layout.maximumWidth: 760
        Layout.topMargin: 14
        spacing: 8
        Label {
            text: qsTr("Test the selected layout")
            color: Theme.text
            font.pixelSize: 13
            font.weight: Font.DemiBold
        }
        AppTextField {
            Layout.fillWidth: true
            placeholderText: qsTr("Type letters, numbers, and symbols here")
        }
        Label {
            text: qsTr("Nothing typed here is saved.")
            color: Theme.subtle
            font.pixelSize: 11
        }
    }

    Item { Layout.fillHeight: true }
}
