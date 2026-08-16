import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import "../components"

InstallerPage {
    eyebrow: qsTr("System identity")
    title: qsTr("Region and machine name")
    description: qsTr("These settings are written to system.nim and activated consistently in the live session and installed system.")

    GridLayout {
        Layout.fillWidth: true
        Layout.maximumWidth: 650
        columns: 2
        rowSpacing: 16
        columnSpacing: 24

        Label { text: qsTr("System locale"); color: Theme.muted; font.pixelSize: 12 }
        AppComboBox {
            id: localeCombo
            Layout.fillWidth: true
            model: ["en_US.UTF-8", "en_GB.UTF-8", "de_DE.UTF-8", "fr_FR.UTF-8", "es_ES.UTF-8", "it_IT.UTF-8", "pt_BR.UTF-8", "ja_JP.UTF-8", "zh_CN.UTF-8", "bg_BG.UTF-8"]
            Component.onCompleted: {
                var idx = model.indexOf(installerState.locale);
                if (idx >= 0) currentIndex = idx;
            }
            onCurrentTextChanged: installerState.locale = currentText
        }

        Label { text: qsTr("Timezone"); color: Theme.muted; font.pixelSize: 12 }
        AppComboBox {
            id: timezoneCombo
            Layout.fillWidth: true
            model: ["Europe/Sofia", "Europe/Berlin", "Europe/London", "Europe/Paris", "Europe/Madrid", "America/New_York", "America/Los_Angeles", "America/Chicago", "Asia/Tokyo", "Asia/Shanghai", "Australia/Sydney", "UTC"]
            Component.onCompleted: {
                var idx = model.indexOf(installerState.timezone);
                if (idx >= 0) currentIndex = idx;
            }
            onCurrentTextChanged: installerState.timezone = currentText
        }

        Label { text: qsTr("Machine name"); color: Theme.muted; font.pixelSize: 12 }
        AppTextField {
            Layout.fillWidth: true
            text: installerState.hostname
            placeholderText: "reproos"
            onTextChanged: installerState.hostname = text
        }
    }

    Label {
        Layout.maximumWidth: 650
        Layout.fillWidth: true
        text: qsTr("The machine name identifies this installation in logs, shells, and local networking. Use lowercase letters, numbers, and hyphens.")
        color: Theme.subtle
        font.pixelSize: 11
        wrapMode: Text.WordWrap
    }

    Item { Layout.fillHeight: true }
}
