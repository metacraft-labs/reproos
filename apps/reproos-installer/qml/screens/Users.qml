import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import "../components"

InstallerPage {
    eyebrow: qsTr("Primary account")
    title: qsTr("Create your user")
    description: qsTr("ReproOS creates one local account now. Additional users remain ordinary system.nim configuration after installation.")

    GridLayout {
        Layout.fillWidth: true
        Layout.maximumWidth: 680
        columns: 2
        rowSpacing: 13
        columnSpacing: 24

        Label { text: qsTr("Full name"); color: Theme.muted; font.pixelSize: 12 }
        AppTextField {
            Layout.fillWidth: true
            text: installerState.fullName
            placeholderText: qsTr("Repro User")
            onTextChanged: installerState.fullName = text
        }

        Label { text: qsTr("Username"); color: Theme.muted; font.pixelSize: 12 }
        AppTextField {
            Layout.fillWidth: true
            text: installerState.username
            placeholderText: "repro"
            validator: RegularExpressionValidator { regularExpression: /^[a-z][a-z0-9_-]*$/ }
            onTextChanged: installerState.username = text
        }

        Label { text: qsTr("Password"); color: Theme.muted; font.pixelSize: 12 }
        AppTextField {
            Layout.fillWidth: true
            echoMode: TextInput.Password
            text: installerState.password
            placeholderText: qsTr("Choose a password")
            onTextChanged: installerState.password = text
        }

        Label { text: qsTr("Confirm password"); color: Theme.muted; font.pixelSize: 12 }
        AppTextField {
            id: confirmField
            Layout.fillWidth: true
            echoMode: TextInput.Password
            placeholderText: qsTr("Type the password again")
        }

        Item { Layout.preferredWidth: 1; Layout.preferredHeight: 1 }
        CheckBox {
            checked: installerState.isAdmin
            text: qsTr("Allow this user to administer the system")
            palette.windowText: Theme.text
            onToggled: installerState.isAdmin = checked
        }
    }

    Label {
        Layout.leftMargin: 154
        Layout.preferredHeight: 18
        visible: confirmField.text.length > 0
            && confirmField.text !== installerState.password
        text: qsTr("Passwords do not match")
        color: Theme.danger
        font.pixelSize: 11
    }

    Item { Layout.fillHeight: true }
}
