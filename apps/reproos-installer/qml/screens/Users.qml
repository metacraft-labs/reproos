import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import "../components"

InstallerPage {
    eyebrow: qsTr("Primary account")
    title: qsTr("Create your user")
    description: qsTr("Create the local account used to sign in and administer this ReproOS system.")

    GridLayout {
        Layout.fillWidth: true
        Layout.maximumWidth: 760
        columns: 2
        rowSpacing: 13
        columnSpacing: 24

        Label { Layout.preferredWidth: 130; text: qsTr("Full name"); color: Theme.muted; font.pixelSize: 12 }
        AppTextField {
            Layout.fillWidth: true
            text: installerState.fullName
            placeholderText: qsTr("Repro User")
            onTextChanged: installerState.fullName = text
        }

        Label { Layout.preferredWidth: 130; text: qsTr("Username"); color: Theme.muted; font.pixelSize: 12 }
        AppTextField {
            Layout.fillWidth: true
            text: installerState.username
            placeholderText: "repro"
            validator: RegularExpressionValidator { regularExpression: /^[a-z][a-z0-9_-]*$/ }
            onTextChanged: installerState.username = text
        }

        Label { Layout.preferredWidth: 130; text: qsTr("Password"); color: Theme.muted; font.pixelSize: 12 }
        AppTextField {
            Layout.fillWidth: true
            echoMode: TextInput.Password
            text: installerState.password
            placeholderText: qsTr("Choose a password")
            onTextChanged: installerState.password = text
        }

        Label { Layout.preferredWidth: 130; text: qsTr("Confirm password"); color: Theme.muted; font.pixelSize: 12 }
        AppTextField {
            id: confirmField
            Layout.fillWidth: true
            echoMode: TextInput.Password
            placeholderText: qsTr("Type the password again")
        }

        Item { Layout.preferredWidth: 1; Layout.preferredHeight: 1 }
        Label {
            Layout.fillWidth: true
            Layout.preferredHeight: 18
            opacity: confirmField.text.length > 0
                && confirmField.text !== installerState.password ? 1 : 0
            text: qsTr("Passwords do not match")
            color: Theme.danger
            font.pixelSize: 11
        }

        Item { Layout.preferredWidth: 1; Layout.preferredHeight: 1 }
        CheckBox {
            checked: installerState.isAdmin
            text: qsTr("Allow this user to administer the system")
            palette.windowText: Theme.text
            onToggled: installerState.isAdmin = checked
        }
    }

    Item { Layout.fillHeight: true }
}
