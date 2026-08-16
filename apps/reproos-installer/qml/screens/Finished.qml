import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import "../components"

InstallerPage {
    eyebrow: qsTr("Installation complete")
    title: qsTr("ReproOS is ready")
    description: qsTr("Remove the installation medium, then reboot into the source-built Sway desktop on the target disk.")

    Rectangle {
        Layout.fillWidth: true
        Layout.maximumWidth: 760
        Layout.preferredHeight: 64
        radius: 6
        color: Theme.accentSoft
        border.width: 1
        border.color: Theme.accent

        RowLayout {
            anchors.fill: parent
            anchors.margins: 14
            Label {
                text: qsTr("HEALTH CHECK")
                color: Theme.accent
                font.pixelSize: 10
                font.weight: Font.DemiBold
            }
            Label {
                Layout.fillWidth: true
                text: qsTr("Configuration written and target unmounted cleanly")
                color: Theme.text
                font.pixelSize: 13
                font.weight: Font.DemiBold
            }
        }
    }

    Label {
        Layout.topMargin: 10
        text: qsTr("Durable configuration")
        color: Theme.text
        font.pixelSize: 14
        font.weight: Font.DemiBold
    }

    GridLayout {
        Layout.fillWidth: true
        Layout.maximumWidth: 760
        columns: 2
        rowSpacing: 10
        columnSpacing: 24

        Label { text: "/etc/repro/system.nim"; color: Theme.text; font.family: "monospace"; font.pixelSize: 12 }
        Label { text: qsTr("System choices and profile imports"); color: Theme.muted; font.pixelSize: 12 }
        Label { text: "/etc/repro/hardware.nim"; color: Theme.text; font.family: "monospace"; font.pixelSize: 12 }
        Label { text: qsTr("Disk and detected hardware"); color: Theme.muted; font.pixelSize: 12 }
        Label { text: "/etc/repro/auto-config.toml"; color: Theme.text; font.family: "monospace"; font.pixelSize: 12 }
        Label { text: qsTr("Replayable unattended-install input"); color: Theme.muted; font.pixelSize: 12 }
    }

    Label {
        Layout.topMargin: 10
        Layout.fillWidth: true
        Layout.maximumWidth: 760
        text: qsTr("After reboot, edit the configuration and run repro infra apply to create the next system generation.")
        color: Theme.muted
        font.pixelSize: 12
        wrapMode: Text.WordWrap
    }

    Item { Layout.fillHeight: true }
}
