import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import "../components"

InstallerPage {
    eyebrow: qsTr("A reproducible desktop operating system")
    title: "ReproOS"
    description: qsTr("Build a transparent system configuration, install it once, and keep every choice editable after first boot.")

    RowLayout {
        Layout.fillWidth: true
        Layout.maximumWidth: 820
        spacing: 28

        ColumnLayout {
            Layout.fillWidth: true
            spacing: 14

            Label {
                text: qsTr("Standard configuration")
                color: Theme.text
                font.pixelSize: 17
                font.weight: Font.DemiBold
            }
            Label {
                Layout.fillWidth: true
                text: qsTr("Choose your region, account, target disk, and desktop profile. Before installation, ReproOS shows the exact declarative configuration it will write.")
                color: Theme.muted
                font.pixelSize: 13
                lineHeight: 1.3
                wrapMode: Text.WordWrap
            }
            RowLayout {
                spacing: 18
                Label {
                    text: qsTr("10 focused steps")
                    color: Theme.accent
                    font.pixelSize: 12
                    font.weight: Font.DemiBold
                }
                Label {
                    text: qsTr("Backtrack until install")
                    color: Theme.muted
                    font.pixelSize: 12
                }
            }
        }

        Rectangle {
            Layout.preferredWidth: 1
            Layout.preferredHeight: 142
            color: Theme.border
        }

        ColumnLayout {
            Layout.preferredWidth: 290
            spacing: 10

            Label {
                text: qsTr("Existing configuration")
                color: Theme.text
                font.pixelSize: 15
                font.weight: Font.DemiBold
            }
            Label {
                Layout.fillWidth: true
                text: qsTr("Restore from USB and Git are not available in this source build yet. No disabled action is required to continue.")
                color: Theme.muted
                font.pixelSize: 12
                lineHeight: 1.25
                wrapMode: Text.WordWrap
            }
            Label {
                text: qsTr("Status: planned")
                color: Theme.warning
                font.pixelSize: 11
                font.weight: Font.DemiBold
            }
        }
    }

    Item { Layout.fillHeight: true }

    Rectangle {
        Layout.fillWidth: true
        Layout.preferredHeight: 58
        radius: 6
        color: Theme.surface
        border.width: 1
        border.color: Theme.border

        RowLayout {
            anchors.fill: parent
            anchors.margins: 14
            spacing: 12
            Label {
                text: qsTr("CONFIGURATION FIRST")
                color: Theme.accent
                font.pixelSize: 10
                font.weight: Font.DemiBold
            }
            Label {
                Layout.fillWidth: true
                text: qsTr("The installer produces system.nim, hardware.nim, and an unattended install configuration.")
                color: Theme.muted
                font.pixelSize: 12
                elide: Text.ElideRight
            }
        }
    }
}
