import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import "../components"

InstallerPage {
    id: diskPage
    eyebrow: qsTr("Destructive operation")
    title: qsTr("Choose the installation disk")
    description: qsTr("The selected disk will be replaced by a source-built ReproOS system. Other disks are left untouched.")

    function pickDevicePath(entry) {
        var parts = entry.trim().split(/\s+/);
        return parts.length > 0 ? "/dev/" + parts[0] : "";
    }

    function formatEntry(entry) {
        var parts = entry.trim().split(/\s+/);
        if (parts.length < 2)
            return entry;
        var detail = parts.slice(2).join(" ").replace(/_/g, " ");
        return "/dev/" + parts[0] + "  -  " + parts[1]
            + (detail.length > 0 ? "  -  " + detail : "");
    }

    RowLayout {
        Layout.fillWidth: true
        spacing: 10
        Label {
            Layout.preferredWidth: 100
            text: qsTr("Target disk")
            color: Theme.muted
            font.pixelSize: 12
        }
        AppComboBox {
            id: diskCombo
            Layout.fillWidth: true
            model: installerState.availableDisks
            displayText: currentText.length > 0
                ? diskPage.formatEntry(currentText)
                : qsTr("No disks detected")
            delegate: ItemDelegate {
                width: diskCombo.width
                text: diskPage.formatEntry(modelData)
                contentItem: Label {
                    text: parent.text
                    color: Theme.text
                    font.pixelSize: 12
                    verticalAlignment: Text.AlignVCenter
                }
                background: Rectangle {
                    color: parent.highlighted ? Theme.accentSoft : Theme.surfaceRaised
                }
            }
            onCurrentTextChanged: {
                if (currentText.length > 0)
                    installerState.targetDevice = diskPage.pickDevicePath(currentText);
            }
            Component.onCompleted: {
                for (var i = 0; i < model.length; ++i) {
                    if (diskPage.pickDevicePath(model[i]) === installerState.targetDevice) {
                        currentIndex = i;
                        break;
                    }
                }
            }
        }
        AppButton {
            text: qsTr("Refresh")
            onClicked: {
                installerState.refreshAvailableDisks();
                diskCombo.currentIndex = 0;
            }
        }
    }

    Label {
        text: qsTr("Disk layout")
        color: Theme.text
        font.pixelSize: 13
        font.weight: Font.DemiBold
        Layout.topMargin: 4
    }

    ChoiceCard {
        Layout.fillWidth: true
        Layout.preferredHeight: 82
        title: qsTr("UEFI + ext4")
        description: qsTr("512 MiB EFI System Partition and one ext4 root filesystem. This is the currently validated unattended-install layout.")
        meta: qsTr("RECOMMENDED")
        selected: true
        onChosen: installerState.diskoPreset = "simple"
    }

    Item { Layout.fillHeight: true }

    Rectangle {
        Layout.fillWidth: true
        Layout.preferredHeight: 72
        radius: 6
        color: Theme.warningSoft
        border.width: 1
        border.color: Theme.warning

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: 16
            anchors.rightMargin: 16
            spacing: 12
            CheckBox {
                checked: installerState.wipeAcknowledged
                onToggled: installerState.wipeAcknowledged = checked
            }
            ColumnLayout {
                Layout.fillWidth: true
                spacing: 2
                Label {
                    text: qsTr("Erase %1 and install ReproOS")
                        .arg(installerState.targetDevice.length > 0
                            ? installerState.targetDevice : qsTr("the selected disk"))
                    color: Theme.text
                    font.pixelSize: 13
                    font.weight: Font.DemiBold
                }
                Label {
                    Layout.fillWidth: true
                    text: qsTr("I understand that all existing partitions and data on this disk will be destroyed.")
                    color: Theme.muted
                    font.pixelSize: 11
                    wrapMode: Text.WordWrap
                }
            }
        }
    }

    Component.onCompleted: {
        installerState.diskoPreset = "simple";
        if (installerState.availableDisks.length === 0)
            installerState.refreshAvailableDisks();
    }
}
