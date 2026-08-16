import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    id: card
    property string title
    property string description
    property string meta
    property bool selected: false
    signal chosen()

    implicitHeight: 92
    radius: 6
    color: selected ? Theme.accentSoft : Theme.surface
    border.width: selected ? 2 : 1
    border.color: selected ? Theme.accent : Theme.border

    RowLayout {
        anchors.fill: parent
        anchors.margins: 16
        spacing: 14

        Rectangle {
            Layout.preferredWidth: 22
            Layout.preferredHeight: 22
            radius: 11
            color: card.selected ? Theme.accent : "transparent"
            border.width: card.selected ? 0 : 1
            border.color: Theme.borderStrong

            Rectangle {
                visible: card.selected
                anchors.centerIn: parent
                width: 7
                height: 7
                radius: 4
                color: Theme.accentText
            }
        }

        ColumnLayout {
            Layout.fillWidth: true
            spacing: 3
            RowLayout {
                Layout.fillWidth: true
                Label {
                    Layout.fillWidth: true
                    text: card.title
                    color: Theme.text
                    font.pixelSize: 15
                    font.weight: Font.DemiBold
                }
                Label {
                    visible: card.meta.length > 0
                    text: card.meta
                    color: card.selected ? Theme.accent : Theme.muted
                    font.pixelSize: 11
                    font.weight: Font.DemiBold
                }
            }
            Label {
                Layout.fillWidth: true
                text: card.description
                color: Theme.muted
                font.pixelSize: 12
                lineHeight: 1.2
                wrapMode: Text.WordWrap
            }
        }
    }

    MouseArea {
        anchors.fill: parent
        cursorShape: Qt.PointingHandCursor
        onClicked: card.chosen()
    }
}
