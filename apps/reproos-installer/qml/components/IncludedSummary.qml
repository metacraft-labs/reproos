import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
    id: summary
    property string title
    property string description
    property string status: qsTr("INCLUDED")
    default property alias details: detailRow.data

    implicitHeight: content.implicitHeight

    Rectangle {
        anchors.left: parent.left
        anchors.top: parent.top
        anchors.bottom: parent.bottom
        width: 3
        color: Theme.accent
    }

    ColumnLayout {
        id: content
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.leftMargin: 16
        spacing: 5

        RowLayout {
            Layout.fillWidth: true
            Label {
                Layout.fillWidth: true
                text: summary.title
                color: Theme.text
                font.pixelSize: 15
                font.weight: Font.DemiBold
                elide: Text.ElideRight
            }
            Label {
                text: summary.status
                color: Theme.accent
                font.pixelSize: 10
                font.weight: Font.DemiBold
            }
        }

        Label {
            Layout.fillWidth: true
            text: summary.description
            color: Theme.muted
            font.pixelSize: 12
            lineHeight: 1.2
            wrapMode: Text.WordWrap
        }

        RowLayout {
            id: detailRow
            Layout.fillWidth: true
            Layout.topMargin: 2
            spacing: 22
        }
    }
}
