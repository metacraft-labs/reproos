import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
    id: page
    property string eyebrow
    property string title
    property string description
    default property alias body: content.data

    ColumnLayout {
        anchors.fill: parent
        anchors.leftMargin: 36
        anchors.rightMargin: 36
        anchors.topMargin: 28
        anchors.bottomMargin: 24
        spacing: 0

        Label {
            visible: page.eyebrow.length > 0
            text: page.eyebrow.toUpperCase()
            color: Theme.accent
            font.pixelSize: 10
            font.weight: Font.DemiBold
            font.letterSpacing: 0
        }

        Label {
            Layout.topMargin: page.eyebrow.length > 0 ? 6 : 0
            text: page.title
            color: Theme.text
            font.pixelSize: 27
            font.weight: Font.DemiBold
        }

        Label {
            Layout.topMargin: 8
            Layout.fillWidth: true
            Layout.maximumWidth: 760
            text: page.description
            color: Theme.muted
            font.pixelSize: 13
            lineHeight: 1.25
            wrapMode: Text.WordWrap
        }

        ColumnLayout {
            id: content
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.topMargin: 24
            spacing: 14
        }
    }
}
