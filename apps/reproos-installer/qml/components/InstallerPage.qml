import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
    id: page
    property string eyebrow
    property string title
    property string description
    default property alias body: content.data
    readonly property int horizontalInset: width < 820 ? 28 : 36

    ColumnLayout {
        anchors.fill: parent
        anchors.leftMargin: page.horizontalInset
        anchors.rightMargin: page.horizontalInset
        anchors.topMargin: width < 820 ? 24 : 28
        anchors.bottomMargin: 20
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
            Layout.topMargin: 7
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
            Layout.topMargin: width < 820 ? 20 : 24
            spacing: 12
        }
    }
}
