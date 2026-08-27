import QtQuick 2.15
import QtQuick.Window 2.15

Window {
    id: desktop
    visible: true
    width: 1280
    height: 800
    title: "ReproOS Desktop"
    color: "#090b0d"

    Rectangle {
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        height: 72
        color: "#20242a"

        Text {
            anchors.left: parent.left
            anchors.leftMargin: 30
            anchors.verticalCenter: parent.verticalCenter
            text: "ReproOS"
            color: "#f5f7fa"
            font.family: "DejaVu Sans"
            font.pixelSize: 25
            font.weight: Font.DemiBold
        }

        Row {
            anchors.right: parent.right
            anchors.rightMargin: 30
            anchors.verticalCenter: parent.verticalCenter
            spacing: 12

            Rectangle {
                anchors.verticalCenter: parent.verticalCenter
                width: 12
                height: 12
                radius: 6
                color: "#43a047"
            }

            Text {
                text: "Ready"
                color: "#dce2e7"
                font.family: "DejaVu Sans"
                font.pixelSize: 17
            }
        }

        Rectangle {
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.bottom: parent.bottom
            height: 4
            color: "#43a047"
        }
    }
}
