import QtQuick
import QtQuick.Controls

TextField {
    id: control
    implicitHeight: 44
    leftPadding: 13
    rightPadding: 13
    color: Theme.text
    placeholderTextColor: Theme.subtle
    selectionColor: Theme.accent
    selectedTextColor: Theme.accentText
    font.pixelSize: 13

    background: Rectangle {
        radius: 5
        color: Theme.input
        border.width: control.activeFocus ? 2 : 1
        border.color: control.activeFocus ? Theme.accent : Theme.borderStrong
    }
}
