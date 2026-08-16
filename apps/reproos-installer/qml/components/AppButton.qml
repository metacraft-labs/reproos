import QtQuick
import QtQuick.Controls

Button {
    id: control
    property bool primary: false
    property bool danger: false

    implicitHeight: 42
    implicitWidth: Math.max(104, contentItem.implicitWidth + 32)
    leftPadding: 16
    rightPadding: 16

    contentItem: Label {
        text: control.text
        color: !control.enabled ? Theme.subtle
            : control.primary ? Theme.accentText
            : control.danger ? Theme.danger : Theme.text
        font.pixelSize: 13
        font.weight: control.primary ? Font.DemiBold : Font.Medium
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
    }

    background: Rectangle {
        radius: 6
        color: !control.enabled ? Theme.surface
            : control.primary
                ? (control.hovered ? Theme.accentHover : Theme.accent)
                : control.danger ? Theme.dangerSoft
                : control.hovered ? Theme.surfaceRaised : Theme.surface
        border.width: control.primary ? 0 : 1
        border.color: control.danger ? Theme.danger : Theme.borderStrong
    }
}
