import QtQuick
import QtQuick.Controls

ComboBox {
    id: control
    implicitHeight: 44
    leftPadding: 13
    rightPadding: 38
    font.pixelSize: 13

    contentItem: Label {
        text: control.displayText
        color: control.enabled ? Theme.text : Theme.subtle
        font: control.font
        verticalAlignment: Text.AlignVCenter
        elide: Text.ElideRight
    }

    indicator: Label {
        x: control.width - width - 14
        y: (control.height - height) / 2
        text: "v"
        color: Theme.muted
        font.pixelSize: 12
    }

    background: Rectangle {
        radius: 5
        color: Theme.input
        border.width: control.activeFocus ? 2 : 1
        border.color: control.activeFocus ? Theme.accent : Theme.borderStrong
    }

    delegate: ItemDelegate {
        width: control.width
        text: control.textRole.length > 0
            ? model[control.textRole] : modelData
        highlighted: control.highlightedIndex === index
        contentItem: Label {
            text: parent.text
            color: Theme.text
            font.pixelSize: 13
            verticalAlignment: Text.AlignVCenter
        }
        background: Rectangle {
            color: parent.highlighted ? Theme.accentSoft : Theme.surfaceRaised
        }
    }

    popup: Popup {
        y: control.height + 4
        width: control.width
        implicitHeight: Math.min(contentItem.implicitHeight + 2, 320)
        padding: 1
        contentItem: ListView {
            clip: true
            implicitHeight: contentHeight
            model: control.popup.visible ? control.delegateModel : null
            currentIndex: control.highlightedIndex
            ScrollIndicator.vertical: ScrollIndicator { }
        }
        background: Rectangle {
            color: Theme.surfaceRaised
            border.color: Theme.borderStrong
            radius: 5
        }
    }
}
