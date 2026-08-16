// M9.R.18.4 -- ReproOS Installer Qt6/QML entry point.
//
// Per ReproOS-Installer-PRD.md Sec 7.1 the installer is a Qt6 + QML
// application loaded into a single QQmlApplicationEngine. This file
// is the C++ shim PRD Sec 9 Q1 anticipated as the fallback for the
// patchy Nim Qt6 binding landscape -- the logic stays in Nim (via
// the libreproos_installer shared library the Nim recipe builds and
// links here), but the Qt object instantiation is C++.
//
// M9.R.23.5 -- adds the --automated CONFIG_TOML CLI flag that
// bypasses the wizard, loads CONFIG_TOML, and runs install()
// directly. Used by the smoke harness + future first-boot kiosks
// that prefer pre-configured installs.

#include <QtCore/QCommandLineParser>
#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <QtCore/QStandardPaths>
#include <QtCore/QTimer>
#include <QtCore/QUrl>
#include <QtCore/QDebug>
#include <QtGui/QGuiApplication>
#include <QtGui/QImage>
#include <QtQml/QQmlApplicationEngine>
#include <QtQml/QQmlContext>
#include <QtQuick/QQuickWindow>

#include "installer_state.h"

int main(int argc, char *argv[]) {
    QGuiApplication::setApplicationName("ReproOS Installer");
    QGuiApplication::setApplicationVersion("0.1.0");
    QGuiApplication::setOrganizationName("ReproOS");
    QGuiApplication::setOrganizationDomain("reproos.org");

    QGuiApplication app(argc, argv);

    QCommandLineParser parser;
    parser.setApplicationDescription(
        "ReproOS first-boot installer wizard. "
        "See ReproOS-Installer-PRD.md for the user-facing spec.");
    parser.addHelpOption();
    parser.addVersionOption();
    QCommandLineOption activitiesOpt(
        "activities-toml",
        "Path to the activity catalog TOML (default: "
        "/usr/share/reproos-installer/activities.toml).",
        "path",
        "/usr/share/reproos-installer/activities.toml");
    QCommandLineOption dryRunOpt(
        "dry-run",
        "Stop before the destructive install step -- prints the planned "
        "system.nim instead.");
    QCommandLineOption automatedOpt(
        "automated",
        "Skip the wizard + run install() directly using CONFIG_TOML as "
        "the source of truth. The TOML is read with a minimal key=value "
        "parser (no nested tables). Smoke harness + first-boot kiosk "
        "use this path.",
        "config-toml");
    QCommandLineOption screenshotOpt(
        "screenshot",
        "Capture the selected wizard screen to OUTPUT_PNG and exit. "
        "Use QT_QPA_PLATFORM=offscreen for unattended capture.",
        "output-png");
    QCommandLineOption visualScreenOpt(
        "visual-screen",
        "Open a named wizard screen for deterministic visual review.",
        "screen-id",
        "welcome");
    QCommandLineOption windowSizeOpt(
        "window-size",
        "Set the capture window size as WIDTHxHEIGHT.",
        "size",
        "1280x800");
    parser.addOption(activitiesOpt);
    parser.addOption(dryRunOpt);
    parser.addOption(automatedOpt);
    parser.addOption(screenshotOpt);
    parser.addOption(visualScreenOpt);
    parser.addOption(windowSizeOpt);
    parser.process(app);

    InstallerState state;
    state.setActivitiesTomlPath(parser.value(activitiesOpt));
    state.setDryRun(parser.isSet(dryRunOpt));

    if (parser.isSet(screenshotOpt)) {
        // Stable, non-destructive fixture data keeps every visual state
        // meaningful without probing the host or touching a disk.
        state.setHostname("repro-workstation");
        state.setUsername("repro");
        state.setFullName("Repro User");
        state.setPassword("visual-fixture");
        state.setDesktopKind("sway");
        state.setTargetDevice("/dev/vda");
        state.setAvailableDisks({
            "vda 64G VirtIO_System_Disk Red_Hat",
            "sdb 16G ReproOS_Install_Media Metacraft"
        });
        state.setWipeAcknowledged(true);
        state.setActiveActivities({
            "daily-computing", "development", "system-tools"
        });
    }

    if (parser.isSet(automatedOpt)) {
        // Headless install path. main.cpp returns the install() exit
        // code directly without entering the QML event loop.
        const QString cfg = parser.value(automatedOpt);
        const int rc = state.runAutomatedConfig(cfg);
        return rc;
    }

    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty("installerState", &state);
    engine.rootContext()->setContextProperty(
        "startupScreenId", parser.value(visualScreenOpt));
    engine.rootContext()->setContextProperty(
        "visualCaptureMode", parser.isSet(screenshotOpt));

    const QUrl url(QStringLiteral("qrc:/qml/main.qml"));
    QObject::connect(&engine, &QQmlApplicationEngine::objectCreated, &app,
        [url](QObject *obj, const QUrl &objUrl) {
            if (!obj && url == objUrl) {
                QGuiApplication::exit(-1);
            }
        }, Qt::QueuedConnection);
    engine.load(url);

    if (parser.isSet(screenshotOpt)) {
        if (engine.rootObjects().isEmpty()) {
            qCritical() << "screenshot capture has no root window";
            return 2;
        }
        auto *window = qobject_cast<QQuickWindow *>(engine.rootObjects().first());
        if (!window) {
            qCritical() << "screenshot capture root is not a QQuickWindow";
            return 2;
        }

        const QStringList dimensions = parser.value(windowSizeOpt).split('x');
        bool widthOk = false;
        bool heightOk = false;
        const int width = dimensions.value(0).toInt(&widthOk);
        const int height = dimensions.value(1).toInt(&heightOk);
        if (dimensions.size() != 2 || !widthOk || !heightOk ||
            width < 720 || height < 540) {
            qCritical() << "invalid --window-size; expected WIDTHxHEIGHT with"
                        << "minimum 720x540";
            return 2;
        }
        window->setWidth(width);
        window->setHeight(height);

        const QString output = QFileInfo(
            parser.value(screenshotOpt)).absoluteFilePath();
        QDir().mkpath(QFileInfo(output).absolutePath());
        QTimer::singleShot(700, &app, [window, output, &app]() {
            const QImage image = window->grabWindow();
            if (image.isNull() || !image.save(output, "PNG")) {
                qCritical() << "failed to capture wizard screenshot" << output;
                app.exit(3);
                return;
            }
            qInfo().noquote() << "captured" << output << image.size();
            app.exit(0);
        });
    }

    return app.exec();
}
