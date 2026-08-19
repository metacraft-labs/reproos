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
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QStandardPaths>
#include <QtCore/QTimer>
#include <QtCore/QUrl>
#include <QtCore/QDebug>
#include <QtGui/QGuiApplication>
#include <QtGui/QFont>
#include <QtGui/QFontDatabase>
#include <QtGui/QImage>
#include <QtQml/QQmlApplicationEngine>
#include <QtQml/QQmlContext>
#include <QtQuick/QQuickWindow>

#include <memory>

#include "installer_state.h"

int main(int argc, char *argv[]) {
    QCoreApplication::setApplicationName("ReproOS Installer");
    QCoreApplication::setApplicationVersion("0.1.0");
    QCoreApplication::setOrganizationName("ReproOS");
    QCoreApplication::setOrganizationDomain("reproos.org");

    bool coreOnly = false;
    for (int i = 1; i < argc; ++i) {
        const QString argument = QString::fromLocal8Bit(argv[i]);
        if (argument == "--emit-artifacts" ||
            argument.startsWith("--emit-artifacts=") ||
            argument == "--automated" ||
            argument.startsWith("--automated=")) {
            coreOnly = true;
        }
    }
    std::unique_ptr<QCoreApplication> application;
    if (coreOnly) {
        application = std::make_unique<QCoreApplication>(argc, argv);
    } else {
        application = std::make_unique<QGuiApplication>(argc, argv);
        const QString fontFile = qEnvironmentVariable(
            "REPROOS_INSTALLER_FONT_FILE",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf");
        QString fontFamily = QStringLiteral("DejaVu Sans");
        const int fontId = QFontDatabase::addApplicationFont(fontFile);
        if (fontId >= 0) {
            const QStringList families = QFontDatabase::applicationFontFamilies(fontId);
            if (!families.isEmpty())
                fontFamily = families.first();
        }
        QFont applicationFont(fontFamily);
        applicationFont.setStyleHint(QFont::SansSerif);
        static_cast<QGuiApplication *>(application.get())->setFont(applicationFont);
    }

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
        "the source of truth. Smoke harness + first-boot kiosk use this "
        "path.",
        "config-toml");
    QCommandLineOption configOpt(
        "config",
        "Load CONFIG_TOML into the installer without starting an install.",
        "config-toml");
    QCommandLineOption emitArtifactsOpt(
        "emit-artifacts",
        "Write auto-config.toml, system.nim, hardware.nim, disko.json, "
        "and home.nim to DIRECTORY, then exit.",
        "directory");
    QCommandLineOption screenshotOpt(
        "screenshot",
        "Capture the selected wizard screen to OUTPUT_PNG and exit. "
        "Use QT_QPA_PLATFORM=offscreen for unattended capture.",
        "output-png");
    QCommandLineOption previewOpt(
        "preview",
        "Run the complete wizard as a non-destructive desktop preview. "
        "Seeds representative fixture data and simulates install commands.");
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
    parser.addOption(configOpt);
    parser.addOption(emitArtifactsOpt);
    parser.addOption(screenshotOpt);
    parser.addOption(previewOpt);
    parser.addOption(visualScreenOpt);
    parser.addOption(windowSizeOpt);
    parser.process(*application);

    InstallerState state;
    state.setActivitiesTomlPath(parser.value(activitiesOpt));
    const bool previewMode = parser.isSet(previewOpt);
    state.setDryRun(parser.isSet(dryRunOpt) || previewMode);

    if (parser.isSet(screenshotOpt) || previewMode) {
        // Stable, non-destructive defaults keep every visual state meaningful
        // without probing the host. An explicit --config is loaded afterward
        // so interactive preview can inspect real generated configurations.
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
        state.setActiveActivities({});
    }

    if (parser.isSet(configOpt)) {
        QString configError;
        if (!state.loadAutoConfig(parser.value(configOpt), &configError)) {
            qCritical().noquote() << "configuration rejected:" << configError;
            return 2;
        }
    }

    if (parser.isSet(emitArtifactsOpt)) {
        QString artifactError;
        if (!state.writeConfigurationArtifacts(
                parser.value(emitArtifactsOpt), &artifactError)) {
            qCritical().noquote() << "artifact emission failed:"
                                  << artifactError;
            return 3;
        }
        qInfo().noquote() << "configuration artifacts written to"
                          << QFileInfo(parser.value(emitArtifactsOpt))
                                 .absoluteFilePath();
        return 0;
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
    engine.rootContext()->setContextProperty("previewMode", previewMode);

    const QUrl url(QStringLiteral("qrc:/qml/main.qml"));
    QObject::connect(&engine, &QQmlApplicationEngine::objectCreated,
        application.get(),
        [url](QObject *obj, const QUrl &objUrl) {
            if (!obj && url == objUrl) {
                QGuiApplication::exit(-1);
            }
        }, Qt::QueuedConnection);
    engine.load(url);

    if (engine.rootObjects().isEmpty()) {
        qCritical() << "installer has no root window";
        return 2;
    }
    auto *window = qobject_cast<QQuickWindow *>(engine.rootObjects().first());
    if (!window) {
        qCritical() << "installer root is not a QQuickWindow";
        return 2;
    }

    if (parser.isSet(windowSizeOpt) || parser.isSet(screenshotOpt) || previewMode) {
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
    }

    const QString readyFile = qEnvironmentVariable(
        "REPROOS_INSTALLER_READY_FILE");
    if (!readyFile.isEmpty()) {
        QObject::connect(window, &QQuickWindow::frameSwapped,
            application.get(), [readyFile]() {
                QFile marker(readyFile);
                if (!marker.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
                    qWarning() << "failed to publish installer readiness"
                               << readyFile << marker.errorString();
                    return;
                }
                marker.write("REPROOS_INSTALLER_FRAME_READY\n");
                marker.close();
            }, Qt::SingleShotConnection);
    }

    if (parser.isSet(screenshotOpt)) {
        const QString output = QFileInfo(
            parser.value(screenshotOpt)).absoluteFilePath();
        QDir().mkpath(QFileInfo(output).absolutePath());
        QTimer::singleShot(700, application.get(),
            [window, output, app = application.get()]() {
            const QImage image = window->grabWindow();
            if (image.isNull() || !image.save(output, "PNG")) {
                qCritical() << "failed to capture wizard screenshot" << output;
                app->exit(3);
                return;
            }
            qInfo().noquote() << "captured" << output << image.size();
            app->exit(0);
        });
    }

    return application->exec();
}
