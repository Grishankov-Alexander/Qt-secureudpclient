#include <QApplication>

#include "mainwindow.h"

int main(int argc, char **argv)
{
    QT_USE_NAMESPACE

    QApplication app(argc, argv);
    MainWindow window;
    window.show();
    return app.exec();
}
