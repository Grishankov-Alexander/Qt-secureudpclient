#ifndef ASSOCIATION_H
#define ASSOCIATION_H

#include <QtNetwork>
#include <QtCore>

QT_BEGIN_NAMESPACE
class DtlsAssociation : public QObject
{
    Q_OBJECT

public:
    DtlsAssociation(const QHostAddress &address, quint16 port,
                    const QString &connectionName);
    ~DtlsAssociation();
    void startHandshake();

signals:
    void errorMessage(const QString &message);
    void warningMessage(const QString &message);
    void infoMessage(const QString &message);
    void serverResponse(const QString &clientInfo, const QByteArray &datagram,
                        const QByteArray &plainText);

private slots:
    void udpSocketConnected();
    void readyRead();
    void handshakeTimeout();
    void pskRequired(QSslPreSharedKeyAuthenticator *auth);
    void pingTimeout();

private:
    QString name;
    QUdpSocket socket;
    QDtls crypto;
    QTimer pingTimer;
    unsigned ping = 0;
    Q_DISABLE_COPY(DtlsAssociation)
};

QT_END_NAMESPACE
#endif // ASSOCIATION_H
