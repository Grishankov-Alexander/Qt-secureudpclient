#include "association.h"

QT_BEGIN_NAMESPACE
DtlsAssociation::DtlsAssociation(const QHostAddress &address, quint16 port,
                                 const QString &connectionName)
    : name(connectionName),
      crypto(QSslSocket::SslClientMode)
{
    auto configuration = QSslConfiguration::defaultDtlsConfiguration();
    configuration.setPeerVerifyMode(QSslSocket::VerifyNone);
    crypto.setPeer(address, port);
    crypto.setDtlsConfiguration(configuration);
    connect(&crypto, &QDtls::handshakeTimeout, this, &DtlsAssociation::handshakeTimeout);
    connect(&crypto, &QDtls::pskRequired, this, &DtlsAssociation::pskRequired);
    socket.connectToHost(address.toString(), port);
    connect(&socket, &QUdpSocket::readyRead, this, &DtlsAssociation::readyRead);
    pingTimer.setInterval(5000);
    connect(&pingTimer, &QTimer::timeout, this, &DtlsAssociation::pingTimeout);
}

DtlsAssociation::~DtlsAssociation()
{
    if (crypto.isConnectionEncrypted())
        crypto.shutdown(&socket);
}

void DtlsAssociation::startHandshake()
{
    if (socket.state() != QAbstractSocket::ConnectedState) {
        emit infoMessage(tr("%1: connecting UDP socket first...").arg(name));
        connect(&socket, &QAbstractSocket::connected, this, &DtlsAssociation::udpSocketConnected);
        return;
    }
    if (!crypto.doHandshake(&socket))
        emit errorMessage(tr("%1: failed to start a handshake - %2")
                          .arg(name, crypto.dtlsErrorString()));
    else
        emit infoMessage(tr("%1: starting a handshake").arg(name));
}

void DtlsAssociation::udpSocketConnected()
{
    emit infoMessage(tr("%1: UDP socket is now in connected state, continue with handshake...")
                     .arg(name));
    startHandshake();
}

void DtlsAssociation::readyRead()
{
    QByteArray dgram(socket.pendingDatagramSize(), Qt::Uninitialized);
    const qint64 bytesRead = socket.readDatagram(dgram.data(), dgram.size());
    if (bytesRead <= 0) {
        emit warningMessage(tr("%1: spurious read notification?").arg(name));
        return;
    }
    dgram.resize(bytesRead);
    if (crypto.isConnectionEncrypted()) {
        const QByteArray plainText = crypto.decryptDatagram(&socket, dgram);
        if (plainText.size()) {
            emit serverResponse(name, dgram, plainText);
            return;
        }
        if (crypto.dtlsError() == QDtlsError::RemoteClosedConnectionError) {
            emit errorMessage(tr("%1: shutdown alert received").arg(name));
            socket.close();
            pingTimer.stop();
            return;
        }
        emit warningMessage(tr("%1: zero-length datagram received?").arg(name));
    } else {
        if (!crypto.doHandshake(&socket, dgram)) {
            emit errorMessage(tr("%1: handshake error - %2")
                              .arg(name, crypto.dtlsErrorString()));
            return;
        }
        if (crypto.isConnectionEncrypted()) {
            emit infoMessage(tr("%1: encrypted connection established!").arg(name));
            pingTimer.start();
            pingTimeout();
        } else
            emit infoMessage(tr("%1: continuing with handshake...").arg(name));
    }
}

void DtlsAssociation::handshakeTimeout()
{
    emit warningMessage(tr("%1: handshake timeout, trying to re-transmit").arg(name));
    if (!crypto.handleTimeout(&socket))
        emit errorMessage(tr("%1: failed to re-transmit - %2")
                          .arg(name, crypto.dtlsErrorString()));
}

void DtlsAssociation::pskRequired(QSslPreSharedKeyAuthenticator *auth)
{
    Q_ASSERT(auth);
    emit infoMessage(tr("%1: providing pre-shared key...").arg(name));
    auth->setIdentity(name.toLatin1());
    auth->setPreSharedKey(QByteArrayLiteral("\x1a\x2b\x3c\x4d\x5e\x6f"));
}

void DtlsAssociation::pingTimeout()
{
    static const QString message = QStringLiteral("I am %1, please, accept our ping %2");
    const qint64 written = crypto.writeDatagramEncrypted(&socket, message.arg(name).arg(ping).toLatin1());
    if (written <= 0) {
        emit errorMessage(tr("%1: failed to send a ping - %2")
                          .arg(name, crypto.dtlsErrorString()));
        pingTimer.stop();
        return;
    }
    ++ping;
}

QT_END_NAMESPACE
