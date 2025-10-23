#ifndef PROXYBEAN_H
#define PROXYBEAN_H

#include <QString>
#include <QJsonObject>

class ProxyBean {
public:
    QString type;
    QString name;
    QString serverAddress;
    int serverPort = 0;

    virtual ~ProxyBean() = default;
    virtual bool TryParseLink(const QString &link) = 0;
    virtual QJsonObject ToJson() = 0;
};

class VMessBean : public ProxyBean {
public:
    QString uuid;
    int aid = 0;
    QString security = "auto";
    QString network = "tcp";
    QString tls = "";
    QString sni = "";
    QString host = "";
    QString path = "";

    bool TryParseLink(const QString &link) override;
    QJsonObject ToJson() override;
};

class ShadowSocksBean : public ProxyBean {
public:
    QString method;
    QString password;

    bool TryParseLink(const QString &link) override;
    QJsonObject ToJson() override;
};

class TrojanVLESSBean : public ProxyBean {
public:
    QString password;
    QString flow = "";
    QString network = "tcp";
    QString security = "";
    QString sni = "";
    QString host = "";
    QString path = "";

    bool TryParseLink(const QString &link) override;
    QJsonObject ToJson() override;
};

class SocksHttpBean : public ProxyBean {
public:
    QString username;
    QString password;

    bool TryParseLink(const QString &link) override;
    QJsonObject ToJson() override;
};

#endif // PROXYBEAN_H