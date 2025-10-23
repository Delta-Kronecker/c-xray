#include "../include/ProxyBean.h"
#include "../include/Utils.h"
#include <QUrl>
#include <QUrlQuery>

// VMess Parser
bool VMessBean::TryParseLink(const QString &link) {
    type = "vmess";

    // V2RayN Format (Base64 encoded JSON)
    auto linkN = DecodeB64IfValid(SubStrAfter(link, "vmess://"));
    if (!linkN.isEmpty()) {
        auto objN = QString2QJsonObject(linkN);
        if (objN.isEmpty()) return false;

        uuid = objN["id"].toString();
        serverAddress = objN["add"].toString();
        serverPort = objN["port"].toVariant().toInt();
        name = objN["ps"].toString();
        aid = objN["aid"].toVariant().toInt();
        host = objN["host"].toString();
        path = objN["path"].toString();
        sni = objN["sni"].toString();
        network = objN["net"].toString();
        tls = objN["tls"].toString();

        return true;
    }

    // Standard format
    auto url = QUrl(link);
    if (!url.isValid()) return false;
    auto query = GetQuery(url);

    name = url.fragment(QUrl::FullyDecoded);
    serverAddress = url.host();
    serverPort = url.port();
    uuid = url.userName();

    security = GetQueryValue(query, "encryption", "auto");
    network = GetQueryValue(query, "type", "tcp");
    tls = GetQueryValue(query, "security", "");
    sni = GetQueryValue(query, "sni");

    if (network == "ws") {
        path = GetQueryValue(query, "path", "");
        host = GetQueryValue(query, "host", "");
    }

    return !(uuid.isEmpty() || serverAddress.isEmpty());
}

QJsonObject VMessBean::ToJson() {
    QJsonObject obj;
    obj["type"] = "vmess";
    obj["name"] = name;
    obj["server"] = serverAddress;
    obj["port"] = serverPort;
    obj["uuid"] = uuid;
    obj["alterId"] = aid;
    obj["cipher"] = security;
    obj["network"] = network;
    if (!tls.isEmpty()) obj["tls"] = tls;
    if (!sni.isEmpty()) obj["sni"] = sni;
    if (!host.isEmpty()) obj["host"] = host;
    if (!path.isEmpty()) obj["path"] = path;
    return obj;
}

// ShadowSocks Parser
bool ShadowSocksBean::TryParseLink(const QString &link) {
    type = "shadowsocks";

    if (SubStrBefore(link, "#").contains("@")) {
        auto url = QUrl(link);
        if (!url.isValid()) return false;

        name = url.fragment(QUrl::FullyDecoded);
        serverAddress = url.host();
        serverPort = url.port();

        if (url.password().isEmpty()) {
            auto method_password = DecodeB64IfValid(url.userName(), QByteArray::Base64UrlEncoding);
            if (method_password.isEmpty()) return false;
            method = SubStrBefore(method_password, ":");
            password = SubStrAfter(method_password, ":");
        } else {
            method = url.userName();
            password = url.password();
        }
    } else {
        // v2rayN format
        QString linkN = DecodeB64IfValid(SubStrBefore(SubStrAfter(link, "://"), "#"), QByteArray::Base64UrlEncoding);
        if (linkN.isEmpty()) return false;
        auto url = QUrl("https://" + linkN);

        serverAddress = url.host();
        serverPort = url.port();
        method = url.userName();
        password = url.password();
        if (link.contains("#")) {
            name = SubStrAfter(link, "#");
        }
    }

    return !(serverAddress.isEmpty() || method.isEmpty() || password.isEmpty());
}

QJsonObject ShadowSocksBean::ToJson() {
    QJsonObject obj;
    obj["type"] = "shadowsocks";
    obj["name"] = name;
    obj["server"] = serverAddress;
    obj["port"] = serverPort;
    obj["method"] = method;
    obj["password"] = password;
    return obj;
}

// Trojan/VLESS Parser
bool TrojanVLESSBean::TryParseLink(const QString &link) {
    auto url = QUrl(link);
    if (!url.isValid()) return false;
    auto query = GetQuery(url);

    if (link.startsWith("trojan://")) {
        type = "trojan";
    } else if (link.startsWith("vless://")) {
        type = "vless";
    }

    name = url.fragment(QUrl::FullyDecoded);
    serverAddress = url.host();
    serverPort = url.port();
    password = url.userName();

    network = GetQueryValue(query, "type", "tcp");
    security = GetQueryValue(query, "security", "");
    sni = GetQueryValue(query, "sni");

    if (network == "ws") {
        path = GetQueryValue(query, "path", "");
        host = GetQueryValue(query, "host", "");
    } else if (network == "grpc") {
        path = GetQueryValue(query, "serviceName", "");
    }

    if (type == "vless") {
        flow = GetQueryValue(query, "flow", "");
    }

    return !(password.isEmpty() || serverAddress.isEmpty());
}

QJsonObject TrojanVLESSBean::ToJson() {
    QJsonObject obj;
    obj["type"] = type;
    obj["name"] = name;
    obj["server"] = serverAddress;
    obj["port"] = serverPort;
    obj["password"] = password;
    if (!network.isEmpty()) obj["network"] = network;
    if (!security.isEmpty()) obj["security"] = security;
    if (!sni.isEmpty()) obj["sni"] = sni;
    if (!host.isEmpty()) obj["host"] = host;
    if (!path.isEmpty()) obj["path"] = path;
    if (!flow.isEmpty() && type == "vless") obj["flow"] = flow;
    return obj;
}

// SOCKS/HTTP Parser
bool SocksHttpBean::TryParseLink(const QString &link) {
    auto url = QUrl(link);
    if (!url.isValid()) return false;

    if (link.startsWith("socks")) {
        type = "socks";
    } else if (link.startsWith("http")) {
        type = "http";
    }

    name = url.fragment(QUrl::FullyDecoded);
    serverAddress = url.host();
    serverPort = url.port();
    username = url.userName();
    password = url.password();

    if (serverPort == -1) {
        serverPort = (type == "http") ? 443 : 1080;
    }

    // v2rayN format
    if (password.isEmpty() && !username.isEmpty()) {
        QString n = DecodeB64IfValid(username);
        if (!n.isEmpty()) {
            username = SubStrBefore(n, ":");
            password = SubStrAfter(n, ":");
        }
    }

    return !serverAddress.isEmpty();
}

QJsonObject SocksHttpBean::ToJson() {
    QJsonObject obj;
    obj["type"] = type;
    obj["name"] = name;
    obj["server"] = serverAddress;
    obj["port"] = serverPort;
    if (!username.isEmpty()) obj["username"] = username;
    if (!password.isEmpty()) obj["password"] = password;
    return obj;
}