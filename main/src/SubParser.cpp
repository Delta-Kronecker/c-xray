#include "../include/SubParser.h"
#include "../include/Utils.h"
#include <QDebug>

QList<std::shared_ptr<ProxyBean>> SubParser::ParseSubscription(const QString &content) {
    // Try Base64 decode
    auto decoded = DecodeB64IfValid(content);
    if (!decoded.isEmpty()) {
        return ParseSubscription(QString::fromUtf8(decoded));
    }

    // Multi-line
    if (content.count("\n") > 0) {
        return ParseMultiLine(content);
    }

    // Single link
    QList<std::shared_ptr<ProxyBean>> result;
    auto bean = ParseSingleLink(content.trimmed());
    if (bean) {
        result.append(bean);
    }
    return result;
}

QList<std::shared_ptr<ProxyBean>> SubParser::ParseMultiLine(const QString &str) {
    QList<std::shared_ptr<ProxyBean>> result;
    auto lines = str.split('\n', Qt::SkipEmptyParts);

    for (const auto &line : lines) {
        auto trimmed = line.trimmed();
        if (trimmed.startsWith("#") || trimmed.startsWith("//") || trimmed.length() < 5) {
            continue;
        }

        auto bean = ParseSingleLink(trimmed);
        if (bean) {
            result.append(bean);
        }
    }

    return result;
}

std::shared_ptr<ProxyBean> SubParser::ParseSingleLink(const QString &str) {
    std::shared_ptr<ProxyBean> bean;

    // VMess
    if (str.startsWith("vmess://")) {
        bean = std::make_shared<VMessBean>();
        if (!bean->TryParseLink(str)) return nullptr;
    }
    // ShadowSocks
    else if (str.startsWith("ss://")) {
        bean = std::make_shared<ShadowSocksBean>();
        if (!bean->TryParseLink(str)) return nullptr;
    }
    // Trojan
    else if (str.startsWith("trojan://")) {
        auto trojanBean = std::make_shared<TrojanVLESSBean>();
        trojanBean->type = "trojan";
        if (!trojanBean->TryParseLink(str)) return nullptr;
        bean = trojanBean;
    }
    // VLESS
    else if (str.startsWith("vless://")) {
        auto vlessBean = std::make_shared<TrojanVLESSBean>();
        vlessBean->type = "vless";
        if (!vlessBean->TryParseLink(str)) return nullptr;
        bean = vlessBean;
    }
    // SOCKS
    else if (str.startsWith("socks")) {
        bean = std::make_shared<SocksHttpBean>();
        if (!bean->TryParseLink(str)) return nullptr;
    }
    // HTTP
    else if (str.startsWith("http://") || str.startsWith("https://")) {
        bean = std::make_shared<SocksHttpBean>();
        if (!bean->TryParseLink(str)) return nullptr;
    }

    return bean;
}