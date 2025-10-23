#ifndef SUBPARSER_H
#define SUBPARSER_H

#include <QString>
#include <QList>
#include <QJsonObject>
#include "ProxyBean.h"
#include <memory>

class SubParser {
public:
    static QList<std::shared_ptr<ProxyBean>> ParseSubscription(const QString &content);

private:
    static QList<std::shared_ptr<ProxyBean>> ParseMultiLine(const QString &str);
    static std::shared_ptr<ProxyBean> ParseSingleLink(const QString &str);
};

#endif // SUBPARSER_H