#include "../include/Utils.h"
#include "../3rdparty/base64.h"
#include <QFile>
#include <QTextStream>
#include <QJsonDocument>

QByteArray DecodeB64IfValid(const QString &input, QByteArray::Base64Options options) {
    Qt515Base64::Base64Options newOptions = Qt515Base64::Base64Option::AbortOnBase64DecodingErrors;
    if (options.testFlag(QByteArray::Base64UrlEncoding))
        newOptions |= Qt515Base64::Base64Option::Base64UrlEncoding;
    if (options.testFlag(QByteArray::OmitTrailingEquals))
        newOptions |= Qt515Base64::Base64Option::OmitTrailingEquals;

    auto result = Qt515Base64::QByteArray_fromBase64Encoding(input.toUtf8(), newOptions);
    if (result) {
        return result.decoded;
    }
    return {};
}

QString SubStrBefore(const QString &str, const QString &sep) {
    auto index = str.indexOf(sep);
    if (index == -1) return str;
    return str.left(index);
}

QString SubStrAfter(const QString &str, const QString &sep) {
    auto index = str.indexOf(sep);
    if (index == -1) return "";
    return str.mid(index + sep.length());
}

QString GetQueryValue(const QUrlQuery &q, const QString &key, const QString &def) {
    auto a = q.queryItemValue(key);
    if (a.isEmpty()) return def;
    return a;
}

QJsonObject QString2QJsonObject(const QString &jsonString) {
    QJsonDocument jsonDocument = QJsonDocument::fromJson(jsonString.toUtf8());
    return jsonDocument.object();
}

QString QJsonObject2QString(const QJsonObject &jsonObject, bool compact) {
    return QJsonDocument(jsonObject).toJson(compact ? QJsonDocument::Compact : QJsonDocument::Indented);
}

QString ReadFileText(const QString &path) {
    QFile file(path);
    if (!file.open(QFile::ReadOnly | QFile::Text)) {
        return "";
    }
    QTextStream stream(&file);
    return stream.readAll();
}

bool WriteFileText(const QString &path, const QString &text) {
    QFile file(path);
    if (!file.open(QFile::WriteOnly | QFile::Text)) {
        return false;
    }
    QTextStream stream(&file);
    stream << text;
    return true;
}

QUrlQuery GetQuery(const QUrl &url) {
    return QUrlQuery(url.query());
}