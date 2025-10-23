#ifndef UTILS_H
#define UTILS_H

#include <QString>
#include <QByteArray>
#include <QJsonObject>
#include <QJsonArray>
#include <QUrlQuery>

// Base64 decoding
QByteArray DecodeB64IfValid(const QString &input, QByteArray::Base64Options options = QByteArray::Base64Encoding);

// String helpers
QString SubStrBefore(const QString &str, const QString &sep);
QString SubStrAfter(const QString &str, const QString &sep);
QString GetQueryValue(const QUrlQuery &q, const QString &key, const QString &def = "");

// JSON helpers
QJsonObject QString2QJsonObject(const QString &jsonString);
QString QJsonObject2QString(const QJsonObject &jsonObject, bool compact = false);

// File operations
QString ReadFileText(const QString &path);
bool WriteFileText(const QString &path, const QString &text);

// Helper to get query from URL
QUrlQuery GetQuery(const QUrl &url);

#endif // UTILS_H