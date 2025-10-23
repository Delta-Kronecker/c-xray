#ifndef HTTPHELPER_H
#define HTTPHELPER_H

#include <QString>
#include <QByteArray>

struct HttpResponse {
    QString error;
    QByteArray data;
};

class HttpHelper {
public:
    static HttpResponse HttpGet(const QString &url);
};

#endif // HTTPHELPER_H