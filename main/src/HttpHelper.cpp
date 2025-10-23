#include "../include/HttpHelper.h"
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QEventLoop>
#include <QTimer>

HttpResponse HttpHelper::HttpGet(const QString &url) {
    QNetworkRequest request;
    QNetworkAccessManager accessManager;
    accessManager.setTransferTimeout(10000);
    request.setUrl(url);

    // Set User-Agent
    request.setHeader(QNetworkRequest::UserAgentHeader, "ConfigCollector/1.0");

    auto reply = accessManager.get(request);

    // Wait for response
    QEventLoop loop;
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();

    HttpResponse result;
    if (reply->error() == QNetworkReply::NoError) {
        result.error = "";
        result.data = reply->readAll();
    } else {
        result.error = reply->errorString();
        result.data = "";
    }

    reply->deleteLater();
    return result;
}