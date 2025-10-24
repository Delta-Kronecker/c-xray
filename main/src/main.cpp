#include <QCoreApplication>
#include <QDebug>
#include <QDir>
#include <QMap>
#include "../include/Utils.h"
#include "../include/HttpHelper.h"
#include "../include/SubParser.h"

// Generate unique key for deduplication (protocol + server + port)
QString GenerateConfigKey(const std::shared_ptr<ProxyBean> &bean) {
    return QString("%1://%2:%3")
        .arg(bean->type)
        .arg(bean->serverAddress)
        .arg(bean->serverPort);
}

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);

    qDebug() << "=== ConfigCollector Started ===";

    // Read Sub.txt
    QString subFilePath = "../../data/Sub.txt";
    QString subContent = ReadFileText(subFilePath);

    if (subContent.isEmpty()) {
        qDebug() << "Error: Sub.txt is empty or not found!";
        qDebug() << "Please create" << QDir::current().absoluteFilePath(subFilePath);
        return 1;
    }

    auto subLinks = subContent.split('\n', Qt::SkipEmptyParts);
    qDebug() << "Found" << subLinks.size() << "subscription links";

    int totalConfigs = 0;
    int duplicateCount = 0;
    int configIndex = 1;

    // HashMap for deduplication (key -> bean)
    QMap<QString, std::shared_ptr<ProxyBean>> uniqueConfigs;

    // Process each subscription link
    for (int i = 0; i < subLinks.size(); i++) {
        auto link = subLinks[i].trimmed();
        if (link.isEmpty() || link.startsWith("#")) continue;

        qDebug() << "\n[" << (i+1) << "/" << subLinks.size() << "] Processing:" << link;

        // Download subscription
        auto response = HttpHelper::HttpGet(link);

        if (!response.error.isEmpty()) {
            qDebug() << "  Error downloading:" << response.error;
            continue;
        }

        qDebug() << "  Downloaded" << response.data.size() << "bytes";

        // Parse subscription
        auto beans = SubParser::ParseSubscription(QString::fromUtf8(response.data));
        qDebug() << "  Parsed" << beans.size() << "configs";

        // Add to unique configs map
        for (const auto &bean : beans) {
            QString key = GenerateConfigKey(bean);

            if (uniqueConfigs.contains(key)) {
                // Duplicate found, skip
                duplicateCount++;
            } else {
                // New unique config, add to map
                uniqueConfigs[key] = bean;
                totalConfigs++;
            }
        }
    }

    qDebug() << "\n=== Saving Unique Configs ===";
    qDebug() << "Total unique configs:" << totalConfigs;
    qDebug() << "Duplicates removed:" << duplicateCount;

    // Save unique configs to files
    for (const auto &bean : uniqueConfigs) {
        auto json = bean->ToJson();
        auto jsonStr = QJsonObject2QString(json, false);

        QString filename = QString("../../data/Config/config_%1.json").arg(configIndex, 4, 10, QChar('0'));

        if (WriteFileText(filename, jsonStr)) {
            configIndex++;
        } else {
            qDebug() << "  Error saving:" << filename;
        }
    }

    qDebug() << "\n=== ConfigCollector Finished ===";
    qDebug() << "Total unique configs saved:" << totalConfigs;
    qDebug() << "Total duplicates removed:" << duplicateCount;

    return 0;
}
