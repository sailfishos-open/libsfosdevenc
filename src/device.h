#ifndef DEVENC_DEVICE_H
#define DEVENC_DEVICE_H

#include <QByteArray>
#include <QObject>
#include <QSettings>

#include "password.h"

namespace DevEnc {

  class Device : public QObject
  {
    Q_OBJECT

    Q_PROPERTY(bool deviceAvailable READ deviceAvailable NOTIFY deviceAvailableChanged)
    Q_PROPERTY(bool encrypted READ encrypted NOTIFY encryptedChanged)
    Q_PROPERTY(bool initialized READ initialized NOTIFY initializedChanged)
    Q_PROPERTY(QString id READ id NOTIFY idChanged)
    Q_PROPERTY(QString name READ name NOTIFY nameChanged)
    Q_PROPERTY(bool developer READ developer)
    Q_PROPERTY(bool encryptionRequired READ encryptionRequired)

  public:
    Device(QObject *parent = nullptr);
    Device(QSettings &settings, QObject *parent = nullptr);

    Q_INVOKABLE QString getRecoveryPassword() const;
    bool removeRecoveryPasswordCopy();

    bool deviceAvailable() const;
    bool encrypted() const;
    QString id() const { return m_id; }
    bool initialized() const { return m_state != StateReset; }
    QString name() const { return m_name; }
    bool developer() const { return m_developer; }
    bool encryptionRequired() const { return m_encRequired; }

    // set device either to be encrypted or not
    Q_INVOKABLE bool setEncryption(bool encrypt);

    // call when considered that device is ready for use
    Q_INVOKABLE bool setInitialized();

    // password
    int freePasswordSlots();
    int usedPasswordSlots();

    Q_INVOKABLE bool addPassword(Password *new_password) { return addPassword(nullptr, new_password); }
    Q_INVOKABLE bool addPassword(Password *password, Password *new_password);

    bool removePassword(Password *passwordObj, Password *toremove_passwordObj);

    bool testPassword(Password *passwordObj);

    // used by generator to create SystemD units
    bool createSystemDConfig(const QString &prefix);

  signals:
    void deviceAvailableChanged();
    void encryptedChanged();
    void initializedChanged();
    void idChanged();
    void nameChanged();

  private:
    bool createFile();
    bool deleteFile();

    void createRecoveryPassword();
    bool writeRecoveryPasswordCopy();

    bool encryptAndFormat();
    bool format();

  private:
    enum State {
      StateReset,
      StateEncrypted,
      StatePlain
    };

    enum Type {
      TypeDevice,
      TypeFile
    };

  private:
    QString m_id;
    QString m_name;
    QString m_device;
    QString m_mapper;
    QString m_mount;
    Type m_type{TypeDevice};
    uint32_t m_size_mb;
    State m_state{StateReset};
    bool m_developer = false;
    bool m_encRequired = false;

    // internal variables
    QString m_recovery_password;
    bool m_set_encryption_success{false};
  };

} // namespace DevEnc

#endif // DEVENC_DEVICE_H
