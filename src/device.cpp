#include "device.h"
#include "constants.h"

#include <QDir>
#include <QDebug>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QTemporaryDir>

#include <exception>
#include <fstream>
#include <iostream>
#include <libcryptsetup.h>
#include <random>


using namespace DevEnc;

// helper macros
#define OPCHECK(op, msg) if (!(op)) { \
  std::cerr << "DevEnc::Dev:" << __LINE__ << ": " << msg << ". Device: " << m_device.toStdString() << "\n"; \
  return false; }
#define OPCHECK_CRYPT(op, msg) if (!(op)) { \
  crypt_free(cd); \
  std::cerr << "DevEnc::Dev:" << __LINE__ << ": " << msg << ". Device: " << m_device.toStdString() << "\n"; \
  return false; }

Device::Device(QObject *parent) : QObject(parent)
{
  // required by QML
}

Device::Device(QSettings &settings, QObject *parent) : QObject(parent)
{
  m_id = settings.group();

  m_name = settings.value("name").toString();
  if (m_name == "Home") m_name = tr("Home");
  else if (m_name == "SD Card") m_name = tr("SD Card");

  m_device = settings.value("device").toString();
  m_mapper = settings.value("mapper").toString();
  m_mount = settings.value("mount").toString();
  m_developer = settings.value("developer", false).toBool();

  // check settings
  if (m_device.isEmpty())
    throw std::runtime_error(m_id.toStdString() + ": Missing device");

  if (!QDir::isAbsolutePath(m_device))
    throw std::runtime_error(m_id.toStdString() + ": Device should be given by absolute path");

  if (m_mapper.isEmpty())
    throw std::runtime_error(m_id.toStdString() + ": Missing device mapper name");

  if (m_mapper.contains('/') || m_mapper.contains('-'))
    throw std::runtime_error(m_id.toStdString() + ": Mapper name should not contain / or -");

  if (m_mount.isEmpty())
    throw std::runtime_error(m_id.toStdString() + ": Missing mount point");

  if (!QDir::isAbsolutePath(m_mount))
    throw std::runtime_error(m_id.toStdString() + ": Mount point should be absolute path");

  // load and check remaining settings
  QString t = settings.value("type").toString();
  if (t == "device") m_type = TypeDevice;
  else if (t == "file") m_type = TypeFile;
  else throw std::runtime_error(m_id.toStdString() + ": Missing type of device");

  m_size_mb = settings.value("size_mb", 0).toInt();
  if (m_size_mb <= 0 && m_type == TypeFile)
    throw std::runtime_error(m_id.toStdString() + ": Missing size of allocated file");

  QString s = settings.value("state", "reset").toString();
  if (s == "reset") m_state = StateReset;
  else if (s == "encrypted") m_state = StateEncrypted;
  else if (s == "plain") m_state = StatePlain;
  else
    throw std::runtime_error(m_id.toStdString() + ": Unknown state of the device");
}

bool Device::deviceAvailable() const
{
  QFileInfo fi(m_device);

  if (m_type==TypeDevice)
    return fi.exists();

  if (fi.exists() && fi.isFile())
    return true;
  else if (fi.exists())
    return false; // if it exists it should be file

  // file can be made if needed in directory
  return fi.dir().exists();
}

bool Device::encrypted() const
{
  OPCHECK(deviceAvailable(), "Device is not available");

  struct crypt_device *cd;

  OPCHECK(crypt_init(&cd, m_device.toLatin1().data()) == 0, "crypt_init() failed");
  OPCHECK_CRYPT(crypt_load(cd, CRYPT_LUKS, NULL) == 0, "crypt_load() failed on device");

  //qDebug() << crypt_get_type(cd) << crypt_get_cipher(cd) << crypt_get_cipher_mode(cd) << crypt_get_iv_offset(cd) << crypt_get_volume_key_size(cd);

  // cleanup
  crypt_free(cd);
  return true;
}

bool Device::setEncryption(bool enc)
{
  m_set_encryption_success = false;

  OPCHECK(!initialized(), "Set encryption can be called on noninitialized device only");
  OPCHECK(deviceAvailable(), "Device is not available");

  // preparation for files
  if (m_type == TypeFile)
    {
      if (enc) { OPCHECK(createFile(), "Failed to create file"); }
      else { OPCHECK(deleteFile(), "Failed to delete file"); }
    }

  // encrypt and format the volume
  if (enc)
    {
      OPCHECK(encryptAndFormat(), "Failed to encrypt and format device");
    }
  else if (m_type == TypeDevice)
    {
      OPCHECK(format(), "Failed to reformat device as a part of a reset");
    }

  m_set_encryption_success = true;
  m_state = (enc ? StateEncrypted : StatePlain);

  emit encryptedChanged();

  return true;
}

bool Device::setInitialized()
{
  OPCHECK(m_set_encryption_success, "Cannot set device to initialized before successful setEncrypt");
  OPCHECK(m_state != StateReset, "Cannot set device to initialized before successful setEncrypt");

  bool enc = (m_state == StateEncrypted);

  // record changes in configuration
  QSettings settings(INI_SETTINGS, QSettings::IniFormat);
  settings.beginGroup(m_id);
  settings.setValue("state", enc ? "encrypted" : "plain");

  emit initializedChanged();
  return true;
}

QString Device::getRecoveryPassword() const
{
  if (!m_recovery_password.isEmpty()) return m_recovery_password;

  // load from stored copy and show that. but never load it to
  // local var to distinguish between initialization state when
  // device was just formatted and the state when password was
  // requested by user for backing it up
  QDir dir(m_mount);

  std::ifstream fin( dir.absoluteFilePath(RECOVERY_PASSWORD_FILE).toLatin1().data() );
  if (!fin) return QString();
  std::string pwd;
  fin >> pwd;
  return QString::fromStdString(pwd);
}

bool Device::removeRecoveryPasswordCopy()
{
  QDir dir(m_mount);
  OPCHECK(dir.remove(RECOVERY_PASSWORD_FILE), "Failed to remove recovery password copy");
  return true;
}


// SystemD units
bool Device::createSystemDConfig(const QString &prefix)
{
  OPCHECK(initialized(), "Cannot create systemd units for uninitialized device");
  OPCHECK(deviceAvailable(), "Device is not available");

  QDir etc(prefix);
  bool enc = (m_state == StateEncrypted);

  QString mount = m_mount.mid(1);

  // cleanup and remove possibly present units
  QStringList conffilelist;
  conffilelist << mount + ".mount"
               << "late-mount.target.requires/" + mount + ".mount"
               << "decrypt-" + m_mapper + "service"
               << "late-mount.target.requires/decrypt-" + m_mapper + ".service"
               << "dev-mapper-" + m_mapper + ".device"
               << "mounttmp-" + mount + ".service"
               << "late-mount.target.requires/mounttmp-" + mount + ".service";
  for (const QString &i: conffilelist)
    etc.remove(i);

  // new units

  if (!enc && m_type == TypeFile)
    return true; // nothing to mount in this case

  OPCHECK(etc.mkpath("late-mount.target.requires"),
          "Failed to create missing systemd directory");

  // required in all remaining cases
  std::ofstream fmount(etc.absoluteFilePath(mount + ".mount").toLatin1().data());

  if (!enc && m_type == TypeDevice)
    {
      fmount << "[Unit]\n"
             << "Description=" << m_name.toStdString() << "\n"
             << "Before=late-mount.target\n"
             << "After=late-mount-pre.target\n\n"
             << "[Mount]\n"
             << "What=" << m_device.toStdString() << "\n"
             << "Where=" << m_mount.toStdString() << "\n"
             << "Options=defaults,noatime\n\n"
             << "[Install]\n"
             << "RequiredBy=late-mount.target\n";
      OPCHECK(fmount, "Failed to write mount unit");

      OPCHECK(QFile::link("../" + mount + ".mount",
                          etc.absoluteFilePath("late-mount.target.requires/" + mount + ".mount")),
              "Failed to enable SystemD mount unit");

      return true;
    }

  OPCHECK(enc, "Internal error, should never happen");

  // mount unit for encrypted case
  fmount << "[Unit]\n"
         << "Description=" << m_name.toStdString() << "\n"
         << "After=decrypt-" << m_mapper.toStdString() << ".service\n"
         << "Before=late-mount.target\n\n"
         << "[Mount]\n"
         << "What=/dev/mapper/" << m_mapper.toStdString() << "\n"
         << "Where=" << m_mount.toStdString() << "\n"
         << "Options=defaults,noatime\n\n"
         << "[Install]\n"
         << "RequiredBy=late-mount.target\n";
  OPCHECK(fmount, "Failed to write mount unit");

  OPCHECK(QFile::link("../" + mount + ".mount",
                      etc.absoluteFilePath("late-mount.target.requires/" + mount + ".mount")),
          "Failed to enable SystemD mount unit");

  // device unit
  std::ofstream fdevice(etc.absoluteFilePath("dev-mapper-" + m_mapper + ".device").toLatin1().data());
  fdevice << "[Unit]\n"
          << "Description=Device " << m_mapper.toStdString() << "\n"
          << "JobTimeoutSec=0\n";
  OPCHECK(fdevice, "Failed to write device unit");

  // decryption service unit
  std::ofstream fservice(etc.absoluteFilePath("decrypt-" + m_mapper + ".service").toLatin1().data());
  fservice << "[Unit]\n"
           << "Description=Decrypt " << m_mapper.toStdString() << "\n"
           << "Before=late-mount.target\n"
           << "After=late-mount-pre.target\n"
           << "ConditionPathExists=!/run/systemd/boot-status/ACT_DEAD\n"
           << "ConditionPathExists=!/run/systemd/boot-status/TEST\n\n"
           << "[Service]\n"
           << "Type=oneshot\n"
           << "RemainAfterExit=yes\n"
           << "ExecStart=" << DECRYPT_CMD << " " << m_device.toStdString() << " " << m_mapper.toStdString() << " \"" << m_name.toStdString() << "\"\n"
           << "Restart=no\n\n"
           << "[Install]\n"
           << "RequiredBy=late-mount.target\n";
  OPCHECK(fservice, "Failed to write decryption service unit");

  OPCHECK(QFile::link("../decrypt-" + m_mapper + ".service",
                      etc.absoluteFilePath("late-mount.target.requires/decrypt-" + m_mapper + ".service")),
          "Failed to enable SystemD decryption service unit");

  // mount service unit used in ACT_DEAD mode
  std::ofstream fmnttmp(etc.absoluteFilePath("mounttmp-" + mount + ".service").toLatin1().data());
  fmnttmp << "[Unit]\n"
          << "Description=Mount " << m_mount.toStdString() << " replacement\n"
          << "Before=late-mount.target\n"
          << "After=late-mount-pre.target\n"
          << "ConditionPathExists=|/run/systemd/boot-status/ACT_DEAD\n"
          << "ConditionPathExists=|/run/systemd/boot-status/TEST\n\n"
          << "[Service]\n"
          << "Type=oneshot\n"
          << "RemainAfterExit=yes\n"
          << "ExecStart=" << MOUNTTMP_CMD << " " << m_mount.toStdString() << "\n\n"
          << "Restart=no\n\n"
          << "[Install]\n"
          << "RequiredBy=late-mount.target\n";
  OPCHECK(fmnttmp, "Failed to write ACT_DEAD mount service unit");

  OPCHECK(QFile::link("../mounttmp-" + mount + ".service",
                      etc.absoluteFilePath("late-mount.target.requires/mounttmp-" + mount + ".service")),
          "Failed to enable SystemD ACT_DEAD mount service unit");

  return true;
}

////////////////////////////////////////////
/// Private methods

bool Device::encryptAndFormat()
{
  // initialize encryption
  struct crypt_device *cd;

  OPCHECK(crypt_init(&cd, m_device.toLatin1().data()) == 0, "crypt_init() failed");

  OPCHECK_CRYPT(crypt_format(cd,            /* crypt context */
                             CRYPT_LUKS2,   /* LUKS2 is a new LUKS format; use CRYPT_LUKS1 for LUKS1 */
                             "aes",         /* used cipher */
                             "xts-plain64", /* used block mode and IV */
                             NULL,          /* generate UUID */
                             NULL,          /* generate volume key from RNG */
                             512 / 8,       /* 512bit key - here AES-256 in XTS mode, size is in bytes */
                             NULL           /* default parameters */) == 0,
                "Failed to crypt_format()");

  createRecoveryPassword();
  OPCHECK_CRYPT(crypt_keyslot_add_by_volume_key(cd, /* crypt context */
                                                CRYPT_ANY_SLOT,
                                                NULL,               /* use internal volume key */
                                                0,                  /* unused (size of volume key) */
                                                m_recovery_password.toLatin1().data(),
                                                m_recovery_password.length()) >= 0,
                "Failed to add recovery password");

  // open encrypted volume
  OPCHECK_CRYPT(crypt_activate_by_passphrase(cd,
                                             m_mapper.toLatin1().data(),
                                             CRYPT_ANY_SLOT,
                                             m_recovery_password.toLatin1().data(),
                                             m_recovery_password.length(),
                                             0) >= 0,
                "Failed to activate device");

  // format
  OPCHECK_CRYPT(QProcess::execute("mkfs.ext4",
                                  QStringList() << "-m" << "1" << "/dev/mapper/" + m_mapper) == 0,
                "Failed to format filesystem");

  // mount and store recovery password
  OPCHECK_CRYPT(writeRecoveryPasswordCopy(), "Failed to store recovery password");

  // close encrypted volume
  OPCHECK_CRYPT(crypt_deactivate(cd, m_mapper.toLatin1().data()) == 0,
                "Failed to deactivate device");

  crypt_free(cd);
  return true;
}

bool Device::format()
{
  OPCHECK(QProcess::execute("mkfs.ext4",
                            QStringList() << "-m" << "1" << m_device) == 0,
          "Failed to format filesystem");
  return true;
}

// recovery password
void Device::createRecoveryPassword()
{
  const QString chars("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
  const int nc = chars.length();

  std::random_device rd("/dev/urandom");
  std::uniform_int_distribution<int> dist(0, nc-1);

  m_recovery_password = QString();
  for (int slot=0; slot < 8; ++slot)
    {
      if (!m_recovery_password.isEmpty())
        m_recovery_password += "-";
      for (int i=0; i < 5; ++i)
        m_recovery_password += chars[dist(rd)];
    }
}

bool Device::writeRecoveryPasswordCopy()
{
  // mount filesystem
  QTemporaryDir tmpDir;
  OPCHECK(tmpDir.isValid(), "Failed to create temporary directory");
  OPCHECK(QProcess::execute("mount",
                            QStringList()
                            << "/dev/mapper/" + m_mapper
                            << tmpDir.path().toLatin1().data()
                            ) == 0,
          "Failed to mount filesystem for temporary access");

  // write password
  QFileInfo fi(RECOVERY_PASSWORD_FILE);
  QString dpath = fi.dir().path();
  QDir dir(tmpDir.path());
  OPCHECK(dir.mkpath(dpath), "Failed to make folder for storing recovery password");

  QString abspath = dir.absoluteFilePath(fi.filePath());
  std::ofstream fout(abspath.toLatin1().data());
  OPCHECK(fout, "Failed to open file for writing recovery password");
  fout << m_recovery_password.toStdString() << "\n";
  OPCHECK(fout, "Failed to write recovery password");
  fout.close();

  // set permissions
  OPCHECK(QFile::setPermissions(abspath, QFileDevice::ReadOwner | QFileDevice::WriteOwner),
          "Failed to set recovery password file permissions");
  OPCHECK(QFile::setPermissions(dir.absoluteFilePath(dpath),
                                QFileDevice::ReadOwner | QFileDevice::WriteOwner),
          "Failed to set permissions for local configuration directory");

  // unmount
  OPCHECK(QProcess::execute("umount",
                            QStringList()
                            << "/dev/mapper/" + m_mapper
                            ) == 0,
          "Failed to unmount filesystem after storing recovery password");

  return true;
}

// File operations
bool Device::createFile()
{
  QFileInfo fi(m_device);

  if (fi.exists())
    {
      QDir dir;
      OPCHECK(dir.remove(fi.absoluteFilePath()), "Failed to remove file");
    }

  std::ofstream fout(fi.absoluteFilePath().toLatin1().data(), std::ios::binary | std::ios::out);
  OPCHECK(fout,"Failed to open file");
  fout.seekp( ((uint64_t)m_size_mb) * 1024*1024 );
  OPCHECK(fout,"Failed to seek in file initialization");
  fout.write("", 1);
  OPCHECK(fout,"Failed to write file");

  return true;
}

bool Device::deleteFile()
{
  QFileInfo fi(m_device);

  if (fi.exists())
    {
      QDir dir;
      OPCHECK(dir.remove(fi.absoluteFilePath()), "Failed to remove file");
    }

  return true;
}
