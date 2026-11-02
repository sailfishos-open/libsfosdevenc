#include "devicelist.h"
#include "constants.h"

#include <QSettings>

#include <unistd.h>

#include <QDebug>

using namespace DevEnc;

DeviceList* DeviceList::s_instance = nullptr;

DeviceList::DeviceList(QObject *parent) : QObject(parent)
{
  // merge distribution provided settings with the settings
  // on this device. separate settings files are required to avoid
  // overwriting configuration during updates as could happen when
  // devices.ini is distributed through droid-config
  {
    QSettings local_config(INI_SETTINGS, QSettings::IniFormat);
    QSettings default_config(INI_DISTRIBUTION_DEFAULTS, QSettings::IniFormat);
    for (QString key: default_config.allKeys())
      if (!local_config.contains(key))
        local_config.setValue(key, default_config.value(key));
  }

  // Load available devices
  QSettings device_config(INI_SETTINGS, QSettings::IniFormat);
  for (QString group: device_config.childGroups())
    {
      device_config.beginGroup(group);
      QSharedPointer<Device> p(new Device(device_config));
      m_devices.append(p);
      device_config.endGroup();
    }

  // After a rootfs reflash that kept userdata, config.ini is gone but the
  // encrypted home is still there. Recognise it (only root can record that).
  if (geteuid() == 0)
    for (auto p: m_devices)
      p->adoptExistingContainer();
}

DeviceList* DeviceList::instance()
{
  if (!s_instance) s_instance = new DeviceList();
  return s_instance;
}

bool DeviceList::initNeeded() const
{
  for (auto p: m_devices)
    if (!p->initialized())
      return true;
  return false;
}

QStringList DeviceList::devices() const
{
  QStringList l;
  for (auto p: m_devices)
    l.append(p->id());
  return l;
}

Device* DeviceList::device(const QString name)
{
  for (auto p: m_devices)
    if (p->id() == name)
      return p.data();
  return nullptr;
}

Device* DevEnc::DeviceList::nextDevice()
{
  int d = m_current_device + 1;
  if (d >= m_devices.length())
    return nullptr;
  m_current_device = d;
  return m_devices[m_current_device].data();
}
