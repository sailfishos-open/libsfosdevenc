#include "device.h"

#include <iostream>
#include <libcryptsetup.h>

using namespace DevEnc;

// helper macros
#define OPCHECK(op, msg) if (!(op)) { \
  std::cerr << "DevEnc::DevKey:" << __LINE__ << ": " << msg << ". Device: " << m_device.toStdString() << "\n"; \
  return false; }
#define OPCHECK_CRYPT(op, msg) if (!(op)) { \
  crypt_free(cd); \
  std::cerr << "DevEnc::DevKey:" << __LINE__ << ": " << msg << ". Device: " << m_device.toStdString() << "\n"; \
  return false; }

bool Device::addPasswordPlain(QByteArray password, QByteArray new_password)
{
  OPCHECK(m_state == StateEncrypted, "Cannot add password to non-encrypted device");
  OPCHECK(!new_password.isEmpty(), "Cannot add empty password");
  if (password.isEmpty()) password = m_recovery_password.toLocal8Bit();
  OPCHECK(!password.isEmpty(), "Cannot add new password without providing another one");

  struct crypt_device *cd;

  OPCHECK(crypt_init(&cd, m_device.toLocal8Bit().data()) == 0, "crypt_init() failed");
  OPCHECK(crypt_load(cd, CRYPT_LUKS, NULL) == 0, "Failed to load LUKS header");

  OPCHECK_CRYPT(crypt_keyslot_add_by_passphrase(cd,
                                                CRYPT_ANY_SLOT,
                                                password.data(),
                                                password.size(),
                                                new_password.data(),
                                                new_password.size()) >= 0,
                "Failed to add new password");

  crypt_free(cd);
  return true;
}