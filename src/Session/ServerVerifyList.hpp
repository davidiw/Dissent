#ifndef DISSENT_SESSION_SERVER_VERIFY_LIST_H_GUARD
#define DISSENT_SESSION_SERVER_VERIFY_LIST_H_GUARD

#include <QByteArray>
#include <QDataStream>
#include <QIODevice>
#include <QVariant>

#include "Connections/Id.hpp"
#include "Crypto/AsymmetricKey.hpp"

namespace Dissent {
namespace Session {
  class ServerVerifyList {
    public:
      explicit ServerVerifyList(const QByteArray &packet) :
        m_packet(packet)
      {
      }

      QByteArray GetPacket() const
      {
        return m_packet;
      }

      QByteArray GetSignature() const
      {
        return m_packet;
      }

    private:
      QByteArray m_packet;
  };

  inline QDataStream &operator<<(QDataStream &stream, const ServerVerifyList &packet)
  {
    stream << packet.GetPacket();
    return stream;
  }

  inline QDataStream &operator>>(QDataStream &stream, ServerVerifyList &packet)
  {
    QByteArray data;
    stream >> data;
    packet = ServerVerifyList(data);
    return stream;
  }
}
}

#endif
