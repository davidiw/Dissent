#ifndef DISSENT_SESSION_CLIENT_QUEUE_H_GUARD
#define DISSENT_SESSION_CLIENT_QUEUE_H_GUARD

#include <QByteArray>
#include <QDataStream>
#include <QIODevice>
#include <QVariant>

#include "Connections/Id.hpp"

namespace Dissent {
namespace Session {
  /**
   * During registration, clients first transmit a Queue message to enter the
   * registration queue. Queue messages contain a client temporary nonce as a means
   * to authenticate the upstream servers to prevent replay attacks.
   */
  class ClientQueue {
    public:
      /**
       * Constructor for packet and fields
       * @param packet packet or nonce
       */
      explicit ClientQueue(const QByteArray &packet) :
        m_packet(packet)
      {
      }

      /**
       * Returns the message as a byte array
       */
      QByteArray GetPacket() const
      {
        return m_packet;
      }

      /**
       * Returns the nonce
       */
      QByteArray GetNonce() const
      {
        return m_packet;
      }

    private:
      QByteArray m_packet;
  };

  inline QDataStream &operator<<(QDataStream &stream, const ClientQueue &packet)
  {
    stream << packet.GetPacket();
    return stream;
  }

  inline QDataStream &operator>>(QDataStream &stream, ClientQueue &packet)
  {
    QByteArray data;
    stream >> data;
    packet = ClientQueue(data);
    return stream;
  }
}
}

#endif
