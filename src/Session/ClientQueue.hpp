#ifndef DISSENT_SESSION_CLIENT_QUEUE_H_GUARD
#define DISSENT_SESSION_CLIENT_QUEUE_H_GUARD

#include <QByteArray>
#include "Messaging/Message.hpp"

namespace Dissent {
namespace Session {
  /**
   * During registration, clients first transmit a Queue message to enter the
   * registration queue. Queue messages contain a client temporary nonce as a means
   * to authenticate the upstream servers to prevent replay attacks.
   */
  class ClientQueue : public Messaging::Message {
    public:
      /**
       * Constructor for packet and fields
       * @param packet packet or nonce
       */
      explicit ClientQueue(const QByteArray &packet)
      {
        SetPacket(packet);
      }

      /**
       * Returns the nonce
       */
      QByteArray GetNonce() const
      {
        return GetPacket();
      }

      /**
       * Returns the message type
       */
      virtual qint8 GetMessageType() const { return 3; }
  };
}
}

#endif
