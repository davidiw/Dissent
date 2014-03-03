#ifndef DISSENT_MESSAGING_MESSAGE_H_GUARD
#define DISSENT_MESSAGING_MESSAGE_H_GUARD

#include <QByteArray>

namespace Dissent {
namespace Messaging {
  class Message {
    public:
      virtual ~Message() {}

      /**
       * Returns the message as a byte array
       */
      QByteArray GetPacket() const
      {
        return m_packet;
      }

      /**
       * Returns the message type
       */
      virtual qint8 GetMessageType() const = 0;

    protected:
      explicit Message() {}

      void SetPacket(const QByteArray &packet)
      {
        m_packet = packet;
      }

    private:
      QByteArray m_packet;
  };
}
}

#endif
