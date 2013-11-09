#ifndef DISSENT_SESSION_SERVER_STOP_H_GUARD
#define DISSENT_SESSION_SERVER_STOP_H_GUARD

#include <QByteArray>
#include <QDataStream>
#include <QIODevice>
#include <QVariant>

#include "Connections/Id.hpp"
#include "Crypto/AsymmetricKey.hpp"

namespace Dissent {
namespace Session {
  /**
   * A protocol round constitutes one or more anonymous exchanges.  The protocol
   * round continues for at least 1 exchange or 60 minutes, whichever is longer. At
   * which point, each server broadcasts a Stop message with the reason "Protocol
   * run complete" and immediate set to false.  At any point, if a server
   * disconnects from any other server, that server immediately broadcasts a Stop
   * message with reason "Server disconnected x from y" and immediate set to true.
   */
  class ServerStop {
    public:
      /**
       * Constructor for packet
       * @param packet a ServerStop in byte format
       */
      explicit ServerStop(const QByteArray &packet) :
        m_packet(packet)
      {
        QDataStream stream0(m_packet);
        stream0 >> m_payload >> m_signature;

        QDataStream stream(m_payload);
        stream >> m_round_id >> m_immediate >> m_reason;
      }

      /**
       * Constructor using fields
       * @param round_id The round identifier
       * @param immediate Should stop now or after the current round has completed
       * @param reason The reason for stopping
       */
      explicit ServerStop(const QByteArray &round_id,
          bool immediate,
          const QString &reason) :
        m_round_id(round_id),
        m_immediate(immediate),
        m_reason(reason)
      {
        QDataStream stream(&m_payload, QIODevice::WriteOnly);
        stream << round_id << immediate << reason;
      }

      /**
       * Returns the message as a byte array
       */
      QByteArray GetPacket() const
      {
        return m_packet;
      }

      /**
       * Returns the message excluding the signature as a byte array,
       * the signature should use these bytes.
       */
      QByteArray GetPayload() const
      {
        return m_payload;
      }

      /**
       * Returns the signature
       */
      QByteArray GetSignature() const
      {
        return m_signature;
      }

      /**
       * Returns the round Id / nonce
       */
      QByteArray GetRoundId() const
      {
        return m_round_id;
      }

      /**
       * Returns whether or not to end the round immediately or at the end
       * of the current exchange
       */
      bool GetImmediate() const
      {
        return m_immediate;
      }

      /**
       * Returns the reason for the round stopping
       */
      QString GetReason() const
      {
        return m_reason;
      }

      /**
       * Sets the signature field and (re)builds the packet
       */
      void SetSignature(const QByteArray &signature)
      {
        m_signature = signature;
        QDataStream stream(&m_packet, QIODevice::WriteOnly);
        stream << m_payload << m_signature;
      }

    private:
      QByteArray m_packet;
      QByteArray m_payload;

      QByteArray m_round_id;
      bool m_immediate;
      QString m_reason;

      QByteArray m_signature;
  };

  inline QDataStream &operator<<(QDataStream &stream, const ServerStop &packet)
  {
    stream << packet.GetPacket();
    return stream;
  }

  inline QDataStream &operator>>(QDataStream &stream, ServerStop &packet)
  {
    QByteArray data;
    stream >> data;
    packet = ServerStop(data);
    return stream;
  }
}
}

#endif
