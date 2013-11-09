#ifndef DISSENT_SESSION_SERVER_INIT_H_GUARD
#define DISSENT_SESSION_SERVER_INIT_H_GUARD

#include <QByteArray>
#include <QDataStream>
#include <QIODevice>
#include <QVariant>

#include "Connections/Id.hpp"
#include "Crypto/AsymmetricKey.hpp"

namespace Dissent {
namespace Session {
  /**
   * Upon establishing connections or completing a round, Dissent begins
   * resynchronization. The first server listed in the configuration file has the
   * unique role of proposing the start of a round via an Init message to all
   * servers.
   */
  class ServerInit {
    public:
      /**
       * Constructor for packet
       * @param packet a ServerInit in byte format
       */
      explicit ServerInit(const QByteArray &packet) :
        m_packet(packet)
      {
        QDataStream stream0(m_packet);
        stream0 >> m_payload >> m_signature;

        QDataStream stream(m_payload);
        stream >> m_peer_id >> m_nonce >> m_timestamp >> m_group_id;
      }

      /**
       * Constructor using fields
       * @param peer_id Sender's overlay Id
       * @param nonce Nonce used to ensure uniqueness of the Init message
       * @param timestamp Time since the "Epoch", ensure causality of Init messages
       * @param group_id The hash of the group roster
       */
      explicit ServerInit(const Connections::Id &peer_id,
          const QByteArray &nonce,
          qint64 timestamp,
          const QByteArray &group_id) :
        m_peer_id(peer_id),
        m_nonce(nonce),
        m_timestamp(timestamp),
        m_group_id(group_id)
      {
        QDataStream stream(&m_payload, QIODevice::WriteOnly);
        stream << peer_id << nonce << timestamp << group_id;
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
       * Returns the sender's overlay Id
       */
      Connections::Id GetId() const
      {
        return m_peer_id;
      }

      qint64 GetTimestamp() const
      {
        return m_timestamp;
      }

      QByteArray GetNonce() const
      {
        return m_nonce;
      }

      QByteArray GetGroupId() const
      {
        return m_group_id;
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

      Connections::Id m_peer_id;
      QByteArray m_nonce;
      qint64 m_timestamp;
      QByteArray m_group_id;

      QByteArray m_signature;
  };

  inline QDataStream &operator<<(QDataStream &stream, const ServerInit &packet)
  {
    stream << packet.GetPacket();
    return stream;
  }

  inline QDataStream &operator>>(QDataStream &stream, ServerInit &packet)
  {
    QByteArray data;
    stream >> data;
    packet = ServerInit(data);
    return stream;
  }
}
}

#endif
