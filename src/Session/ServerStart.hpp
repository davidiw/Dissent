#ifndef DISSENT_SESSION_SERVER_START_H_GUARD
#define DISSENT_SESSION_SERVER_START_H_GUARD

#include <QByteArray>
#include <QDataStream>
#include <QIODevice>
#include <QList>

#include "ClientRegister.hpp"
#include "SerializeList.hpp"

namespace Dissent {
namespace Session {
  /**
   * Upon receiving all signatures, servers can begin the round and simultaneously
   * transmit a Start message to clients initiating the beginning of the protocol
   * round.
   */
  class ServerStart {
    public:
      /**
       * Constructor for packet
       * @param packet a ClientRegister in byte format
       */
      explicit ServerStart(const QByteArray &packet) :
        m_packet(packet)
      {
        QDataStream stream(m_packet);
        stream >> m_register >> m_signatures;

        m_register_list = DeserializeList<ClientRegister>(m_register);
      }

      /**
       * Constructor using fields
       * @param register_list List of all the ClientRegister messages
       * @param signatures Set of server signatures for the accumulated list
       * of ClientRegister messages
       * @param register_data precomputed byte array of register_list
       */
      explicit ServerStart(const QList<QSharedPointer<ClientRegister> > &register_list,
          const QList<QByteArray> &signatures,
          const QByteArray &register_data = QByteArray()) :
        m_register_list(register_list),
        m_register(register_data.isEmpty() ?
            SerializeList<ClientRegister>(register_list) : register_data),
        m_signatures(signatures)
      {
        QDataStream stream(&m_packet, QIODevice::WriteOnly);
        stream << m_register << m_signatures;
      }

      /**
       * Returns the message as a byte array
       */
      QByteArray GetPacket() const
      {
        return m_packet;
      }

      /**
       * Returns the list of signatures obtained from VerifyList
       */
      QList<QByteArray> GetSignatures() const
      {
        return m_signatures;
      }

      /**
       * Returns the list of registered clients (optional)
       */
      QList<QSharedPointer<ClientRegister> > GetRegisterList() const
      {
        return m_register_list;
      }

      /**
       * Returns the byte representation of the list of registered clients
       */
      QByteArray GetRegisterBytes() const
      {
        return m_register;
      }

    private:
      QByteArray m_packet;

      QList<QSharedPointer<ClientRegister> > m_register_list;
      QByteArray m_register;
      QList<QByteArray> m_signatures;
  };

  inline QDataStream &operator<<(QDataStream &stream, const ServerStart &packet)
  {
    stream << packet.GetPacket();
    return stream;
  }

  inline QDataStream &operator>>(QDataStream &stream, ServerStart &packet)
  {
    QByteArray data;
    stream >> data;
    packet = ServerStart(data);
    return stream;
  }
}
}

#endif
