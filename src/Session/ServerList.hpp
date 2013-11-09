#ifndef DISSENT_SESSION_SERVER_LIST_H_GUARD
#define DISSENT_SESSION_SERVER_LIST_H_GUARD

#include <QByteArray>
#include <QDataStream>
#include <QIODevice>
#include <QList>

#include "ClientRegister.hpp"
#include "SerializeList.hpp"

namespace Dissent {
namespace Session {
  class ServerList {
    public:
      explicit ServerList(const QByteArray &packet) :
        m_packet(packet)
      {
        QDataStream stream0(m_packet);
        stream0 >> m_payload >> m_signature;
        m_register_list = DeserializeList<ClientRegister>(m_payload);
      }

      explicit ServerList(const QList<QSharedPointer<ClientRegister> > &register_list) :
        m_register_list(register_list),
        m_register(SerializeList<ClientRegister>(register_list))
      {
        m_payload = m_register;
      }

      explicit ServerList(const QList<QSharedPointer<ClientRegister> > &register_list,
          const QByteArray &list_data) :
        m_register_list(register_list),
        m_register(list_data)
      {
        m_payload = m_register;
      }

      QByteArray GetPacket() const
      {
        return m_packet;
      }

      QByteArray GetPayload() const
      {
        return m_payload;
      }

      QByteArray GetSignature() const
      {
        return m_signature;
      }

      QList<QSharedPointer<ClientRegister> > GetRegisterList() const
      {
        return m_register_list;
      }

      void SetSignature(const QByteArray &signature)
      {
        m_signature = signature;
        QDataStream stream(&m_packet, QIODevice::WriteOnly);
        stream << m_payload << m_signature;
      }

    private:
      QByteArray m_packet;
      QByteArray m_payload;

      QList<QSharedPointer<ClientRegister> > m_register_list;
      QByteArray m_register;

      QByteArray m_signature;
  };

  inline QDataStream &operator<<(QDataStream &stream, const ServerList &packet)
  {
    stream << packet.GetPacket();
    return stream;
  }

  inline QDataStream &operator>>(QDataStream &stream, ServerList &packet)
  {
    QByteArray data;
    stream >> data;
    packet = ServerList(data);
    return stream;
  }
}
}

#endif
