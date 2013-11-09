#include "Connections/Connection.hpp"
#include "Crypto/CryptoRandom.hpp"
#include "Messaging/Request.hpp"

#include "Round.hpp"

namespace Dissent {
namespace Anonymity {
  Round::Round(const Identity::Roster &clients,
      const Identity::Roster &servers,
      const Identity::PrivateIdentity &ident,
      const QByteArray &nonce,
      const QSharedPointer<ClientServer::Overlay> &overlay,
      Messaging::GetDataCallback &get_data) :
    m_create_time(Dissent::Utils::Time::GetInstance().CurrentTime()),
    m_clients(clients),
    m_servers(servers),
    m_ident(ident),
    m_nonce(nonce),
    m_overlay(overlay),
    m_get_data_cb(get_data),
    m_successful(false),
    m_interrupted(false)
  {
  }

  void Round::OnStart()
  {
    m_start_time = Utils::Time::GetInstance().CurrentTime();
  }

  void Round::OnStop()
  {
    emit Finished();
  }

  void Round::IncomingData(const Messaging::Request &notification)
  {
    if(Stopped()) {
      qWarning() << "Received a message on a closed session:" << ToString();
      return;
    }

    QSharedPointer<Connections::IOverlaySender> sender =
      notification.GetFrom().dynamicCast<Connections::IOverlaySender>();

    if(!sender) {
      qDebug() << ToString() << " received wayward message from: " <<
        notification.GetFrom()->ToString();
      return;
    }

    const Connections::Id &id = sender->GetRemoteId();
    if(!GetServers().Contains(id) && !GetClients().Contains(id)) {
      qDebug() << ToString() << " received wayward message from: " <<
        notification.GetFrom()->ToString();
      return;
    }

    ProcessData(id, notification.GetData().toHash().value("data").toByteArray());
  }

  bool Round::Verify(const Connections::Id &from,
      const QByteArray &data, QByteArray &msg)
  {
    QSharedPointer<Crypto::AsymmetricKey> key = GetServers().GetKey(from);
    if(key.isNull()) {
      qDebug() << "Received malsigned data block, no such peer";
      return false;
    }

    int sig_size = key->GetSignatureLength();
    if(data.size() < sig_size) {
      qDebug() << "Received malsigned data block, not enough data blocks." <<
       "Expected at least:" << sig_size << "got" << data.size();
      return false;
    }

    msg = data.left(data.size() - sig_size);
    QByteArray sig = QByteArray::fromRawData(data.data() + msg.size(), sig_size);
    return key->Verify(msg, sig);
  }

  void Round::HandleDisconnect(const Connections::Id &id)
  {
    if(GetServers().Contains(id) || GetClients().Contains(id)) {
      SetInterrupted();
      Stop(QString(id.ToString() + " disconnected"));
    }
  }

  void Round::Send(const QByteArray &)
  {
    throw std::logic_error("Not implemented");
  }

  QByteArray Round::GenerateData(int size)
  {
    int maximum = GetClients().Count();
    Crypto::CryptoRandom rand;
    int value = rand.GetInt(0, maximum);
    if(float(value) / float(maximum) > PERCENT_ACTIVE) {
      return QByteArray();
    }
    QByteArray data(size, 0);
    rand.GenerateBlock(data);
    return data;
  }

  void Round::PushData(int, const QByteArray &data)
  {
    PushData(GetSharedPointer(), data);
  }
}
}
