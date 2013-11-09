#include "Session.hpp"

#include "Crypto/DiffieHellman.hpp"
#include "Crypto/DsaPrivateKey.hpp"

namespace Dissent {
namespace Session {
  Session::Session(const QSharedPointer<ClientServer::Overlay> &overlay,
          const QSharedPointer<Crypto::AsymmetricKey> &my_key,
          const QSharedPointer<Crypto::KeyShare> &keys,
          Anonymity::CreateRound create_round) :
    m_overlay(overlay),
    m_my_key(my_key),
    m_keys(keys),
    m_create_round(create_round)
  {
    GetOverlay()->GetRpcHandler()->Register("Stop", this, "HandleStop");
    GetOverlay()->GetRpcHandler()->Register("SessionData", this, "IncomingData");
  }

  Session::~Session()
  {
    GetOverlay()->GetRpcHandler()->Unregister("HandleStop");
    GetOverlay()->GetRpcHandler()->Unregister("SessionData");
  }

  void Session::Send(const QByteArray &data)
  {
    m_send_queue.AddData(data);
  }

  void Session::GenerateRoundData()
  {
    m_ephemeral_key = QSharedPointer<Crypto::AsymmetricKey>(new Crypto::DsaPrivateKey());
    Crypto::DiffieHellman dh_key;
    m_optional_public = dh_key.GetPublicComponent();
    m_optional_private = dh_key.GetPrivateComponent();
  }

  void Session::NextRound()
  {
//    QSharedPointer<Buddies::BuddyPolicy> bp(new Buddies::NullBuddyPolicy(GetGroup().Count()));
//    QSharedPointer<Buddies::BuddyMonitor> bm(new Buddies::BuddyMonitor(bp));

    QVector<Identity::PublicIdentity> server_idents;
    foreach(const QSharedPointer<ServerAgree> &server, GetServers()) {
      Identity::PublicIdentity ident(server->GetId(), server->GetKey(),
          server->GetOptional().toByteArray());
      server_idents.append(ident);
    }

    QVector<Identity::PublicIdentity> client_idents;
    foreach(const QSharedPointer<ClientRegister> &client, GetClients()) {
      Identity::PublicIdentity ident(client->GetId(), client->GetKey(),
          client->GetOptional().toByteArray());
      client_idents.append(ident);
    }

    Identity::Roster clients(client_idents);
    Identity::Roster servers(server_idents);

    qDebug() << "HMM" << server_idents.count() << client_idents.count() << clients.Count() << servers.Count();

    Crypto::DiffieHellman dh_key(GetOptionalPrivate().toByteArray(), false);
    Identity::PrivateIdentity my_ident(GetOverlay()->GetId(),
        GetEphemeralKey(), dh_key);
    m_round = m_create_round(clients, servers, my_ident,
        GetRoundId(), GetOverlay(), m_send_queue.GetCallback());
    m_round->SetSink(this);
    QObject::connect(GetRound().data(), SIGNAL(Finished()),
        this, SLOT(HandleRoundFinishedSlot()));

    QList<Messaging::Request> msgs = m_round_queue;
    m_round_queue.clear();
    foreach(const Messaging::Request &msg, msgs) {
      m_round->IncomingData(msg);
    }
  }

  void Session::HandleRoundFinishedSlot()
  { 
    Anonymity::Round *round = qobject_cast<Anonymity::Round *>(sender());
    if(round != m_round.data()) {
      qWarning() << "Received an awry Round Finished notification";
      return;
    }
  
    qDebug() << ToString() << "- round finished due to -" <<
      m_round->GetStoppedReason();
    
    if(!m_round->Successful()) {
      m_send_queue.UnGet();
    }

    emit RoundFinished(m_round);
  
    if(Stopped()) {
      qDebug() << "Session stopped.";
      return;
    }

    HandleRoundFinished();
  }

  void Session::IncomingData(const Messaging::Request &notification)
  {
    if(m_round && m_round->Started()) {
      m_round->IncomingData(notification);
    } else {
      m_round_queue.append(notification);
    }
  }

  void Session::HandleStop(const Messaging::Request &)
  {
    // Is it a valid stop?
    OnStop();
  }

  QPair<QByteArray, bool> Session::DataQueue::GetData(int max)
  {
    if(m_trim > 0) {
      m_queue = m_queue.mid(m_trim);
    }

    QByteArray data;
    int idx = 0;
    while(idx < m_queue.count()) {
      if(max < m_queue[idx].count()) {
        qDebug() << "Message in queue is larger than max data:" <<
          m_queue[idx].count() << "/" << max;
        idx++;
        continue;
      } else if(max < (data.count() + m_queue[idx].count())) {
        break;
      }

      data.append(m_queue[idx++]);
    }

    m_trim = idx;

    bool more = m_queue.count() != m_trim;
    return QPair<QByteArray, bool>(data, more);
  }

  void Session::HandleConnection(
      const QSharedPointer<Connections::Connection> &)
  {
  }

  void Session::HandleDisconnect(
      const QSharedPointer<Connections::Connection> &)
  {
  }

  bool Session::CheckServerAgree(const ServerAgree &agree)
  {
    if(!GetKeyShare()->GetKey(agree.GetId().ToString())->Verify(agree.GetPayload(),
          agree.GetSignature()))
    {
      qWarning() << GetOverlay()->GetId() <<
        "Session::CheckServerAgree: Invalid signature" << agree.GetId();
      return false;
    }

    if(!agree.GetKey()->IsValid()) {
      qWarning() << GetOverlay()->GetId() <<
        "Session::CheckServerAgree: Invalid Ephemeral Key:" << agree.GetId();
      return false;
    }

    if(agree.GetRoundId() != GetRoundId()) {
      qWarning() << GetOverlay()->GetId() <<
        "Session::CheckServerAgree: RoundId in Agree message doesn't match our RoundId:"
        << agree.GetId() << agree.GetRoundId() << "!=" << GetRoundId();
      return false;
    }

    return true;
  }
}
}
