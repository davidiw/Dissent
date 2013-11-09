#include "NullRound.hpp"

namespace Dissent {
namespace Anonymity {
  NullRound::NullRound(const Identity::Roster &clients,
      const Identity::Roster &servers,
      const Identity::PrivateIdentity &ident,
      const QByteArray &nonce,
      const QSharedPointer<ClientServer::Overlay> &overlay,
      Messaging::GetDataCallback &get_data) :
    Round(clients, servers, ident, nonce, overlay, get_data),
    m_received(servers.Count() + clients.Count()),
    m_msgs(0)
  {
  }

  void NullRound::OnStart()
  {
    Round::OnStart();
    QPair<QByteArray, bool> data = GetData(1024);
    QVariantHash hash;
    hash["data"] = data.first;
    hash["nonce"] = GetNonce();
    GetOverlay()->Broadcast("SessionData", hash);
  }

  void NullRound::ProcessData(const Connections::Id &id,
      const QByteArray &data)
  {
    int idx = 0;
    if(GetOverlay()->IsServer(id)) {
      idx = GetServers().GetIndex(id);
    } else {
      idx = GetServers().Count() + GetClients().GetIndex(id);
    }

    if(!m_received[idx].isEmpty()) {
      qWarning() << "Receiving a second message from: " << id.ToString();
      return;
    }

    if(!data.isEmpty()) {
      qDebug() << GetLocalId().ToString() << "received a real message from" <<
        id.ToString();
    }

    m_received[idx] = data;
    m_msgs++;

    qDebug() << GetLocalId().ToString() << "received" <<
      m_msgs << "expecting" << m_received.size();

    if(m_msgs != m_received.size()) {
      return;
    }

    foreach(const QByteArray &msg, m_received) {
      if(!msg.isEmpty()) {
        PushData(GetSharedPointer(), msg);
      }
    }

    SetSuccessful(true);
    Stop("Round successfully finished.");
  }
}
}
