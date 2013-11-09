#include "ClientServer/CSNetwork.hpp"
#include "ClientServer/Overlay.hpp"
#include "Connections/Connection.hpp"
#include "Connections/DefaultNetwork.hpp"
#include "Identity/PublicIdentity.hpp"

#include "Node.hpp"
#include "SessionFactory.hpp"

using Dissent::Identity::PublicIdentity;
using Dissent::ClientServer::CSNetwork;
using Dissent::Connections::DefaultNetwork;
using Dissent::Connections::Id;
using Dissent::Crypto::AsymmetricKey;
using Dissent::Crypto::DiffieHellman;

namespace Dissent {
namespace Applications {
  Node::Node(const PrivateIdentity &ident,
      const QSharedPointer<GroupHolder> &group_holder,
      const QSharedPointer<ClientServer::Overlay> &overlay,
      const QSharedPointer<Network> &network,
      const QSharedPointer<ISink> &sink,
      const SessionFactory::SessionType stype,
      AuthFactory::AuthType auth,
      const QSharedPointer<KeyShare> &keys) :
    m_ident(ident),
    m_group_holder(group_holder),
    m_overlay(overlay),
    m_net(network),
    m_sm(m_overlay->GetRpcHandler()),
    m_sink(sink)
  {
    SessionFactory::CreateSession(this, Id::Zero(), stype, auth, keys);
  }

  Node::~Node()
  {
  }

  QSharedPointer<Node> Node::CreateClientServer(const PrivateIdentity &ident,
      const Group &group, const QList<Address> &local,
      const QList<Address> &remote, const QSharedPointer<ISink> &sink,
      SessionFactory::SessionType session, AuthFactory::AuthType auth,
      const QSharedPointer<KeyShare> &keys)
  {
    QSharedPointer<GroupHolder> gh(new GroupHolder(group));
    QSharedPointer<ClientServer::Overlay> overlay(new ClientServer::Overlay(
          ident.GetLocalId(), local, remote, QList<Connections::Id>(), ident.GetSuperPeer()));
    QObject::connect(gh.data(), SIGNAL(GroupUpdated()),
        overlay.data(), SLOT(GroupUpdated()));
    QSharedPointer<Network> network(new CSNetwork(overlay));
    return QSharedPointer<Node>(new Node(ident, gh, overlay,
          network, sink, session, auth, keys));
  }
}
}
