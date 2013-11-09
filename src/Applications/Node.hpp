#ifndef DISSENT_APPLICATIONS_BASE_NODE_H_GUARD
#define DISSENT_APPLICATIONS_BASE_NODE_H_GUARD

#include "Anonymity/Sessions/SessionManager.hpp"
#include "Connections/Network.hpp"
#include "Identity/PrivateIdentity.hpp"
#include "Identity/Group.hpp"
#include "Identity/GroupHolder.hpp"
#include "Messaging/ISink.hpp"
#include "ClientServer/Overlay.hpp"
#include "Transports/Address.hpp"

#include "AuthFactory.hpp"
#include "SessionFactory.hpp"

namespace Dissent {
namespace Applications {
  /**
   * A wrapper class combining an overlay, session manager, session, sink,
   * key, and whatever else might be necessary.
   */
  class Node {
    public:
      typedef Anonymity::Sessions::SessionManager SessionManager;
      typedef Connections::Connection Connection;
      typedef Connections::Network Network;
      typedef Crypto::AsymmetricKey AsymmetricKey;
      typedef Crypto::KeyShare KeyShare;
      typedef Identity::PrivateIdentity PrivateIdentity;
      typedef Identity::Group Group;
      typedef Identity::GroupHolder GroupHolder;
      typedef Messaging::ISink ISink;
      typedef Transports::Address Address;

      typedef QSharedPointer<Node> (*CreateNode)(const PrivateIdentity &,
          const Group &, const QList<Address> &, const QList<Address> &,
          const QSharedPointer<ISink> &, SessionFactory::SessionType,
          AuthFactory::AuthType, const QSharedPointer<KeyShare> &keys);

      static QSharedPointer<Node> CreateClientServer(const PrivateIdentity &ident,
          const Group &group, const QList<Address> &local,
          const QList<Address> &remote, const QSharedPointer<ISink> &sink,
          SessionFactory::SessionType session,
          AuthFactory::AuthType auth = AuthFactory::NULL_AUTH,
          const QSharedPointer<KeyShare> &keys = QSharedPointer<KeyShare>());

      /**
       * Constructor
       * @param local the EL addresses
       * @param remote the bootstrap peer list
       */
      explicit Node(const PrivateIdentity &ident,
          const QSharedPointer<GroupHolder> &group_holder,
          const QSharedPointer<ClientServer::Overlay> &overlay,
          const QSharedPointer<Network> &network,
          const QSharedPointer<ISink> &sink,
          SessionFactory::SessionType stype,
          AuthFactory::AuthType auth,
          const QSharedPointer<KeyShare> &keys);

      /**
       * Destructor
       */
      virtual ~Node();

      PrivateIdentity GetPrivateIdentity() const { return m_ident; }
      QSharedPointer<GroupHolder> GetGroupHolder() const { return m_group_holder; }
      Group GetGroup() const { return m_group_holder->GetGroup(); }
      QSharedPointer<Network> GetNetwork() { return m_net; }
      QSharedPointer<ClientServer::Overlay> GetOverlay() { return m_overlay; }
      SessionManager &GetSessionManager() { return m_sm; }
      QSharedPointer<ISink> GetSink() const { return m_sink; }

    private:
      PrivateIdentity m_ident;
      QSharedPointer<GroupHolder> m_group_holder;
      QSharedPointer<ClientServer::Overlay> m_overlay;
      QSharedPointer<Network> m_net;
      SessionManager m_sm;
      QSharedPointer<ISink> m_sink;
  };
}
}

#endif
