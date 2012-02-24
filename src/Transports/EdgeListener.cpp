#include "EdgeListener.hpp"

namespace Dissent {
namespace Transports {
  EdgeListener::EdgeListener(const Address &local_address) :
    _local_address(local_address)
  {
  }

  void EdgeListener::ProcessNewEdge(QSharedPointer<Edge> edge)
  {
    Q_ASSERT(edge->GetSharedPointer());
    QObject::connect(edge.data(), SIGNAL(Closed(const QString &)),
        this, SLOT(HandleEdgeClose(const QString &)));
    emit NewEdge(edge);
  }

  void EdgeListener::ProcessEdgeCreationFailure(const Address &to, const QString &reason)
  {
    emit EdgeCreationFailure(to, reason);
  }

  void EdgeListener::HandleEdgeClose(const QString &)
  {
  }

  void EdgeListener::SetSharedPointer(const QSharedPointer<Edge> &edge)
  {
    edge->SetSharedPointer(edge);
  }
}
}
