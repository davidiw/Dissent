#include "BufferEdge.hpp"

using Dissent::Utils::TimerCallback;
using Dissent::Utils::Timer;
using Dissent::Utils::TimerMethodShared;

namespace Dissent {
namespace Transports {
  BufferEdge::BufferEdge(const Address &local, const Address &remote,
      bool outgoing, int delay) :
    Edge(local, remote, outgoing), Delay(delay), _remote_edge(0),
    _rem_closing(false)
  {
  }

  BufferEdge::~BufferEdge()
  {
  }

  void BufferEdge::SetRemoteEdge(QSharedPointer<BufferEdge> remote_edge)
  {
    if(!_remote_edge.isNull()) {
      qWarning() << "BufferEdge's remote already set.";
      return;
    }
    _remote_edge = remote_edge;
  }

  void BufferEdge::Send(const QByteArray &data)
  {
    if(Stopped()) {
      qWarning() << "Attempted to send on a closed edge.";
      return;
    }

    if(_rem_closing) {
      return;
    }

    TimerCallback *tm = new TimerMethodShared<BufferEdge, QByteArray>(
        _remote_edge.dynamicCast<BufferEdge>(),
        &BufferEdge::DelayedReceive, data);
    Timer::GetInstance().QueueCallback(tm, Delay);
  }

  void BufferEdge::OnStop()
  {
    if(!_rem_closing) {
      _remote_edge->_rem_closing = true;
      _remote_edge.clear();
    }
    Edge::OnStop();
  }

  void BufferEdge::DelayedReceive(const QByteArray &data)
  {
    if(Stopped()) {
      return;
    }
    PushData(GetSharedPointer(), data);
  }
}
}
