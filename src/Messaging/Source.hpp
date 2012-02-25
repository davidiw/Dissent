#ifndef DISSENT_SOURCE_H_GUARD
#define DISSENT_SOURCE_H_GUARD

#include <QDebug>
#include <QSharedPointer>

#include "DummySink.hpp"
#include "ISink.hpp"

namespace Dissent {
namespace Messaging {
  class ISender;

  /**
   * Produces data to be received by a sink
   */
  class Source {
    public:
      Source(const QSharedPointer<ISink> sink =
          QSharedPointer<ISink>(new DummySink())) :
        _sink(sink)
      {
      }

      /**
       * Push data from this source into a sink return the old sink if
       * one existed
       * @param sink the sink to push data into
       */
      QSharedPointer<ISink> SetSink(const QSharedPointer<ISink> &sink)
      {
        QSharedPointer<ISink> old_sink = _sink;
        _sink = sink;
        return old_sink;
      }

      virtual ~Source() {}

    protected:
      /**
       * Pushes data into the sink
       * @param from the remote sending party
       * @param data the message
       */
      inline void PushData(const QSharedPointer<ISender> &from,
          const QByteArray &data)
      {
        _sink->HandleData(from, data);
      }

    private:
      /**
       * Where to push data
       */
      QSharedPointer<ISink> _sink;
  };
}
}

#endif
