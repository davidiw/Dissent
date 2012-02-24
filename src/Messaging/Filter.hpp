#ifndef DISSENT_MESSAGING_FILTER_H_GUARD
#define DISSENT_MESSAGING_FILTER_H_GUARD

#include <QSharedPointer>

#include "ISender.hpp"
#include "ISink.hpp"
#include "Source.hpp"

namespace Dissent {
namespace Messaging {
  /**
   * Acts as a basic messaging Filter.  Must call GetSharedPointer or the
   * object in question will *never* be deleted!
   */
  class Filter : public Source, public ISender, public ISink {
    public:
      Filter() :
        _shared(this),
        _weak(_shared.toWeakRef())
      {
      }

      inline virtual void HandleData(const QSharedPointer<ISender> &,
          const QByteArray &data)
      {
        PushData(_weak.toStrongRef(), data);
      }

      /**
       * Destructor
       */
      virtual ~Filter() {}

      bool Shared() { return _shared == QSharedPointer<ISender>(); }

      QSharedPointer<ISender> GetSharedPointer()
      {
        QSharedPointer<ISender> shared = _shared;
        _shared.clear();
        return shared;
      }

    private:
      QSharedPointer<ISender> _shared;
      QWeakPointer<ISender> _weak;
  };
}
}

#endif
