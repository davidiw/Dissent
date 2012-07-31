
#include "Crypto/CryptoFactory.hpp"
#include "ServerCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  ServerCiphertext::ServerCiphertext(const Parameters params, const PublicKeySet client_pks) :
    _params(params),
    _client_pks(client_pks)
  {}

  void ServerCiphertext::SetProof(const PrivateKey &priv)
  {
    // element = (prod of client_pks)^-server_sk mod p
    _element = _client_pks.GetInteger().Pow(priv.GetInteger(), _params.GetP()).ModInverse(_params.GetP());

    Integer v, t1, t2;
      
    // v in [0,q) 
    v = _params.RandomExponent();

    // g1 = DH generator
    // g2 = product of client PKs

    // t1 = g1^v
    t1 = _params.GetG().Pow(v, _params.GetP());

    // t2 = g2^-v
    t2 = _client_pks.GetInteger().Pow(v, _params.GetP());
    t2 = t2.ModInverse(_params.GetP());

    // y1 = server PK
    // y2 = server ciphertext
   
    // c = HASH(g1, g2, y1, y2, t1, t2) mod q
    _challenge = Commit(_params.GetG(), _client_pks.GetInteger(),
        PublicKey(priv).GetInteger(), _element,
        t1, t2);

    // r = v - cx == v - (chal)server_sk
    _response = (v - (_challenge*priv.GetInteger())) % _params.GetQ();
  }

  bool ServerCiphertext::VerifyProof(const PublicKey &pub) const
  {
    // g1 = DH generator 
    // g2 = product of all client pub keys
    // y1 = server PK
    // y2 = server ciphertext
    // t'1 = g1^r  * y1^c
    // t'2 = g2^-r  * y2^c

    if(!(_params.IsElement(pub.GetInteger()) &&
      _params.IsElement(_client_pks.GetInteger()) &&
      _params.IsElement(_element))) return false;

    Integer g2, t1, t2;

    // t1 = g1^r * y1^c
    t1 = (_params.GetG().Pow(_response, _params.GetP()) * 
        pub.GetInteger().Pow(_challenge, _params.GetP())) % _params.GetP();

    // t2 = g2^-r * y2^c
    t2 = (_client_pks.GetInteger().Pow(_response, _params.GetP()).ModInverse(_params.GetP()) *
        _element.Pow(_challenge, _params.GetP())) % _params.GetP();
    
    Integer tmp = Commit(_params.GetG(), _client_pks.GetInteger(),
        pub.GetInteger(), _element,
        t1, t2);

    return (tmp == _challenge);
  }

  Integer ServerCiphertext::Commit(const Integer &g1, const Integer &g2, 
      const Integer &y1, const Integer &y2,
      const Integer &t1, const Integer &t2) const
  {
    Hash *hash = CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm();
    hash->Restart();
    hash->Update(_params.GetP().GetByteArray());
    hash->Update(_params.GetQ().GetByteArray());
    hash->Update(_params.GetG().GetByteArray());
    hash->Update(g1.GetByteArray());
    hash->Update(g2.GetByteArray());
    hash->Update(y1.GetByteArray());
    hash->Update(y2.GetByteArray());
    hash->Update(t1.GetByteArray());
    hash->Update(t2.GetByteArray());

    return Integer(hash->ComputeHash()) % _params.GetQ();
  }
}
}
}