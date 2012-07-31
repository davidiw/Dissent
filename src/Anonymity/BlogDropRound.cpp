#include "Crypto/Hash.hpp"
#include "Crypto/BlogDrop/ClientCiphertext.hpp"
#include "Crypto/BlogDrop/Plaintext.hpp"
#include "Crypto/BlogDrop/ServerCiphertext.hpp"
#include "Identity/PublicIdentity.hpp"
#include "Utils/Random.hpp"
#include "Utils/QRunTimeError.hpp"
#include "Utils/Serialization.hpp"
#include "Utils/Time.hpp"
#include "Utils/Utils.hpp"

#include "BlogDropRound.hpp"

namespace Dissent {
  using Crypto::BlogDrop::ClientCiphertext;
  using Crypto::BlogDrop::Plaintext;
  using Crypto::BlogDrop::ServerCiphertext;
  using Crypto::CryptoFactory;
  using Crypto::Hash;
  using Crypto::Library;
  using Identity::PublicIdentity;
  using Utils::QRunTimeError;
  using Utils::Serialization;

namespace Anonymity {
  BlogDropRound::BlogDropRound(const Group &group, const PrivateIdentity &ident,
      const Id &round_id, QSharedPointer<Network> network,
      GetDataCallback &get_data, CreateRound create_shuffle) :
    BaseBulkRound(group, ident, round_id, network, get_data, create_shuffle),
    _state_machine(this),
    _stop_next(false)
  {
    _state_machine.AddState(OFFLINE);
    _state_machine.AddState(SHUFFLING, -1, 0, &BlogDropRound::StartShuffle);
    _state_machine.AddState(FINISHED);

    if(group.GetSubgroup().Contains(ident.GetLocalId())) {
      _state_machine.AddState(CLIENT_WAIT_FOR_SERVER_PUBLIC_KEYS,
          SERVER_PUBLIC_KEY, &BlogDropRound::HandleServerPublicKey,
          &BlogDropRound::SubmitServerPublicKey);
    } else {
      _state_machine.AddState(CLIENT_WAIT_FOR_SERVER_PUBLIC_KEYS,
          SERVER_PUBLIC_KEY, &BlogDropRound::HandleServerPublicKey);
    }

    _state_machine.AddState(PREPARE_FOR_BULK, -1, 0,
        &BlogDropRound::PrepareForBulk);
    
    _state_machine.AddState(PROCESS_DATA_SHUFFLE, -1, 0,
        &BlogDropRound::ProcessDataShuffle);
    _state_machine.AddTransition(SHUFFLING, PROCESS_DATA_SHUFFLE);
    _state_machine.AddTransition(PROCESS_DATA_SHUFFLE, CLIENT_WAIT_FOR_SERVER_PUBLIC_KEYS);
    _state_machine.AddTransition(CLIENT_WAIT_FOR_SERVER_PUBLIC_KEYS, 
        PREPARE_FOR_BULK);

    _state_machine.AddTransition(OFFLINE, SHUFFLING);
    _state_machine.SetState(OFFLINE);

    if(group.GetSubgroup().Contains(ident.GetLocalId())) {
      InitServer();
    } else {
      InitClient();
    }

  }

  void BlogDropRound::InitServer()
  {
    _server_state = QSharedPointer<ServerState>(new ServerState());
    _state = _server_state;
    Q_ASSERT(_state);

    foreach(const QSharedPointer<Connection> &con,
        GetNetwork()->GetConnectionManager()->
        GetConnectionTable().GetConnections())
    {
      if(!GetGroup().Contains(con->GetRemoteId()) ||
          GetGroup().GetSubgroup().Contains(con->GetRemoteId()))
      {
        continue;
      }

      _server_state->allowed_clients.insert(con->GetRemoteId());
    }

    _state_machine.AddState(SERVER_WAIT_FOR_CLIENT_CIPHERTEXT,
        CLIENT_CIPHERTEXT, &BlogDropRound::HandleClientCiphertext,
        &BlogDropRound::SetOnlineClients);

    _state_machine.AddState(SERVER_WAIT_FOR_CLIENT_LISTS,
        SERVER_CLIENT_LIST, &BlogDropRound::HandleServerClientList,
        &BlogDropRound::SubmitClientList);

    _state_machine.AddState(SERVER_WAIT_FOR_SERVER_COMMITS,
        SERVER_COMMIT, &BlogDropRound::HandleServerCommit,
        &BlogDropRound::SubmitCommit);

    _state_machine.AddState(SERVER_WAIT_FOR_SERVER_CIPHERTEXT,
        SERVER_CIPHERTEXT, &BlogDropRound::HandleServerCiphertext,
        &BlogDropRound::SubmitServerCiphertext);

    _state_machine.AddState(SERVER_WAIT_FOR_SERVER_VALIDATION,
        SERVER_VALIDATION, &BlogDropRound::HandleServerValidation,
        &BlogDropRound::SubmitValidation);

    _state_machine.AddState(SERVER_PUSH_CLEARTEXT, -1, 0,
        &BlogDropRound::PushCleartext);

    _state_machine.AddTransition(PREPARE_FOR_BULK,
        SERVER_WAIT_FOR_CLIENT_CIPHERTEXT);
    _state_machine.AddTransition(SERVER_WAIT_FOR_CLIENT_CIPHERTEXT,
        SERVER_WAIT_FOR_CLIENT_LISTS);
    _state_machine.AddTransition(SERVER_WAIT_FOR_CLIENT_LISTS,
        SERVER_WAIT_FOR_SERVER_COMMITS);
    _state_machine.AddTransition(SERVER_WAIT_FOR_SERVER_COMMITS,
        SERVER_WAIT_FOR_SERVER_CIPHERTEXT);
    _state_machine.AddTransition(SERVER_WAIT_FOR_SERVER_CIPHERTEXT,
        SERVER_WAIT_FOR_SERVER_VALIDATION);
    _state_machine.AddTransition(SERVER_WAIT_FOR_SERVER_VALIDATION,
        SERVER_PUSH_CLEARTEXT);
    _state_machine.AddTransition(SERVER_PUSH_CLEARTEXT,
        SERVER_WAIT_FOR_CLIENT_CIPHERTEXT);

    _state_machine.SetCycleState(SERVER_PUSH_CLEARTEXT);
  }

  void BlogDropRound::InitClient()
  {
    _state = QSharedPointer<State>(new State());

    foreach(const QSharedPointer<Connection> &con,
        GetNetwork()->GetConnectionManager()->
        GetConnectionTable().GetConnections())
    {
      if(GetGroup().GetSubgroup().Contains(con->GetRemoteId())) {
        _state->my_server = con->GetRemoteId();
        break;
      }
    }

    _state_machine.AddState(CLIENT_WAIT_FOR_CLEARTEXT,
        SERVER_CLEARTEXT, &BlogDropRound::HandleServerCleartext,
        &BlogDropRound::SubmitClientCiphertext);

    _state_machine.AddTransition(PREPARE_FOR_BULK,
        CLIENT_WAIT_FOR_CLEARTEXT);
    _state_machine.AddTransition(CLIENT_WAIT_FOR_CLEARTEXT,
        CLIENT_WAIT_FOR_CLEARTEXT);

    _state_machine.SetCycleState(CLIENT_WAIT_FOR_CLEARTEXT);
  }

  BlogDropRound::~BlogDropRound()
  {
  }

  void BlogDropRound::VerifiableBroadcastToServers(const QByteArray &data)
  {
    Q_ASSERT(IsServer());
    foreach(const PublicIdentity &pi, GetGroup().GetSubgroup()) {
      VerifiableSend(pi.GetId(), data);
    }
  }

  void BlogDropRound::VerifiableBroadcastToClients(const QByteArray &data)
  {
    Q_ASSERT(IsServer());
    foreach(const QSharedPointer<Connection> &con,
        GetNetwork()->GetConnectionManager()->
        GetConnectionTable().GetConnections())
    {
      if(!GetGroup().Contains(con->GetRemoteId()) ||
          GetGroup().GetSubgroup().Contains(con->GetRemoteId()))
      {
        continue;
      }

      VerifiableSend(con->GetRemoteId(), data);
    }
  }

  void BlogDropRound::OnStart()
  {
    Round::OnStart();
    _state_machine.StateComplete();
  }

  void BlogDropRound::OnStop()
  {
    _state_machine.SetState(FINISHED);
    Utils::PrintResourceUsage(ToString() + " " + "finished bulk");
    Round::OnStop();
  }

  void BlogDropRound::HandleDisconnect(const Id &id)
  {
    if(!GetGroup().Contains(id)) {
      return;
    }

    if(IsServer() && GetGroup().Contains(id)) {
      _server_state->allowed_clients.remove(id);
    }

    if((_state_machine.GetState() == OFFLINE) ||
        (_state_machine.GetState() == SHUFFLING))
    {
      GetShuffleRound()->HandleDisconnect(id);
    } else if(GetGroup().GetSubgroup().Contains(id)) {
      qDebug() << "A server (" << id << ") disconnected.";
      SetInterrupted();
      Stop("A server (" + id.ToString() +") disconnected.");
    } else {
      qDebug() << "A client (" << id << ") disconnected, ignoring.";
    }
  }

  void BlogDropRound::BeforeStateTransition()
  {
    if(_server_state) {
      _server_state->handled_servers.clear();
    }
  }

  bool BlogDropRound::CycleComplete()
  {
    if(_server_state) {
      _server_state->client_ciphertexts.clear();
      _server_state->server_ciphertexts.clear();
      _server_state->client_cobjs_by_slot.clear();
      _server_state->client_one_time_keys.clear();
      _server_state->client_pk_sets.clear();
    }

    if(_stop_next) {
      SetInterrupted();
      Stop("Stopped for join");
      return false;
    }
    return true;
  }

  void BlogDropRound::HandleServerPublicKey(const Id &from, QDataStream &stream)
  {
    if(!GetGroup().GetSubgroup().Contains(from)) {
      throw QRunTimeError("Got public key from non-server");
    }

    const int server_idx = GetGroup().GetSubgroup().GetIndex(from);

    if(_state->server_pks.contains(server_idx)) {
      throw QRunTimeError("Already have server public key");
    }

    QByteArray payload;
    stream >> payload;

    _state->server_pks[server_idx] = PublicKey(_state->params, payload);
    if(!_state->server_pks[server_idx].IsValid()) {
      Stop("Got invalid public key--aborting");
      return;
    }

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      ": received server public key from" << GetGroup().GetIndex(from) <<
      from.ToString() << "Have" << _state->server_pks.count()
      << "expecting" << GetGroup().GetSubgroup().Count();

    if(_state->server_pks.count() == GetGroup().GetSubgroup().Count())
    {
      _state_machine.StateComplete();
    } 
  }

  void BlogDropRound::HandleServerCleartext(const Id &from, QDataStream &stream)
  {
    if(IsServer()) {
      throw QRunTimeError("Not a client");
    } else if(_state->my_server != from) {
      throw QRunTimeError("Not a server");
    }

    QHash<int, QByteArray> signatures;
    QByteArray cleartext;
    stream >> signatures >> cleartext;

    int server_length = GetGroup().GetSubgroup().Count();
    for(int idx = 0; idx < server_length; idx++) {
      if(!GetGroup().GetSubgroup().GetKey(idx)->Verify(cleartext,
            signatures[idx]))
      {
        Stop("Failed to verify signatures");
        return;
      }
    }

    _state->cleartext = cleartext;
    ProcessCleartext();

    _state_machine.StateComplete();
  }

  void BlogDropRound::HandleClientCiphertext(const Id &from, QDataStream &stream)
  {
    if(!IsServer()) {
      throw QRunTimeError("Not a server");
    }

    Q_ASSERT(_server_state);

    if(!_server_state->allowed_clients.contains(from)) {
      throw QRunTimeError("Not allowed to submit a ciphertext");
    } else if(_server_state->client_ciphertexts.contains(from)) {
      throw QRunTimeError("Already have ciphertext");
    }

    QByteArray payload;
    stream >> payload;

    _server_state->client_ciphertexts[from] = payload;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      ": received client ciphertext from" << GetGroup().GetIndex(from) <<
      from.ToString() << "Have" << _server_state->client_ciphertexts.count()
      << "expecting" << _server_state->allowed_clients.count();

    if(_server_state->allowed_clients.count() ==
        _server_state->client_ciphertexts.count())
    {
      _state_machine.StateComplete();
    } 
  }

  void BlogDropRound::HandleServerClientList(const Id &from, QDataStream &stream)
  {
    if(!IsServer()) {
      throw QRunTimeError("Not a server");
    } else if(!GetGroup().GetSubgroup().Contains(from)) {
      throw QRunTimeError("Not a server");
    }

    Q_ASSERT(_server_state);

    if(_server_state->handled_servers.contains(from)) {
      throw QRunTimeError("Already have client list");
    }

    QHash<Id,QByteArray> remote_ctexts;
    stream >> remote_ctexts;

    _server_state->handled_servers.insert(from);

    // Make sure there are no overlaps in their list and our list
    QSet<Id> mykeys = _server_state->client_ciphertexts.keys().toSet();
    QSet<Id> theirkeys = remote_ctexts.keys().toSet();

    if((mykeys & theirkeys).count() != 0 && from != GetLocalId()) {
      qWarning() << "Clients" << (mykeys & theirkeys) <<
        "submitted ciphertexts to multiple servers";
      Stop("Clients submitted ciphertexts to many servers");
      return;
    }

    _server_state->client_ciphertexts.unite(remote_ctexts);

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      ": received client list from" << GetGroup().GetIndex(from) <<
      from.ToString() << "Have" << _server_state->handled_servers.count()
      << "expecting" << GetGroup().GetSubgroup().Count();

    if(_server_state->handled_servers.count() == GetGroup().GetSubgroup().Count()) {
      _state_machine.StateComplete();
    }
  }

  void BlogDropRound::HandleServerCommit(const Id &from, QDataStream &stream)
  {
    if(!IsServer()) {
      throw QRunTimeError("Not a server");
    } else if(!GetGroup().GetSubgroup().Contains(from)) {
      throw QRunTimeError("Not a server");
    }

    Q_ASSERT(_server_state);

    if(_server_state->handled_servers.contains(from)) {
      throw QRunTimeError("Already have commit");
    }

    QByteArray commit;
    stream >> commit;

    _server_state->handled_servers.insert(from);
    _server_state->server_commits[GetGroup().GetSubgroup().GetIndex(from)] = commit;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      ": received commit from" << GetGroup().GetIndex(from) <<
      from.ToString() << "Have" << _server_state->handled_servers.count()
      << "expecting" << GetGroup().GetSubgroup().Count();

    if(_server_state->handled_servers.count() == GetGroup().GetSubgroup().Count()) {
      _state_machine.StateComplete();
    }
  }

  void BlogDropRound::HandleServerCiphertext(const Id &from, QDataStream &stream)
  {
    if(!IsServer()) {
      throw QRunTimeError("Not a server");
    } else if(!GetGroup().GetSubgroup().Contains(from)) {
      throw QRunTimeError("Not a server");
    }

    Q_ASSERT(_server_state);

    if(_server_state->handled_servers.contains(from)) {
      throw QRunTimeError("Already have ciphertext");
    }

    QByteArray ciphertext;
    stream >> ciphertext;

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QSharedPointer<Hash> hashalgo(lib->GetHashAlgorithm());
    QByteArray commit = hashalgo->ComputeHash(ciphertext);

    if(commit != _server_state->server_commits[
        GetGroup().GetSubgroup().GetIndex(from)])
    {
      throw QRunTimeError("Does not match commit.");
    }

    _server_state->handled_servers.insert(from);
    _server_state->server_ciphertexts[GetGroup().GetSubgroup().GetIndex(from)] = ciphertext;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      ": received ciphertext from" << GetGroup().GetIndex(from) <<
      from.ToString() << "Have" << _server_state->handled_servers.count()
      << "expecting" << GetGroup().GetSubgroup().Count();

    if(_server_state->handled_servers.count() == GetGroup().GetSubgroup().Count()) {
      _state_machine.StateComplete();
    }
  }

  void BlogDropRound::HandleServerValidation(const Id &from, QDataStream &stream)
  {
    if(!IsServer()) {
      throw QRunTimeError("Not a server");
    } else if(!GetGroup().GetSubgroup().Contains(from)) {
      throw QRunTimeError("Not a server");
    }

    Q_ASSERT(_server_state);

    if(_server_state->handled_servers.contains(from)) {
      throw QRunTimeError("Already have signature.");
    }

    QByteArray signature;
    stream >> signature;

    if(!GetGroup().GetSubgroup().GetKey(from)->
        Verify(_state->cleartext, signature))
    {
      throw QRunTimeError("Siganture doesn't match.");
    }

    _server_state->handled_servers.insert(from);
    _server_state->signatures[GetGroup().GetSubgroup().GetIndex(from)] = signature;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      ": received validation from" << GetGroup().GetIndex(from) <<
      from.ToString() << "Have" << _server_state->handled_servers.count()
      << "expecting" << GetGroup().GetSubgroup().Count();

    if(_server_state->handled_servers.count() == GetGroup().GetSubgroup().Count()) {
      _state_machine.StateComplete();
    }
  }

  void BlogDropRound::StartShuffle()
  {
    GetShuffleRound()->Start();
  }

  QPair<QByteArray, bool> BlogDropRound::GetShuffleData(int)
  {
    _state->shuffle_data = _state->anonymous_pub.GetByteArray();
    return QPair<QByteArray, bool>(_state->shuffle_data, false);
  }

  void BlogDropRound::ShuffleFinished()
  {
    if(!GetShuffleRound()->Successful()) {
      SetBadMembers(GetShuffleRound()->GetBadMembers());
      if(GetShuffleRound()->Interrupted()) {
        SetInterrupted();
      }
      Stop("ShuffleRound failed");
      return;
    }

    _state_machine.StateComplete();
  }

  void BlogDropRound::ProcessDataShuffle()
  {
    if(GetShuffleSink().Count() != GetGroup().Count()) {
      qFatal("Did not receive a descriptor from everyone.");
    }

    int count = GetShuffleSink().Count();
    for(int idx = 0; idx < count; idx++) {
      QPair<QSharedPointer<ISender>, QByteArray> pair(GetShuffleSink().At(idx));
      PublicKey key(_state->params, pair.second);

      if(!key.IsValid()) {
        qDebug() << "Invalid key in shuffle.";
        continue;
      }

      if(_state->shuffle_data == pair.second) {
        _state->my_idx = _state->anonymous_keys.count();
      }
      _state->anonymous_keys.append(key);
    }

    _state_machine.StateComplete();
  }

  void BlogDropRound::SubmitServerPublicKey()
  {
    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream << SERVER_PUBLIC_KEY << GetRoundId() <<
      _state_machine.GetPhase() << _server_state->server_pub.GetByteArray();

    VerifiableBroadcast(payload);
  }

  void BlogDropRound::PrepareForBulk()
  {
    _state->server_pk_set = QSharedPointer<PublicKeySet>(
        new PublicKeySet(_state->params, _state->server_pks.values().toSet()));

    _state_machine.StateComplete();
    Utils::PrintResourceUsage(ToString() + " " + "beginning bulk");
  }

  void BlogDropRound::SubmitClientCiphertext()
  {
    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream << CLIENT_CIPHERTEXT << GetRoundId() << _state_machine.GetPhase()
      << GenerateClientCiphertext();

    VerifiableSend(_state->my_server, payload);
  }

  QByteArray BlogDropRound::GenerateClientCiphertext()
  {
    QList<QByteArray> ctexts;

    for(int client_idx=0; client_idx<GetGroup().Count(); client_idx++) {
      if(client_idx == _state->my_idx) {

        QPair<QByteArray, bool> pair = GetData(Plaintext::CanFit(_state->params));
        if(pair.first.size() > 0) {
          qDebug() << "Found a message of" << pair.first.size();
        }

        Plaintext m(_state->params);
        QByteArray rest = m.Encode(pair.first);
        Q_ASSERT(rest.count() == 0);

        ClientCiphertext c(_state->params, *_state->server_pk_set, _state->anonymous_keys[client_idx]);
        c.SetAuthorProof(_state->anonymous_priv, m);
        ctexts.append(c.GetByteArray());
      } else {
        ClientCiphertext c(_state->params, *_state->server_pk_set, _state->anonymous_keys[client_idx]);
        c.SetProof();
        ctexts.append(c.GetByteArray());
      }
    }

    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);
    stream << ctexts;

    /* Return a serialized list of serialized ciphertexts */
    return out;
  }

  void BlogDropRound::SetOnlineClients()
  {
    _server_state->allowed_clients.clear();

    foreach(const QSharedPointer<Connection> &con,
        GetNetwork()->GetConnectionManager()->
        GetConnectionTable().GetConnections())
    {
      if(!GetGroup().Contains(con->GetRemoteId()) ||
          GetGroup().GetSubgroup().Contains(con->GetRemoteId()))
      {
        continue;
      }

      _server_state->allowed_clients.insert(con->GetRemoteId());
    }

    if(_server_state->allowed_clients.count() == 0) {
      _state_machine.StateComplete();
      return;
    }

    _server_state->expected_clients = _server_state->allowed_clients.count();
  }

  void BlogDropRound::ConcludeClientCiphertextSubmission(const int &)
  {
    qDebug() << "Client window has closed, unfortunately some client may not"
      << "have transmitted in time.";
    _state_machine.StateComplete();
  }

  void BlogDropRound::SubmitClientList()
  {
    // XXX should verify all ciphertexts before sending them out
    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream << SERVER_CLIENT_LIST << GetRoundId() <<
      _state_machine.GetPhase() << _server_state->client_ciphertexts;

    VerifiableBroadcastToServers(payload);
  }

  void BlogDropRound::SubmitCommit()
  {
    GenerateServerCiphertext();
    GenerateServerCommit();

    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream << SERVER_COMMIT << GetRoundId() <<
      _state_machine.GetPhase() << _server_state->my_commit;

    VerifiableBroadcastToServers(payload);
  }

  void BlogDropRound::GenerateServerCiphertext()
  {
    // For each slot
    for(int slot_idx=0; slot_idx<GetGroup().Count(); slot_idx++) {
      _server_state->client_cobjs_by_slot.append(QList<ClientCiphertext>());
      _server_state->client_one_time_keys.append(QSet<PublicKey>());
    }

    // For each user
    for(QHash<Id, QByteArray>::const_iterator i=_server_state->client_ciphertexts.begin();
        i!=_server_state->client_ciphertexts.end();
        i++) {

      QList<QByteArray> ctexts;
      QDataStream stream(_server_state->client_ciphertexts[i.key()]);
      stream >> ctexts;

      if(ctexts.count() != GetGroup().Count()) {
        throw QRunTimeError("Ciphertext vector has invalid length");
      }

      // For each slot
      for(int slot_idx=0; slot_idx<GetGroup().Count(); slot_idx++) {
        ClientCiphertext c(_state->params, *_state->server_pk_set, 
            _state->anonymous_keys[slot_idx], ctexts[slot_idx]);

        if(!c.VerifyProof()) {
          qWarning() << "Member" << i.key() << "submitted invalid ciphertext on slot" << slot_idx;
          QVector<int> bad;
          bad.append(GetGroup().GetIndex(i.key()));
          Stop("Found bad client");
        }

        _server_state->client_cobjs_by_slot[slot_idx].append(c);
        _server_state->client_one_time_keys[slot_idx].insert(c.GetOneTimeKey());
      }
    }

    QList<QByteArray> server_ctexts;
    for(int slot_idx=0; slot_idx<GetGroup().Count(); slot_idx++) {
      _server_state->client_pk_sets.append(QSharedPointer<PublicKeySet>(
          new PublicKeySet(_state->params, _server_state->client_one_time_keys[slot_idx])));

      // do stuff that sets _server_state->my_ciphertext
      ServerCiphertext s(_state->params, *(_server_state->client_pk_sets[slot_idx]));
      s.SetProof(_server_state->server_priv);

      server_ctexts.append(s.GetByteArray());
    }

    QDataStream stream(&(_server_state->my_ciphertext), QIODevice::WriteOnly);
    stream << server_ctexts;
  }

  void BlogDropRound::GenerateServerCommit()
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QSharedPointer<Hash> hashalgo(lib->GetHashAlgorithm());
    _server_state->my_commit = hashalgo->ComputeHash(_server_state->my_ciphertext);
  }

  void BlogDropRound::SubmitServerCiphertext()
  {
    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream << SERVER_CIPHERTEXT << GetRoundId() <<
      _state_machine.GetPhase() << _server_state->my_ciphertext;

    VerifiableBroadcastToServers(payload);
  }

  void BlogDropRound::SubmitValidation()
  {
    /* list[slot_idx][server_idx] = ciphertext */
    QList<QList<ServerCiphertext> > server_by_slot;
    for(int slot_idx=0; slot_idx<GetGroup().Count(); slot_idx++) {
      server_by_slot.append(QList<ServerCiphertext>());
    }

    for(int server_idx=0; server_idx<GetGroup().GetSubgroup().Count(); server_idx++) {
      QList<QByteArray> server_list;
      QDataStream stream(_server_state->server_ciphertexts[server_idx]);
      stream >> server_list;

      if(server_list.count() != GetGroup().Count()) {
        throw QRunTimeError("Server submitted ciphertext list of wrong length");
      }

      for(int slot_idx=0; slot_idx<GetGroup().Count(); slot_idx++) {
        ServerCiphertext s(_state->params, *(_server_state->client_pk_sets[slot_idx]), server_list[slot_idx]);
          
        if(!s.VerifyProof(_state->server_pks[server_idx])) {
          throw QRunTimeError("Server submitted invalid ciphertext");
        }

        server_by_slot[slot_idx].append(s);
      }
    }

    QList<QByteArray> plaintexts;
    for(int slot_idx=0; slot_idx<GetGroup().Count(); slot_idx++) {
      Plaintext m(_state->params);

      for(int client_idx=0; client_idx<GetGroup().Count(); client_idx++) {
        m.Reveal(_server_state->client_cobjs_by_slot[slot_idx][client_idx].GetElement());
      }

      for(int server_idx=0; server_idx<GetGroup().GetSubgroup().Count(); server_idx++) {
        m.Reveal(server_by_slot[slot_idx][server_idx].GetElement());
      }

      plaintexts.append(m.Decode());
    }

    QDataStream pstream(&(_state->cleartext), QIODevice::WriteOnly);
    pstream << plaintexts;

    QByteArray signature = GetPrivateIdentity().GetSigningKey()->Sign(_state->cleartext);

    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream << SERVER_VALIDATION << GetRoundId() <<
      _state_machine.GetPhase() << signature;

    VerifiableBroadcastToServers(payload);
  }

  void BlogDropRound::PushCleartext()
  {
    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream << SERVER_CLEARTEXT << GetRoundId() << _state_machine.GetPhase()
      << _server_state->signatures << _server_state->cleartext;

    VerifiableBroadcastToClients(payload);
    ProcessCleartext();
    _state_machine.StateComplete();
  }

  void BlogDropRound::ProcessCleartext()
  {
    QList<QByteArray> plaintexts;
    QDataStream stream(_state->cleartext);
    stream >> plaintexts;

    for(int slot_idx=0; slot_idx<plaintexts.count(); slot_idx++) {
      qDebug() << "Pushing cleartext of length" << plaintexts[slot_idx].count();
      PushData(GetSharedPointer(), plaintexts[slot_idx]); 
    }
  }

}
}
