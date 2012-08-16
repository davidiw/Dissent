#include "Crypto/Hash.hpp"
#include "Crypto/BlogDrop/ClientCiphertext.hpp"
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

    _state_machine.AddState(PREPARE_FOR_BULK, -1, 0,
        &BlogDropRound::PrepareForBulk);
    
    _state_machine.AddState(PROCESS_DATA_SHUFFLE, -1, 0,
        &BlogDropRound::ProcessDataShuffle);
    _state_machine.AddTransition(SHUFFLING, PROCESS_DATA_SHUFFLE);
    // CLIENT_WAIT_FOR_SERVER_PUBLIC_KEYS should be just WAIT_FOR_SERVER_PUBLIC_KEYS
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

    _state->n_servers = GetGroup().GetSubgroup().Count();
    _state->n_clients = GetGroup().Count();// - _state->n_servers;
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

    _state_machine.AddState(CLIENT_WAIT_FOR_SERVER_PUBLIC_KEYS,
        SERVER_PUBLIC_KEY, &BlogDropRound::HandleServerPublicKey,
        &BlogDropRound::SubmitServerPublicKey);

    _state_machine.AddState(SERVER_WAIT_FOR_CLIENT_CIPHERTEXT,
        CLIENT_CIPHERTEXT, &BlogDropRound::HandleClientCiphertext,
        &BlogDropRound::SetOnlineClients);

    _state_machine.AddState(SERVER_WAIT_FOR_CLIENT_LISTS,
        SERVER_CLIENT_LIST, &BlogDropRound::HandleServerClientList,
        &BlogDropRound::SubmitClientList);

    _state_machine.AddState(SERVER_WAIT_FOR_SERVER_COMMITS,
        SERVER_COMMIT, &BlogDropRound::HandleServerCommit,
        &BlogDropRound::SubmitServerCommit);

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

    _state_machine.AddState(CLIENT_WAIT_FOR_SERVER_PUBLIC_KEYS,
        SERVER_PUBLIC_KEY, &BlogDropRound::HandleServerPublicKey);
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

  // Check out my new version of CSBulk, calling VerifiableSend is inefficient
  void BlogDropRound::VerifiableBroadcastToServers(const QByteArray &data)
  {
    Q_ASSERT(IsServer());
    foreach(const PublicIdentity &pi, GetGroup().GetSubgroup()) {
      VerifiableSend(pi.GetId(), data);
    }
  }

  // Check out my new version of CSBulk, calling VerifiableSend is inefficient
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
    } else {
      SetInterrupted();
      Stop(QString(id.ToString() + " disconnected"));
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

      for(int slot_idx=0; slot_idx<_state->n_clients; slot_idx++) {
        _server_state->blogdrop_servers[slot_idx]->ClearBin();
      }
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

    _state->server_pks[server_idx] = QSharedPointer<const PublicKey>(new PublicKey(_state->params, payload));
    if(!_state->server_pks[server_idx]->IsValid()) {
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

    // This is confusing, shouldn't the following comparison be before this?
    if((mykeys & theirkeys).count() != 0 && from != GetLocalId()) {
      throw QRunTimeError("Client submitted ciphertexts to multiple servers");
    }

    // Don't add in our own ciphertexts, since we already have them
    if(from != GetLocalId()) {
      _server_state->client_ciphertexts.unite(remote_ctexts);
    }

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
    _state->shuffle_data = _state->anonymous_pub->GetByteArray();

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
    if(GetShuffleSink().Count() != _state->n_clients) {
      throw QRunTimeError("Did not receive a descriptor from everyone.");
    }

    int count = GetShuffleSink().Count();
    for(int idx = 0; idx < count; idx++) {
      QPair<QSharedPointer<ISender>, QByteArray> pair(GetShuffleSink().At(idx));

      QSharedPointer<const PublicKey> key(new PublicKey(_state->params, pair.second));

      if(!key->IsValid()) {
        throw QRunTimeError("Invalid key in shuffle.");
      }

      if(_state->shuffle_data == pair.second) {
        _state->my_idx = idx;
      }

      _state->slot_pks.append(key);

    }

    if(_state->slot_pks.count() != _state->n_clients) {
      throw QRunTimeError("Did not receive a key from all clients");
    }

    _state_machine.StateComplete();
  }

  void BlogDropRound::SubmitServerPublicKey()
  {
    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream << SERVER_PUBLIC_KEY << GetRoundId() <<
      _state_machine.GetPhase() << _server_state->server_pub->GetByteArray();

    VerifiableBroadcast(payload);
  }

  void BlogDropRound::PrepareForBulk()
  {
    _state->server_pk_set = QSharedPointer<const PublicKeySet>(
        new PublicKeySet(_state->params, _state->server_pks.values()));
    _state->blogdrop_author = QSharedPointer<BlogDropAuthor>(
        new BlogDropAuthor(_state->params, _state->server_pk_set, _state->anonymous_priv));

    for(int slot_idx=0; slot_idx<_state->n_clients; slot_idx++) {
      QSharedPointer<BlogDropClient> c(new BlogDropClient(_state->params,
        _state->server_pk_set, _state->slot_pks[slot_idx])); 
      _state->blogdrop_clients.append(c);
    }

    if(IsServer()) {
      for(int slot_idx=0; slot_idx<_state->n_clients; slot_idx++) {
        QSharedPointer<BlogDropServer> s(new BlogDropServer(_state->params,
          _state->server_pk_set, _state->slot_pks[slot_idx], 
          _server_state->server_priv)); 
        _server_state->blogdrop_servers.append(s);
      }
    }

    // Dont need to hold the keys once the BlogDropClients
    // are initialized
    _state->slot_pks.clear();

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

    QByteArray c;
    for(int slot_idx=0; slot_idx < _state->n_clients; slot_idx++) {
      if(slot_idx == _state->my_idx) {

        // Would it make more sense to have this as a component of the blogdrop_author?
        QPair<QByteArray, bool> pair = GetData(Plaintext::CanFit(_state->params));
        if(pair.first.size() > 0) {
          qDebug() << "Found a message of" << pair.first.size();
        }
        
        if(!_state->blogdrop_author->GenerateAuthorCiphertext(c, pair.first)) 
          throw QRunTimeError("Could not generate author ciphertext");

      } else {
        c = _state->blogdrop_clients[slot_idx]->GenerateCoverCiphertext();
      }

      ctexts.append(c);
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
    // Add my own ciphertext to the set
    _server_state->client_ciphertexts[GetLocalId()] = GenerateClientCiphertext();

    // XXX should verify all ciphertexts before sending them out?
    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream << SERVER_CLIENT_LIST << GetRoundId() <<
      _state_machine.GetPhase() << _server_state->client_ciphertexts;

    VerifiableBroadcastToServers(payload);
  }

  void BlogDropRound::SubmitServerCommit()
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
    // by_slot[slot_idx][client_idx] = ciphertext
    QList<QList<QByteArray> > by_slot;
    for(int slot_idx=0; slot_idx<_state->n_clients; slot_idx++) {
      by_slot.append(QList<QByteArray>());
    }

    // Why aren't you using foreach(const Id &id, _server_state->client_ciphertexts.keys())  ... much easier to read
    // For each user
    for(QHash<Id, QByteArray>::const_iterator i=_server_state->client_ciphertexts.begin();
        i!=_server_state->client_ciphertexts.end();
        i++) {

      QList<QByteArray> ctexts;
      QDataStream stream(_server_state->client_ciphertexts[i.key()]);
      stream >> ctexts;

      if(ctexts.count() != _state->n_clients) {
        throw QRunTimeError("Ciphertext vector has invalid length");
      }

      // For each slot
      for(int slot_idx=0; slot_idx<_state->n_clients; slot_idx++) {
        by_slot[slot_idx].append(ctexts[slot_idx]);
      }
    }

    QList<QByteArray> server_ctexts;
    for(int slot_idx=0; slot_idx<_state->n_clients; slot_idx++) {
      _server_state->blogdrop_servers[slot_idx]->AddClientCiphertexts(by_slot[slot_idx]);
      server_ctexts.append(_server_state->blogdrop_servers[slot_idx]->CloseBin());
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
    for(int server_idx=0; server_idx<GetGroup().GetSubgroup().Count(); server_idx++) {
      QList<QByteArray> server_list;
      QDataStream stream(_server_state->server_ciphertexts[server_idx]);
      stream >> server_list;

      if(server_list.count() != _state->n_clients) {
        throw QRunTimeError("Server submitted ciphertext list of wrong length");
      }

      for(int slot_idx=0; slot_idx<_state->n_clients; slot_idx++) {
        if(!_server_state->blogdrop_servers[slot_idx]->AddServerCiphertext(_state->server_pks[server_idx],
              server_list[slot_idx])) {
            throw QRunTimeError("Server submitted invalid ciphertext");
        }
      }
    }

    QList<QByteArray> plaintexts;
    for(int slot_idx=0; slot_idx<_state->n_clients; slot_idx++) {

      QByteArray plain;
      if(!_server_state->blogdrop_servers[slot_idx]->RevealPlaintext(plain)) {
        throw QRunTimeError("Could not decode plaintext message. Maybe bad anon author?");
      }

      plaintexts.append(plain);

      qDebug() << "Decoding message" << plain.toHex();
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
      if(!plaintexts[slot_idx].isEmpty()) {
        qDebug() << "Pushing cleartext of length" << plaintexts[slot_idx].count();
        PushData(GetSharedPointer(), plaintexts[slot_idx]); 
      }
    }
  }

}
}
