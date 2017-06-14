%%%----------------------------------------------------------------------
%%% File    : ejabberd_auth_mongodb.erl
%%% Author  : Andrei Leontev <andrei.leontev@protonmail.ch>
%%% Purpose : Authentification via MongoDB
%%%
%%%
%%% Copyright (C) Andrei Leontev
%%%
%%% This program is free software; you can redistribute it and/or
%%% modify it under the terms of the GNU General Public License as
%%% published by the Free Software Foundation; either version 2 of the
%%% License, or (at your option) any later version.
%%%
%%% This program is distributed in the hope that it will be useful,
%%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
%%% General Public License for more details.
%%%
%%% You should have received a copy of the GNU General Public License along
%%% with this program; if not, write to the Free Software Foundation, Inc.,
%%% 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
%%%
%%%----------------------------------------------------------------------

-module(ejabberd_auth_mongodb).

-compile([{parse_transform, ejabberd_sql_pt}]).

-behaviour(ejabberd_config).

-author('andrei.leontev@protonmail.ch').

-behaviour(ejabberd_auth).

%% External exports
-export([start/1, stop/1, set_password/3, check_password/4,
   check_password/6, try_register/3,
   dirty_get_registered_users/0, get_vh_registered_users/1,
   get_vh_registered_users/2,
   get_vh_registered_users_number/1,
   get_vh_registered_users_number/2, get_password/2,
   get_password_s/2, is_user_exists/2, remove_user/2,
   remove_user/3, store_type/1, export/1, import/2,
   plain_password_required/1, opt_type/1]).
-export([passwd_schema/0]).

-include("ejabberd.hrl").
-include("ejabberd_sql_pt.hrl").
-include("logger.hrl").

-record(passwd, {us = {<<"">>, <<"">>} :: {binary(), binary()} | '$1',
                 password = <<"">> :: binary() | scram() | '_'}).

-define(SALT_LENGTH, 16).

start(_Host) ->
    ok.

stop(_Host) ->
    ok.

plain_password_required(Server) ->
    store_type(Server) == scram.

store_type(Server) ->
    ejabberd_auth:password_format(Server).

passwd_schema() ->
    {record_info(fields, passwd), #passwd{}}.

check_password(User, AuthzId, Server, Password) ->
    if AuthzId /= <<>> andalso AuthzId /= User ->
        false;
    true ->
        LUser = jid:nodeprep(User),
        LServer = jid:nameprep(Server),
        SJID = jid:to_string({LUser, LServer, <<"">>}),
        Map = #{<<"us">> => SJID},
        case ejabberd_mongodb:find_one(passwd, Map) of
          {ok, PassObj} ->
            StoredKey = case maps:get(<<"password">>, PassObj, <<"">>) of 
              {badmap, _} -> <<"">>;
              ValP -> ValP
            end,
            ServerKey = case maps:get(<<"serverkey">>, PassObj, <<"">>) of 
              {badmap, _} -> <<"">>;
              ValSK -> ValSK
            end,
            Salt = case maps:get(<<"salt">>, PassObj, <<"">>) of 
              {badmap, _} -> <<"">>;
              ValS -> ValS
            end,
            IterationCount = case maps:get(<<"iterationcount">>, PassObj, 0) of 
              {badmap, _} -> <<"">>;
              ValI -> ValI
            end,
            case ServerKey of
              <<"">> -> StoredKey /= <<"">>;
              _Val -> is_password_scram_valid(Password, #scram{storedkey = StoredKey,
                                       serverkey = ServerKey,
                                       salt = Salt,
                                       iterationcount = IterationCount})
            end;
        error ->
            false;
        not_found ->
            false
        end
    end.

check_password(User, AuthzId, Server, Password, Digest,
         DigestGen) ->
    if AuthzId /= <<>> andalso AuthzId /= User ->
        false;
    true ->
        LUser = jid:nodeprep(User),
        LServer = jid:nameprep(Server),
        SJID = jid:to_string({LUser, LServer, <<"">>}),
        Map = #{<<"us">> => SJID},
        case ejabberd_mongodb:find_one(passwd, Map) of
          {ok, PassObj} ->
            StoredKey = case maps:get(<<"password">>, PassObj, <<"">>) of 
              {badmap, _} -> <<"">>;
              ValP -> ValP
            end,
            ServerKey = case maps:get(<<"serverkey">>, PassObj, <<"">>) of 
              {badmap, _} -> <<"">>;
              ValSK -> ValSK
            end,
            case ServerKey of
              <<"">> -> 
                DigRes = if Digest /= <<"">> ->
                  Digest == DigestGen(StoredKey);
                  true -> false
                end,
                if DigRes -> true;
                  true -> (StoredKey == Password) and (Password /= <<"">>)
                end;
              _Val -> 
                Passwd = jlib:decode_base64(StoredKey),
                DigRes = if Digest /= <<"">> ->
                  Digest == DigestGen(Passwd);
                  true -> false
                end,
                if DigRes -> true;
                  true -> (Passwd == Password) and (Password /= <<"">>)
                end
            end;
        error ->
            false;
        not_found ->
            false
        end
    end.

set_password(User, Server, Password) ->
    LUser = jid:nodeprep(User),
    LServer = jid:nameprep(Server),
    LPassword = jid:resourceprep(Password),
    if (LUser == error) or (LServer == error) ->
     {error, invalid_jid};
        LPassword == error ->
     {error, invalid_password};
       true ->
            SJID = jid:to_string({LUser, LServer, <<"">>}),
            Map = #{<<"us">> => SJID},
            case is_scrammed() of
                true ->
                    Scram = password_to_scram(Password),
                    Command = #{<<"$set">> => #{<<"password">> => Scram#scram.storedkey,
                          <<"serverkey">> => Scram#scram.serverkey,
                          <<"salt">> => Scram#scram.salt,
                          <<"iterationcount">> => Scram#scram.iterationcount}};
                false ->
                   Command = #{<<"$set">> => #{<<"password">> => Password}}
                end,
            case ejabberd_mongodb:update(passwd, Map, Command) of
              {ok, _V} ->
                ok;
              error ->
                {error, error};
              not_updated ->
                {error, not_updated};
              _ ->
                {error, error}
            end
    end.

try_register(User, Server, Password) ->
    LServer = jid:nameprep(Server),
    LUser = jid:nodeprep(User),
    LPassword = jid:resourceprep(Password),
    if (LUser == error) or (LServer == error) ->
            {error, invalid_jid};
       (LUser == <<>>) or (LServer == <<>>) ->
            {error, invalid_jid};
          LPassword == error ->
            {error, invalid_password};
       true ->
            SJID = jid:to_string({LUser, LServer, <<"">>}),
            case is_scrammed() of
               true ->
                    Scram = password_to_scram(Password),
                    Map = #{<<"us">> => SJID,
                          <<"password">> => Scram#scram.storedkey,
                          <<"serverkey">> => Scram#scram.serverkey,
                          <<"salt">> => Scram#scram.salt,
                          <<"iterationcount">> => Scram#scram.iterationcount};
                false ->
                   Map = #{<<"us">> => SJID, <<"password">> => Password}
                end,
            case ejabberd_mongodb:insert_one(passwd, Map) of
            {ok, _N, _Id} ->
              {atomic, ok};
            error ->
              {atomic, error}
            end
    end.

dirty_get_registered_users() ->
    lists:flatmap(
      fun(Server) ->
              get_vh_registered_users(Server)
      end, ejabberd_config:get_vh_by_auth_method(riak)).

get_vh_registered_users(Server) ->
    LServer = jid:nameprep(Server),
    case ejabberd_riak:get_keys_by_index(passwd, <<"host">>, LServer) of
        {ok, Users} ->
            Users;
        _ ->
            []
    end.

get_vh_registered_users(Server, _) ->
    get_vh_registered_users(Server).

get_vh_registered_users_number(Server) ->
    LServer = jid:nameprep(Server),
    case ejabberd_riak:count_by_index(passwd, <<"host">>, LServer) of
        {ok, N} ->
            N;
        _ ->
            0
    end.

get_vh_registered_users_number(Server, _) ->
    get_vh_registered_users_number(Server).

get_password(User, Server) ->
    LUser = jid:nodeprep(User),
    LServer = jid:nameprep(Server),
    if (LUser == error) or (LServer == error) ->
            false;
       (LUser == <<>>) or (LServer == <<>>) ->
            false;
       true ->
          SJID = jid:to_string({LUser, LServer, <<"">>}),
          Map = #{<<"us">> => SJID},
          case ejabberd_mongodb:find_one(passwd, Map) of
            {ok, PassObj} ->
              StoredKey = case maps:get(<<"password">>, PassObj, <<"">>) of 
                {badmap, _} -> <<"">>;
                ValP -> {ok, ValP}
              end,
              case is_scrammed() of
                true ->
                  ServerKey = case maps:get(<<"serverkey">>, PassObj, <<"">>) of 
                    {badmap, _} -> <<"">>;
                    ValSK -> ValSK
                  end,
                  Salt = case maps:get(<<"salt">>, PassObj, <<"">>) of 
                    {badmap, _} -> <<"">>;
                    ValS -> ValS
                  end,
                  IterationCount = case maps:get(<<"iterationcount">>, PassObj, 0) of 
                    {badmap, _} -> <<"">>;
                    ValI -> ValI
                  end,
                  {jlib:decode_base64(StoredKey),
                   jlib:decode_base64(ServerKey),
                   jlib:decode_base64(Salt),
                   IterationCount};
                false ->
                  StoredKey
              end;
          error ->
              error;
          not_found ->
              error
          end
    end.

get_password_s(User, Server) ->
    LServer = jid:nameprep(Server),
    LUser = jid:nodeprep(User),
    if (LUser == error) or (LServer == error) ->
            <<"">>;
       (LUser == <<>>) or (LServer == <<>>) ->
            <<"">>;
       true ->
          SJID = jid:to_string({LUser, LServer, <<"">>}),
          Map = #{<<"us">> => SJID},
          case ejabberd_mongodb:find_one(passwd, Map) of
            {ok, PassObj} ->
              StoredKey = case maps:get(<<"password">>, PassObj, <<"">>) of 
                {badmap, _} -> <<"">>;
                ValP -> ValP
              end,
              case is_scrammed() of
                true ->
                  <<"">>;
                false ->
                  {StoredKey}
              end;
          error ->
              <<"">>;
          not_found ->
              <<"">>
          end
    end.

is_user_exists(User, Server) ->
    LUser = jid:nodeprep(User),
    LServer = jid:nameprep(Server),
    SJID = jid:to_string({LUser, LServer, <<"">>}),
    Map = #{<<"us">> => SJID},
    case ejabberd_mongodb:find_one(passwd, Map) of 
        {ok, _User} ->
            true;
        error ->
            false;
        not_found ->
            false
        end.

remove_user(User, Server) ->
    LUser = jid:nodeprep(User),
    LServer = jid:nameprep(Server),
    SJID = jid:to_string({LUser, LServer, <<"">>}),
    Map = #{<<"us">> => SJID},    
    case ejabberd_mongodb:delete(passwd, Map) of
       {ok, _Val} ->
           ok;
       error ->
           error;
       not_found ->
           ok;
       _ ->
           ok  
       end.

remove_user(User, Server, Password) ->
    LUser = jid:nodeprep(User),
    LServer = jid:nameprep(Server),
    case ejabberd_riak:get(passwd, passwd_schema(), {LUser, LServer}) of
        {ok, #passwd{password = Password}}
          when is_binary(Password) ->
            ejabberd_riak:delete(passwd, {LUser, LServer}),
            ok;
        {ok, #passwd{password = Scram}}
          when is_record(Scram, scram) ->
            case is_password_scram_valid(Password, Scram) of
                true ->
                    ejabberd_riak:delete(passwd, {LUser, LServer}),
                    ok;
                false -> not_allowed
            end;
        _ -> not_exists
    end.

%%%
%%% SCRAM
%%%

is_scrammed() ->
    scram ==
      ejabberd_config:get_local_option({auth_password_format, ?MYNAME},
                                       fun(V) -> V end).

password_to_scram(Password) ->
    password_to_scram(Password,
          ?SCRAM_DEFAULT_ITERATION_COUNT).

password_to_scram(Password, IterationCount) ->
    Salt = randoms:bytes(?SALT_LENGTH),
    SaltedPassword = scram:salted_password(Password, Salt,
             IterationCount),
    StoredKey =
  scram:stored_key(scram:client_key(SaltedPassword)),
    ServerKey = scram:server_key(SaltedPassword),
    #scram{storedkey = jlib:encode_base64(StoredKey),
     serverkey = jlib:encode_base64(ServerKey),
     salt = jlib:encode_base64(Salt),
     iterationcount = IterationCount}.

is_password_scram_valid(Password, Scram) ->
  case jid:resourceprep(Password) of
    error ->
        false;
    _ ->
      IterationCount = Scram#scram.iterationcount,
      Salt = jlib:decode_base64(Scram#scram.salt),
      SaltedPassword = scram:salted_password(Password, Salt,
             IterationCount),
      StoredKey =
          scram:stored_key(scram:client_key(SaltedPassword)),
      jlib:decode_base64(Scram#scram.storedkey) == StoredKey
  end.

export(_Server) ->
    [{passwd,
      fun(Host, #passwd{us = {LUser, LServer}, password = Password})
         when LServer == Host ->
              [?SQL("delete from users where username=%(LUser)s;"),
               ?SQL("insert into users(username, password) "
                    "values (%(LUser)s, %(Password)s);")];
         (_Host, _R) ->
              []
      end}].

import(LServer, [LUser, Password, _TimeStamp]) ->
    Passwd = #passwd{us = {LUser, LServer}, password = Password},
    ejabberd_riak:put(Passwd, passwd_schema(), [{'2i', [{<<"host">>, LServer}]}]).

opt_type(auth_password_format) -> fun (V) -> V end;
opt_type(_) -> [auth_password_format].
