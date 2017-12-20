%%%----------------------------------------------------------------------
%%% File    : ejabberd_auth_mongodb.erl
%%% Author  : Andrei Leontev <andrei.leontev@protonmail.ch>
%%% Purpose : Authentification via MongoDB
%%% Created : 17 Feb 2017 by Andrei Leontev <andrei.leontev@protonmail.ch>
%%%
%%%
%%% Copyright Andrei Leontev (C) 2017 
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

-author('andrei.leontev@protonmail.ch').

-behaviour(ejabberd_auth).

%% External exports
-export([start/1, stop/1, set_password/3, try_register/3,
   get_users/2, count_users/2, get_password/2, remove_user/2, 
   store_type/1, convert_to_scram/1, plain_password_required/1]).

-include("ejabberd.hrl").
-include("logger.hrl").
-include("ejabberd_auth.hrl").

start(_Host) ->
    ok.

stop(_Host) ->
    ok.

plain_password_required(Server) ->
    store_type(Server) == scram.

store_type(Server) ->
    ejabberd_auth:password_format(Server).

set_password(User, Server, Password) ->
    SJID = jid:to_string({User, Server, <<"">>}),
    Map = #{<<"us">> => SJID},
    case is_record(Password, scram) of
      true ->
        Cmd = #{<<"$set">> => #{<<"password">> => Password#scram.storedkey,
              <<"serverkey">> => Password#scram.serverkey,
              <<"salt">> => Password#scram.salt,
              <<"iterationcount">> => Password#scram.iterationcount}};
      false ->
        Cmd = #{<<"$set">> => #{<<"password">> => Password}}
    end,
    case ejabberd_mongodb:update(passwd, Map, Cmd) of
      {ok, _V} ->
        ok;
      error ->
        {error, error};
      not_updated ->
        {error, not_updated};
      _ ->
       {error, db_failure}
    end.

try_register(User, Server, Password) ->
    if is_record(Password, scram) ->
      Map = #{<<"username">> => User,
              <<"server_host">> => Server,
              <<"password">> => Password#scram.storedkey,
              <<"serverkey">> => Password#scram.serverkey,
              <<"salt">> => Password#scram.salt,
              <<"iterationcount">> => Password#scram.iterationcount};
    true ->
      Map = #{<<"username">> => User, <<"server_host">> => Server, 
              <<"password">> => Password}
    end,
    case ejabberd_mongodb:insert_one(passwd, Map) of
      {ok, _N, _Id} ->
        ok;
      error ->
        {error, exists}
    end.

get_users(Server, _Opts) ->
    Map = #{<<"server_host">> => Server},
    case ejabberd_mongodb:find(passwd, Map) of
      {ok, UsersObj} -> 
          F = fun(V, Acc) ->
            U = case maps:get(<<"username">>, V, <<"">>) of 
              {badmap, _} -> <<"">>;
              ValU -> ValU
            end,
            S = case maps:get(<<"server_host">>, V, <<"">>) of 
              {badmap, _} -> <<"">>;
              ValS -> ValS
            end,
            [{U, S}|Acc]
          end,
          lists:foldl(F, [], UsersObj);
      _ -> []
    end.

count_users(Server, _Opts) ->
    Map = #{<<"server_host">> => Server},
    case ejabberd_mongodb:count(passwd, Map) of
      {ok, Res} ->
          Res;
      _ -> 0
    end.

get_password(User, Server) ->
    Map = #{<<"username">> => User, <<"server_host">> => Server},
    case ejabberd_mongodb:find_one(passwd, Map) of
    {ok, PassObj} ->
        StoredKeyT = case maps:get(<<"password">>, PassObj, <<"">>) of 
          {badmap, _} -> <<"">>;
          ValP -> ValP
        end,
        ServerKeyT = case maps:get(<<"serverkey">>, PassObj, <<"">>) of 
          {badmap, _} -> <<"">>;
          ValSK -> ValSK
        end,
        SaltT = case maps:get(<<"salt">>, PassObj, <<"">>) of 
          {badmap, _} -> <<"">>;
          ValS -> ValS
        end,
        IterationCountT = case maps:get(<<"iterationcount">>, PassObj, 0) of 
          {badmap, _} -> <<"">>;
          ValI -> ValI
        end,
        case {StoredKeyT, ServerKeyT, SaltT, IterationCountT} of
          {Password, <<>>, <<>>, 0} ->
              {ok, Password};
          {StoredKey, ServerKey, Salt, IterationCount} ->
              {ok, #scram{storedkey = StoredKey,
              serverkey = ServerKey,
              salt = Salt,
              iterationcount = IterationCount}}
          end;
    error ->
        error;
    not_found ->
        error
    end.

remove_user(User, Server) ->
    Map = #{<<"username">> => User, <<"server_host">> => Server},    
    case ejabberd_mongodb:delete(passwd, Map) of
       {ok, _Val} ->
           ok;
       error ->
           {error, db_failure};
       not_found ->
           ok;
       _ ->
           {error, db_failure}  
       end.

convert_to_scram(_Server) ->
  ok.
