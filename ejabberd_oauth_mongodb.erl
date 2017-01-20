%%%----------------------------------------------------------------------
%%% File    : ejabberd_auth_mongodb.erl
%%% @author Andrei Leontev <andrei.leontev@protonmail.ch>
%%% Purpose : Authentification via MongoDB
%%% Created : 12 Nov 2016 by Andrei Leontev <andrei.leontev@protonmail.ch>
%%%
%%% Copyright (C) 2016    Andrei Leontev
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

-module(ejabberd_oauth_mongodb).

-export([init/0,
         store/1,
         lookup/1,
         clean/1]).

-include("ejabberd_oauth.hrl").
-include("ejabberd.hrl").
-include("jlib.hrl").
-include("logger.hrl").

init() ->
    ok.

store(R) ->
    {User, Server} = R#oauth_token.us,
    SJID = jid:to_string({User, Server, <<"">>}),
    Map = #{<<"token">> => R#oauth_token.token, <<"us">> => SJID, 
            <<"scope">> => str:join(R#oauth_token.scope, <<" ">>), <<"expire">> => R#oauth_token.expire},
    case ejabberd_mongodb:insert_one(oauth_token, Map) of 
        {ok, _N, _Id} ->
            ok;
        error ->
            {error, <<"Error during an element insertion">>}
        end.

lookup(Token) ->
    Map = #{<<"token">> => Token},
    case ejabberd_mongodb:find_one(oauth_token, Map) of
        {ok, OauthToken} ->
            SJID = case maps:get(<<"us">>, OauthToken) of 
            {badmap, _} -> <<"">>;
            {badkey, _} -> <<"">>;
            ValJid -> ValJid
            end,
            Token = case maps:get(<<"token">>, OauthToken) of 
            {badmap, _} -> <<"">>;
            {badkey, _} -> <<"">>;
            ValT -> ValT
            end,
            Scope = case maps:get(<<"scope">>, OauthToken) of 
            {badmap, _} -> <<"">>;
            {badkey, _} -> <<"">>;
            ValS -> ValS
            end,
            Expire = case maps:get(<<"expire">>, OauthToken) of 
            {badmap, _} -> <<"">>;
            {badkey, _} -> <<"">>;
            ValE -> ValE
            end,
            JID = jid:from_string(SJID),
            US = {JID#jid.luser, JID#jid.lserver},
            #oauth_token{token = Token,
                         us = US,
                         scope = str:tokens(Scope, <<" ">>),
                         expire = Expire};
        error ->
            {error, <<"Error during an element searching">>};
        not_found ->
            {error, notfound}
        end.

clean(_TS) ->
% TODO
    ok.
    
