%%%----------------------------------------------------------------------
%%% File    : ejabberd_mongodb_sup.erl
%%% @author Andrei Leontev <andrei.leontev@protonmail.ch>
%%% @doc
%%% implements MongoDb database connection options
%%% @end
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

-module(ejabberd_mongodb_sup).

-behaviour(supervisor).
-behaviour(ejabberd_config).
-author('andrei.leontev@protonmail.ch').

-export([start/0, start_link/0, init/1, get_pids/0,
	 transform_options/1, get_random_pid/0,
	 host_up/1, config_reloaded/0, opt_type/1]).

-include("ejabberd.hrl").
-include("logger.hrl").

-define(DEFAULT_POOL_SIZE, 10).
-define(DEFAULT_MONGODB_START_INTERVAL, 30). % 30 seconds
-define(DEFAULT_MONGODB_HOST, "127.0.0.1").
-define(DEFAULT_MONGODB_PORT, 27017).
-define(DEFAULT_MONGODB_DATABASE, <<"ejabberd">>).

% time to wait for the supervisor to start its child before returning
% a timeout error to the request
-define(CONNECT_TIMEOUT, 500). % milliseconds

start() ->
    case lists:any(
	   fun(Host) ->
		   is_mongodb_configured(Host)
	   end, ?MYHOSTS) of
	true ->
      ejabberd:start_app(bson),
      ejabberd:start_app(crypto),
	    ejabberd:start_app(mongodb),
      do_start();
	false ->
	    ok
    end.

host_up(Host) ->
    case is_mongodb_configured(Host) of
  true ->
      ejabberd:start_app(mongodb),
      lists:foreach(
        fun(Spec) ->
          supervisor:start_child(?MODULE, Spec)
        end, get_specs());
  false ->
      ok
    end.

get_specs() ->
ok.

config_reloaded() ->
    case is_mongodb_configured() of
  true ->
      ejabberd:start_app(mongodb),
      lists:foreach(
        fun(Spec) ->
          supervisor:start_child(?MODULE, Spec)
        end, get_specs());
  false ->
      lists:foreach(
        fun({Id, _, _, _}) ->
          supervisor:terminate_child(?MODULE, Id),
          supervisor:delete_child(?MODULE, Id)
        end, supervisor:which_children(?MODULE))
    end.

is_mongodb_configured() ->
    lists:any(fun is_mongodb_configured/1, ?MYHOSTS).

is_mongodb_configured(Host) ->
    ServerConfigured = ejabberd_config:has_option({mongodb_server, Host}),
    PortConfigured = ejabberd_config:has_option({mongodb_port, Host}),
    StartIntervalConfigured = ejabberd_config:has_option({mongodb_start_interval, Host}),
    PoolConfigured = ejabberd_config:has_option({mongodb_pool_size, Host}),
    DatabaseConfigured = ejabberd_config:has_option({mongodb_database, Host}),
    UserConfigured = ejabberd_config:has_option({mongodb_username, Host}),
    PassConfigured = ejabberd_config:has_option({mongodb_password, Host}),
    AuthConfigured = lists:member(
           ejabberd_auth_mongodb,
           ejabberd_auth:auth_modules(Host)),
    SMConfigured = ejabberd_config:get_option({sm_db_type, Host}) == mongodb,
    RouterConfigured = ejabberd_config:get_option({router_db_type, Host}) == mongodb,
    ServerConfigured or PortConfigured or StartIntervalConfigured
  or PoolConfigured or DatabaseConfigured
  or UserConfigured or PassConfigured
  or SMConfigured or RouterConfigured
  or AuthConfigured.

do_start() ->
    SupervisorName = ?MODULE,
    ChildSpec =
	{SupervisorName,
	 {?MODULE, start_link, []},
	 transient,
	 infinity,
	 supervisor,
	 [?MODULE]},
    case supervisor:start_child(ejabberd_sup, ChildSpec) of
	{ok, _PID} ->
	    ok;
	_Error ->
	    ?ERROR_MSG("Start of supervisor ~p failed:~n~p~nRetrying...~n",
                       [SupervisorName, _Error]),
            timer:sleep(5000),
	    start()
    end.

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    PoolSize = get_pool_size(),
    StartInterval = get_start_interval(),
    Server = get_mongodb_server(),
    Port = get_mongodb_port(),
    Database = get_mongodb_database(),
    Username = get_mongodb_username(),
    Password = get_mongodb_password(),
    Options = lists:filter(
		fun(X) -> X /= nil end,
		[
     if Username /= nil -> {login, Username};
        true -> nil
     end,
     if Password /= nil -> {password, Password};
        true -> nil
     end
		]),
    {ok, {{one_for_one, PoolSize*10, 1},
	  lists:map(
	    fun(I) ->
		    {ejabberd_mongodb:get_proc(I),
		     {ejabberd_mongodb, start_link,
                      [I, Server, Port, Database, StartInterval*1000, Options]},
		     transient, 2000, worker, [?MODULE]}
	    end, lists:seq(1, PoolSize))}}.


get_start_interval() ->
    ejabberd_config:get_option(mongodb_start_interval, ?DEFAULT_MONGODB_START_INTERVAL).

get_pool_size() ->
    ejabberd_config:get_option(mongodb_pool_size, ?DEFAULT_POOL_SIZE).

get_mongodb_server() ->
    ejabberd_config:get_option(mongodb_server, ?DEFAULT_MONGODB_HOST).

get_mongodb_port() ->
    ejabberd_config:get_option(mongodb_port, ?DEFAULT_MONGODB_PORT).

get_mongodb_database() ->
    ejabberd_config:get_option(mongodb_database, ?DEFAULT_MONGODB_DATABASE).

get_mongodb_username() ->
    ejabberd_config:get_option(mongodb_username, nil).

get_mongodb_password() ->
    ejabberd_config:get_option(mongodb_password, nil).

get_pids() ->
    [ejabberd_mongodb:get_proc(I) || I <- lists:seq(1, get_pool_size())].

get_random_pid() ->
    I = randoms:round_robin(get_pool_size()) + 1,
    ejabberd_mongodb:get_proc(I).

transform_options(Opts) ->
    lists:foldl(fun transform_options/2, [], Opts).

transform_options({mongodb_server, {S, P}}, Opts) ->
    [{mongodb_server, S}, {mongodb_port, P}|Opts];
transform_options(Opt, Opts) ->
    [Opt|Opts].

-spec opt_type(mongodb_pool_size) -> fun((pos_integer()) -> pos_integer());
        (mongodb_port) -> fun((0..65535) -> 0..65535);
        (mongodb_server) -> fun((binary()) -> binary());
        (mongodb_start_interval) -> fun((pos_integer()) -> pos_integer());
        (mongodb_database) -> fun((binary()) -> binary());
        (mongodb_username) -> fun((binary()) -> binary());
        (mongodb_password) -> fun((binary()) -> binary());
        (atom()) -> [atom()].

opt_type(mongodb_pool_size) ->
    fun (N) when is_integer(N), N >= 1 -> N end;
opt_type(mongodb_port) ->
    fun(P) when is_integer(P), P > 0, P < 65536 -> P end;
opt_type(mongodb_server) ->
    fun(S) -> binary_to_list(iolist_to_binary(S)) end;
opt_type(mongodb_start_interval) ->
    fun (N) when is_integer(N), N >= 1 -> N end;
opt_type(mongodb_database) ->
    fun(S) -> iolist_to_binary(S) end;
opt_type(mongodb_username) ->
    fun(S) -> iolist_to_binary(S) end;
opt_type(mongodb_password) ->
    fun(S) -> iolist_to_binary(S) end;
opt_type(_) ->
    [mongodb_pool_size, mongodb_port, mongodb_server,
     mongodb_start_interval, mongodb_database, 
     mongodb_username, mongodb_password].
